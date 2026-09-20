#!/usr/bin/env python3
"""AIRCAP incident response engine.

Consumes fired detections, executes the matching runbook, and writes a complete
incident folder: evidence packs, a timeline, measured metrics and a postmortem.

  ir.py --triage                 run every runbook whose detections fired (no containment)
  ir.py --respond                triage AND apply containment
  ir.py --runbook R005 --respond run one runbook
  ir.py --status                 show active containment
  ir.py --lift                   reverse all containment

On metrics, read engine/METRICS.md before quoting a number. In short: time-to-detectable
and containment duration are measured; MTTD is modelled from a stated polling interval,
because a batch query cannot measure when an alert would have reached a human.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import duckdb  # noqa: E402
import yaml  # noqa: E402

from detections.run import DetectionLoadError, load_all  # noqa: E402
from lab.app.config import base  # noqa: E402
from lab.app.containment import ContainmentError, ContainmentStore  # noqa: E402
from query.q import QueryError, connect  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("aircap.ir")

RUNBOOK_DIR = REPO / "runbooks"
CORPUS_DIR = REPO / "lab/app/corpus"
QUARANTINE_DIR = REPO / "data/quarantine"

# Documents that ship with the lab and must never be quarantined by an automated
# action. A containment step derived from a detection inherits that detection's false
# positives, and a false-positive quarantine is a self-inflicted outage - so the blast
# radius of automation gets an explicit floor.
PROTECTED_DOCUMENTS = frozenset({"onboarding.md", "expenses.md", "support-sla.md"})

# Stated assumption for the modelled MTTD. A real deployment substitutes its own
# alert-pipeline latency; quoting a modelled figure without naming the assumption is
# how detection metrics become fiction.
ASSUMED_POLL_INTERVAL_S = 60.0

REQUIRED_KEYS = {
    "id", "title", "detections", "severity", "nist_csf", "atlas", "owasp",
    "triage", "collect", "contain", "recover",
}


class RunbookError(RuntimeError):
    """Raised when a runbook is malformed or its SQL is invalid."""


@dataclass
class Metrics:
    """Every field states whether it is measured or modelled."""

    measured_time_to_detectable_s: float | None = None
    measured_triage_duration_s: float = 0.0
    measured_containment_duration_s: float | None = None
    measured_evidence_rows: int = 0
    modelled_mttd_s: float | None = None
    modelled_mttd_assumption: str = (
        f"time_to_detectable + {ASSUMED_POLL_INTERVAL_S:.0f}s detection poll interval"
    )
    attack_first_event: str | None = None
    detection_possible_at: str | None = None
    containment_completed_at: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class Runbook:
    id: str
    title: str
    detections: list[str]
    severity: str
    nist_csf: list[str]
    atlas: list[str]
    owasp: list[str]
    triage: str
    collect: list[dict[str, Any]]
    contain: list[dict[str, Any]]
    recover: str
    path: Path


def load_runbooks() -> dict[str, Runbook]:
    books: dict[str, Runbook] = {}
    for path in sorted(RUNBOOK_DIR.glob("*.yml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RunbookError(f"{path.name}: invalid YAML: {exc}") from exc
        missing = REQUIRED_KEYS - set(data)
        if missing:
            raise RunbookError(f"{path.name}: missing key(s) {', '.join(sorted(missing))}")
        book = Runbook(**data, path=path)
        if book.id in books:
            raise RunbookError(f"duplicate runbook id {book.id}")
        books[book.id] = book
    return books


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="milliseconds")


def _rows_to_records(rel: duckdb.DuckDBPyRelation) -> list[dict[str, Any]]:
    cols = [d[0] for d in rel.description]
    out = []
    for row in rel.fetchall():
        rec = {}
        for col, val in zip(cols, row, strict=True):
            rec[col] = val.isoformat() if isinstance(val, datetime) else val
        out.append(rec)
    return out


def collect_evidence(
    con: duckdb.DuckDBPyConnection, book: Runbook, dest: Path
) -> tuple[dict[str, list[dict]], float, list[str]]:
    """Run every collect query, writing each result as its own evidence file."""
    dest.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    evidence: dict[str, list[dict]] = {}
    problems: list[str] = []

    for item in book.collect:
        name = item.get("name", "unnamed")
        try:
            records = _rows_to_records(con.sql(item["sql"]))
        except (duckdb.Error, KeyError) as exc:
            msg = f"collect '{name}' failed: {str(exc).splitlines()[0]}"
            logger.error("%s", msg)
            problems.append(msg)
            records = []
        evidence[name] = records
        (dest / f"{name}.json").write_text(
            json.dumps(
                {
                    "name": name,
                    "description": item.get("description", ""),
                    "sql": item["sql"].strip(),
                    "row_count": len(records),
                    "rows": records,
                },
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )
    return evidence, time.perf_counter() - started, problems


def compute_metrics(
    con: duckdb.DuckDBPyConnection, evidence: dict[str, list[dict]], triage_s: float
) -> Metrics:
    """Derive timing from the evidence itself, never from wall-clock guesses."""
    m = Metrics(measured_triage_duration_s=round(triage_s, 3))
    m.measured_evidence_rows = sum(len(rows) for rows in evidence.values())

    # Timestamps appearing anywhere in the evidence bound the attack window.
    stamps: list[datetime] = []
    for rows in evidence.values():
        for row in rows:
            for key, val in row.items():
                if not isinstance(val, str) or not key.lower().endswith(
                    ("ts", "_at", "_seen", "_exposure", "_disclosure", "_read")
                ):
                    continue
                try:
                    stamps.append(datetime.fromisoformat(val))
                except ValueError:
                    continue

    if not stamps:
        m.notes.append("no timestamps in evidence: timing metrics unavailable")
        return m

    first, last = min(stamps), max(stamps)
    m.attack_first_event = _iso(first)
    m.detection_possible_at = _iso(last)
    m.measured_time_to_detectable_s = round((last - first).total_seconds(), 3)
    m.modelled_mttd_s = round(m.measured_time_to_detectable_s + ASSUMED_POLL_INTERVAL_S, 3)
    if m.measured_time_to_detectable_s == 0:
        m.notes.append(
            "time_to_detectable is 0s: the detection was satisfiable by the very first "
            "event, so there is no accumulation window to measure"
        )
    return m


def apply_containment(
    con: duckdb.DuckDBPyConnection,
    book: Runbook,
    store: ContainmentStore,
    incident_id: str,
    *,
    dry_run: bool,
) -> tuple[list[dict], float, list[str]]:
    """Resolve each containment action's targets via SQL, then apply them."""
    started = time.perf_counter()
    applied: list[dict] = []
    problems: list[str] = []

    for spec in book.contain:
        action = spec.get("action")
        reason = spec.get("reason", book.title)
        try:
            targets = [
                r["target"]
                for r in _rows_to_records(con.sql(spec["targets_sql"]))
                if r.get("target")
            ]
        except (duckdb.Error, KeyError) as exc:
            msg = f"containment '{action}' target query failed: {str(exc).splitlines()[0]}"
            logger.error("%s", msg)
            problems.append(msg)
            continue

        if not targets:
            problems.append(f"containment '{action}' resolved no targets - nothing applied")
            continue

        for target in targets:
            if dry_run:
                applied.append(
                    {"action": action, "target": target, "reason": reason, "dry_run": True}
                )
                logger.info("DRY RUN would %s -> %s", action, target)
                continue
            if action == "quarantine_document" and target in PROTECTED_DOCUMENTS:
                msg = (
                    f"REFUSED to quarantine protected baseline document '{target}' - the "
                    "detection that selected it is producing false positives; investigate "
                    "the rule rather than removing the document"
                )
                logger.error("%s", msg)
                problems.append(msg)
                continue
            try:
                record = store.apply(action, target, incident=incident_id, reason=reason)
                if action == "quarantine_document":
                    _move_to_quarantine(target, problems)
                applied.append(record | {"dry_run": False})
            except ContainmentError as exc:
                problems.append(f"containment '{action}' on {target} failed: {exc}")
    return applied, time.perf_counter() - started, problems


def _move_to_quarantine(filename: str, problems: list[str]) -> None:
    """Move a corpus document out of retrieval reach. Reversible by design."""
    src = CORPUS_DIR / filename
    if not src.exists():
        problems.append(f"quarantine: {filename} not present in corpus (already removed?)")
        return
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        src.replace(QUARANTINE_DIR / filename)
        logger.warning("moved %s to data/quarantine/", filename)
    except OSError as exc:
        problems.append(f"quarantine: cannot move {filename}: {exc}")


def write_reports(
    dest: Path,
    book: Runbook,
    incident_id: str,
    detections_fired: dict[str, int],
    evidence: dict[str, list[dict]],
    metrics: Metrics,
    contained: list[dict],
    problems: list[str],
    dry_run: bool,
) -> None:
    """Write the timeline and the postmortem. These are the deliverable."""

    def fmt(seconds: float | None) -> str:
        return "not measurable" if seconds is None else f"{seconds:.3f}s"

    tl = [
        f"# Incident timeline - {incident_id}",
        "",
        f"**Runbook** {book.id} - {book.title}  ",
        f"**Severity** {book.severity}  ",
        f"**Detections fired** {', '.join(f'{d} ({n} hits)' for d, n in detections_fired.items())}  ",
        f"**NIST SP 800-61r3 / CSF 2.0** {', '.join(book.nist_csf)}  ",
        f"**MITRE ATLAS** {', '.join(book.atlas)}  ",
        f"**OWASP GenAI** {', '.join(book.owasp)}",
        "",
        "## Sequence",
        "",
        "| # | Phase | At | What |",
        "|---|---|---|---|",
    ]
    step = 1
    if metrics.attack_first_event:
        tl.append(f"| {step} | Attack | {metrics.attack_first_event} | first event in the affected sessions |")
        step += 1
    if metrics.detection_possible_at:
        tl.append(f"| {step} | Detectable | {metrics.detection_possible_at} | last event the detection required; alert becomes possible |")
        step += 1
    tl.append(f"| {step} | Triage | (engine) | {len(evidence)} evidence queries, {metrics.measured_evidence_rows} rows, {fmt(metrics.measured_triage_duration_s)} |")
    step += 1
    if contained:
        verb = "would contain (dry run)" if dry_run else "contained"
        for c in contained:
            tl.append(f"| {step} | Contain | {c.get('ts', '(dry run)')} | {verb}: `{c['action']}` -> `{c['target']}` |")
            step += 1
    else:
        tl.append(f"| {step} | Contain | - | no containment action available for this runbook |")

    tl += [
        "",
        "## Metrics",
        "",
        "| Metric | Value | Kind |",
        "|---|---|---|",
        f"| time to detectable | {fmt(metrics.measured_time_to_detectable_s)} | measured |",
        f"| triage duration | {fmt(metrics.measured_triage_duration_s)} | measured |",
        f"| containment duration | {fmt(metrics.measured_containment_duration_s)} | measured |",
        f"| evidence rows collected | {metrics.measured_evidence_rows} | measured |",
        f"| MTTD | {fmt(metrics.modelled_mttd_s)} | **modelled** |",
        "",
        f"MTTD assumption: {metrics.modelled_mttd_assumption}.",
        "",
        "Measured values are wall-clock or log-derived. The modelled MTTD exists because a "
        "batch SQL query cannot observe when an alert would have reached a responder; "
        "substitute your own alert-pipeline latency before quoting it.",
    ]
    if metrics.notes:
        tl += ["", "### Notes on these metrics", ""] + [f"- {n}" for n in metrics.notes]
    (dest / "timeline.md").write_text("\n".join(tl) + "\n", encoding="utf-8")

    pm = [
        f"# Postmortem - {incident_id}",
        "",
        f"## What happened",
        "",
        book.title + ".",
        "",
        "## Triage guidance applied",
        "",
        book.triage.strip(),
        "",
        "## Evidence collected",
        "",
        "| Pack | Rows | Description |",
        "|---|---|---|",
    ]
    for item in book.collect:
        name = item.get("name", "unnamed")
        pm.append(f"| `{name}.json` | {len(evidence.get(name, []))} | {item.get('description','').strip()} |")

    pm += ["", "## Containment", ""]
    if not book.contain:
        pm += [
            "**No containment action exists for this runbook.** That is a finding, not an "
            "omission - see the recovery section.",
            "",
        ]
    elif dry_run:
        pm += ["Dry run: nothing was applied. Actions that *would* have been taken:", ""]
        pm += [f"- `{c['action']}` -> `{c['target']}`" for c in contained] or ["- none resolved"]
        pm.append("")
    else:
        pm += ["Applied and currently in effect:", ""]
        pm += [
            f"- `{c['action']}` -> `{c['target']}`"
            + ("  _(already in effect)_" if c.get("already_in_effect") else "")
            for c in contained
        ] or ["- none resolved"]
        pm += ["", "Reverse with `make ir-lift`."]

    pm += ["", "## Recovery", "", book.recover.strip()]

    if problems:
        pm += [
            "",
            "## Problems during execution",
            "",
            "Recorded rather than suppressed - an incident report that hides its own gaps is "
            "worse than no report.",
            "",
        ]
        pm += [f"- {p}" for p in problems]

    pm += [
        "",
        "## Scope note",
        "",
        "Clean-room lab incident. Telemetry is schema-faithful to Amazon Bedrock invocation "
        "logs and CloudTrail data events but locally generated; no employer data or real "
        "cloud account is involved.",
    ]
    (dest / "postmortem.md").write_text("\n".join(pm) + "\n", encoding="utf-8")


def run_runbook(
    con: duckdb.DuckDBPyConnection,
    book: Runbook,
    detections_fired: dict[str, int],
    store: ContainmentStore,
    *,
    respond: bool,
) -> tuple[Path, Metrics]:
    stamp = _now().strftime("%Y%m%dT%H%M%S")
    incident_id = f"INC-{stamp}-{book.id}"
    dest = REPO / "incidents" / incident_id

    evidence, triage_s, problems = collect_evidence(con, book, dest / "evidence")
    metrics = compute_metrics(con, evidence, triage_s)

    contained, contain_s, contain_problems = apply_containment(
        con, book, store, incident_id, dry_run=not respond
    )
    problems += contain_problems
    if book.contain:
        metrics.measured_containment_duration_s = round(contain_s, 3)
        metrics.containment_completed_at = _iso(_now()) if respond else None
    else:
        metrics.notes.append(
            "no containment action defined: this runbook is detect-and-escalate only"
        )

    (dest / "metrics.json").write_text(json.dumps(asdict(metrics), indent=2), encoding="utf-8")
    (dest / "containment.json").write_text(
        json.dumps({"dry_run": not respond, "actions": contained}, indent=2), encoding="utf-8"
    )
    write_reports(
        dest, book, incident_id, detections_fired, evidence, metrics,
        contained, problems, dry_run=not respond,
    )
    return dest, metrics


def main() -> int:
    ap = argparse.ArgumentParser(description="AIRCAP incident response engine")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--triage", action="store_true", help="collect evidence, do not contain")
    mode.add_argument("--respond", action="store_true", help="collect evidence AND contain")
    mode.add_argument("--status", action="store_true", help="show active containment")
    mode.add_argument("--lift", action="store_true", help="reverse all containment")
    ap.add_argument("--runbook", nargs="+", metavar="ID", help="limit to these runbooks")
    args = ap.parse_args()

    cfg = base()
    data_dir = Path(cfg.data_dir).resolve()
    store = ContainmentStore(data_dir / "containment.json")

    if args.status:
        state = store.state()
        print(json.dumps({k: v for k, v in state.items() if k != "audit"}, indent=2))
        print(f"\n{store.active_count()} action(s) in effect; {len(state['audit'])} audit entries")
        return 0

    if args.lift:
        lifted = store.lift_all(reason="operator requested lift via engine/ir.py --lift")
        restored = 0
        if QUARANTINE_DIR.is_dir():
            for path in QUARANTINE_DIR.glob("*.md"):
                path.replace(CORPUS_DIR / path.name)
                restored += 1
        print(f"lifted {lifted} containment action(s); restored {restored} quarantined document(s)")
        return 0

    try:
        books = load_runbooks()
        detections = load_all()
        con = connect(data_dir)
    except (RunbookError, DetectionLoadError, QueryError) as exc:
        logger.error("%s", exc)
        return 2

    selected = args.runbook or list(books)
    unknown = [r for r in selected if r not in books]
    if unknown:
        logger.error("unknown runbook(s): %s; known: %s", ", ".join(unknown), ", ".join(books))
        return 2

    # Which detections actually fired, so runbooks only open on real hits.
    fired: dict[str, int] = {}
    for did, det in detections.items():
        try:
            fired[did] = len(con.sql(det.sql).fetchall())
        except duckdb.Error as exc:
            logger.error("detection %s failed: %s", did, str(exc).splitlines()[0])
            fired[did] = 0

    mode_label = "RESPOND (containment will be applied)" if args.respond else "TRIAGE (dry run)"
    print(f"\nAIRCAP IR engine - {mode_label}\n{'=' * 78}")

    opened = 0
    for rid in selected:
        book = books[rid]
        hits = {d: fired.get(d, 0) for d in book.detections if fired.get(d, 0)}
        if not hits:
            continue
        dest, metrics = run_runbook(con, book, hits, store, respond=args.respond)
        opened += 1
        print(f"\n{book.id}  {book.title}")
        print(f"     severity  : {book.severity}")
        print(f"     triggered : {', '.join(f'{d}({n})' for d, n in hits.items())}")
        print(f"     evidence  : {metrics.measured_evidence_rows} rows in "
              f"{metrics.measured_triage_duration_s:.3f}s")
        print(f"     detectable: {metrics.measured_time_to_detectable_s}s (measured)  "
              f"MTTD {metrics.modelled_mttd_s}s (modelled)")
        print(f"     incident  : {dest.relative_to(REPO)}")

    print(f"\n{'=' * 78}")
    print(f"{opened} incident(s) opened from {len(selected)} runbook(s) considered")
    if args.respond:
        print(f"{store.active_count()} containment action(s) now in effect - 'make ir-lift' reverses")
    else:
        print("no containment applied (triage mode); use --respond to act")
    return 0


if __name__ == "__main__":
    sys.exit(main())
