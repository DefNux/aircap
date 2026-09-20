#!/usr/bin/env python3
"""Detection runner and coverage matrix.

  run.py                    run every detection, show hit counts
  run.py --id D005          show the matching rows for one detection
  run.py --matrix           attack x detection matrix against expectations
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import duckdb  # noqa: E402

from lab.app.config import base  # noqa: E402
from query.q import QueryError, connect  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("aircap.detect")

SQL_DIR = Path(__file__).resolve().parent / "sql"
_HEADER = re.compile(r"^--\s*(\w+):\s*(.*)$")


@dataclass
class Detection:
    id: str
    title: str
    severity: str
    plane: str
    atlas: str
    owasp: str
    nist: str
    description: str
    sql: str
    path: Path


class DetectionLoadError(RuntimeError):
    """Raised when a detection file is missing required header fields."""


def load_all() -> dict[str, Detection]:
    found: dict[str, Detection] = {}
    for path in sorted(SQL_DIR.glob("*.sql")):
        meta: dict[str, str] = {}
        body: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            match = _HEADER.match(line)
            if match and not body:
                key, value = match.group(1), match.group(2).strip()
                meta[key] = f"{meta[key]} {value}".strip() if key in meta else value
            elif line.startswith("--") and not body and meta:
                # continuation of the previous header field
                last = next(reversed(meta))
                meta[last] = f"{meta[last]} {line.lstrip('- ').strip()}"
            else:
                body.append(line)
        required = ("id", "title", "severity", "plane", "atlas", "owasp", "nist", "description")
        missing = [k for k in required if k not in meta]
        if missing:
            raise DetectionLoadError(f"{path.name} missing header field(s): {', '.join(missing)}")
        det = Detection(
            id=meta["id"], title=meta["title"], severity=meta["severity"], plane=meta["plane"],
            atlas=meta["atlas"], owasp=meta["owasp"], nist=meta["nist"],
            description=meta["description"], sql="\n".join(body).strip(), path=path,
        )
        if det.id in found:
            raise DetectionLoadError(f"duplicate detection id {det.id} in {path.name}")
        found[det.id] = det
    return found


def execute(con: duckdb.DuckDBPyConnection, det: Detection) -> tuple[list, list[str]]:
    """Run one detection. A broken query is reported, never fatal to the run."""
    try:
        rel = con.sql(det.sql)
        return rel.fetchall(), [d[0] for d in rel.description]
    except duckdb.Error as exc:
        logger.error("%s query failed: %s", det.id, str(exc).splitlines()[0])
        return [], []


def sessions_of(rows: list, columns: list[str]) -> set[str]:
    """Attack attribution: which session ids appear in a detection's output."""
    if "session_id" in columns:
        idx = columns.index("session_id")
        return {str(r[idx]) for r in rows if r[idx]}
    return {"<no-session>"} if rows else set()


def row_text(rows: list) -> str:
    """Every cell of a detection's output as one searchable blob, for marker matching."""
    return "\n".join(" ".join("" if c is None else str(c) for c in row) for row in rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="AIRCAP detection runner")
    ap.add_argument("--id", nargs="+", metavar="ID", help="run only these detections")
    ap.add_argument("--matrix", action="store_true", help="attack x detection coverage matrix")
    ap.add_argument("--data-dir", default=None)
    args = ap.parse_args()

    cfg = base()
    data_dir = Path(args.data_dir or cfg.data_dir).resolve()

    try:
        detections = load_all()
        con = connect(data_dir)
    except (DetectionLoadError, QueryError) as exc:
        logger.error("%s", exc)
        return 2

    selected = args.id or list(detections)
    unknown = [d for d in selected if d not in detections]
    if unknown:
        logger.error("unknown detection id(s): %s", ", ".join(unknown))
        return 2

    if args.id and not args.matrix:
        for did in selected:
            det = detections[did]
            print(f"\n{det.id}  {det.title}")
            print(f"  severity={det.severity} plane={det.plane} atlas={det.atlas}")
            print(f"  owasp={det.owasp}  nist={det.nist}")
            print(f"  {det.description}\n")
            con.sql(det.sql).show(max_rows=25, max_width=190)
        return 0

    results: dict[str, tuple[int, set[str]]] = {}
    blobs: dict[str, str] = {}
    print(f"\nAIRCAP detections - {len(selected)} rules over {data_dir.name}/\n{'=' * 84}")
    print(f"{'ID':5} {'SEV':9} {'PLANE':8} {'HITS':>5}  TITLE")
    print("-" * 84)
    for did in selected:
        det = detections[did]
        rows, cols = execute(con, det)
        results[did] = (len(rows), sessions_of(rows, cols))
        blobs[did] = row_text(rows)
        marker = "*" if rows else " "
        print(f"{det.id:5} {det.severity:9} {det.plane:8} {len(rows):5}{marker} {det.title[:52]}")

    fired = sum(1 for n, _ in results.values() if n)
    print("-" * 84)
    print(f"{fired}/{len(selected)} detections fired")

    if args.matrix:
        return matrix(results, blobs)
    return 0


def matrix(results: dict[str, tuple[int, set[str]]], blobs: dict[str, str]) -> int:
    from attacks.runner import discover  # noqa: PLC0415

    attacks = discover()
    det_ids = sorted(results)

    print(f"\nattack x detection coverage matrix\n{'=' * 84}")
    header = "      " + " ".join(d[1:] for d in det_ids)
    print(header)
    gaps: list[tuple[str, str]] = []
    unexpected_quiet: list[str] = []

    for aid, (manifest, _) in attacks.items():
        cells = []
        for did in det_ids:
            _, sessions = results[did]
            hit = f"atk-{aid}" in sessions or f"base-{aid}" in sessions
            if not hit and manifest.markers:
                hit = any(m in blobs.get(did, "") for m in manifest.markers)
            expected = did in manifest.expect
            if hit and expected:
                cells.append(" X ")
            elif hit:
                cells.append(" + ")          # fired, not predicted
            elif expected:
                cells.append(" ! ")          # predicted, did not fire
                gaps.append((aid, did))
            else:
                cells.append(" . ")
        print(f"{aid:5} {''.join(cells)}")

    print("\n  X = fired as predicted   + = fired, unpredicted   ! = predicted, did NOT fire")

    # Control-plane detections cannot be attributed to a session id.
    for did in det_ids:
        count, sessions = results[did]
        if count and sessions == {"<no-session>"}:
            print(f"  note: {did} fired {count} time(s) on control-plane data (no session id)")
        if not count:
            unexpected_quiet.append(did)
    if unexpected_quiet:
        print(f"  silent detections: {', '.join(unexpected_quiet)}")

    if gaps:
        print(f"\nEXPECTATION GAPS ({len(gaps)}):")
        for aid, did in gaps:
            print(f"  {aid} expected {did}, which did not fire")
        return 1
    print("\nall attack expectations satisfied")
    return 0


if __name__ == "__main__":
    sys.exit(main())
