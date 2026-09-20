"""Console service layer: wraps the CLI modules for the web API.

Everything here calls the same functions the CLIs call, so the console cannot drift
from what `make verify` does. No subprocess shelling, so results stay structured.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import duckdb

from attacks.base import BASELINE_CORPUS, corpus_pollution
from attacks.runner import discover as discover_attacks
from attacks.runner import run_one
from detections.run import Detection, execute, load_all, row_text, sessions_of
from discover import scan as shadow
from discover.cloud import parse_logs as cloudlogs
from engine.ir import load_runbooks, run_runbook
from lab.app.config import base
from lab.app.containment import ContainmentStore
from lab.telemetry.emitter import TelemetrySink
from query.q import QueryError, connect

logger = logging.getLogger("aircap.console")

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "data"
INCIDENTS = REPO / "incidents"
CORPUS = REPO / "lab/app/corpus"

# Read-only guard for the ad-hoc query endpoint. The console binds to loopback, but a
# SQL box that accepts DDL is a footgun regardless of who can reach it.
_FORBIDDEN_SQL = (
    "insert", "update", "delete", "drop", "create", "alter", "attach", "detach",
    "copy", "export", "install", "load", "pragma", "set ", "call ",
)


class ConsoleError(RuntimeError):
    """Raised for a request the console can explain to the user."""


def store() -> ContainmentStore:
    return ContainmentStore(DATA / "containment.json")


def _telemetry_counts() -> dict[str, int]:
    return {
        stream: sum(1 for _ in (DATA / stream).rglob("*.jsonl"))
        for stream in ("bedrock-logs", "cloudtrail", "agent-traces")
    }


def _has_telemetry() -> bool:
    return all(v for v in _telemetry_counts().values())


# --- overview ---------------------------------------------------------------

def overview() -> dict[str, Any]:
    cfg = base()
    st = store()
    state = st.state()
    counts = _telemetry_counts()

    inv_path = DATA / "discover/inventory.json"
    discovery: dict[str, Any] | None = None
    if inv_path.exists():
        try:
            discovery = json.loads(inv_path.read_text(encoding="utf-8")).get("summary")
        except (OSError, json.JSONDecodeError):
            discovery = None

    rows = 0
    if _has_telemetry():
        try:
            con = connect(DATA)
            rows = int(con.sql("SELECT count(*) FROM bedrock_invocations").fetchone()[0])
        except (QueryError, duckdb.Error):
            rows = 0

    return {
        "lab": {
            "model_backend": cfg.model_backend,
            "model_id": cfg.model_id,
            "vuln_flags": cfg.vuln_flags,
            "max_tool_depth": cfg.max_tool_depth,
            "max_prompt_chars": cfg.max_prompt_chars,
            "guardrail_id": cfg.active_guardrail,
            "account_id": cfg.account_id,
            "region": cfg.region,
        },
        "telemetry": {
            "files": counts,
            "has_telemetry": _has_telemetry(),
            "invocations": rows,
        },
        "containment": {
            "active": st.active_count(),
            "quarantined_documents": state["quarantined_documents"],
            "disabled_tools": state["disabled_tools"],
            "blocked_egress_hosts": state["blocked_egress_hosts"],
            "revoked_principals": state["revoked_principals"],
            "enforce_output_filter": state["enforce_output_filter"],
            "audit_entries": len(state["audit"]),
        },
        "corpus": {
            "baseline": sorted(BASELINE_CORPUS),
            "present": sorted(p.name for p in CORPUS.glob("*.md")),
            "pollution": corpus_pollution(),
        },
        "incidents": len([p for p in INCIDENTS.glob("INC-*") if p.is_dir()]),
        "discovery": discovery,
        "counts": {
            "attacks": len(discover_attacks()),
            "detections": len(load_all()),
            "runbooks": len(load_runbooks()),
        },
    }


# --- attacks ----------------------------------------------------------------

def list_attacks() -> list[dict[str, Any]]:
    return [
        {
            "id": m.id, "name": m.name, "description": m.description,
            "posture": m.posture, "atlas": list(m.atlas), "owasp": list(m.owasp),
            "expect": list(m.expect), "control_layer": m.control_layer,
            "baseline_prevents": m.baseline_prevents, "notes": m.notes,
        }
        for m, _ in discover_attacks().values()
    ]


def run_attacks(
    ids: list[str] | None, *, hardened: bool, keep_artifacts: bool
) -> dict[str, Any]:
    attacks = discover_attacks()
    selected = ids or list(attacks)
    unknown = [i for i in selected if i not in attacks]
    if unknown:
        raise ConsoleError(f"unknown attack id(s): {', '.join(unknown)}")

    polluted = corpus_pollution()
    if polluted:
        raise ConsoleError(
            f"corpus has {len(polluted)} leftover document(s): {', '.join(polluted)}. "
            "These skew retrieval ranking and every detection count downstream. "
            "Reset the lab first."
        )

    cfg = base()
    sink = TelemetrySink(cfg.data_dir, cfg.account_id, cfg.region)
    started = time.perf_counter()
    results = []
    for aid in selected:
        manifest, module = attacks[aid]
        res = run_one(manifest, module, sink, hardened, keep_artifacts)
        expected_success = not manifest.baseline_prevents
        results.append({
            "id": manifest.id, "name": manifest.name,
            "posture": {} if hardened else manifest.posture,
            "succeeded": res.succeeded, "detail": res.detail,
            "control_layer": manifest.control_layer,
            "baseline_prevents": manifest.baseline_prevents,
            "matches_expectation": (res.succeeded == expected_success) if hardened else None,
        })

    succeeded = sum(1 for r in results if r["succeeded"])
    mismatches = [r for r in results if hardened and not r["matches_expectation"]]
    return {
        "mode": "hardened" if hardened else "vulnerable",
        "run_id": sink.run_id,
        "duration_s": round(time.perf_counter() - started, 2),
        "succeeded": succeeded,
        "total": len(results),
        "keep_artifacts": keep_artifacts,
        "control_test_passed": (not mismatches) if hardened else None,
        "residual_risk": [
            {"id": r["id"], "name": r["name"], "control_layer": r["control_layer"]}
            for r in results
            if hardened and r["succeeded"] and not r["baseline_prevents"]
        ],
        "results": results,
    }


# --- detections -------------------------------------------------------------

def _detection_meta(det: Detection) -> dict[str, Any]:
    return {
        "id": det.id, "title": det.title, "severity": det.severity, "plane": det.plane,
        "atlas": det.atlas, "owasp": det.owasp, "nist": det.nist,
        "description": det.description,
    }


def list_detections() -> list[dict[str, Any]]:
    return [_detection_meta(d) for d in load_all().values()]


def run_detections() -> dict[str, Any]:
    if not _has_telemetry():
        raise ConsoleError("no telemetry yet - run attacks first")
    detections = load_all()
    con = connect(DATA)
    out, blobs = [], {}
    for did, det in detections.items():
        rows, cols = execute(con, det)
        blobs[did] = row_text(rows)
        out.append({**_detection_meta(det), "hits": len(rows),
                    "sessions": sorted(sessions_of(rows, cols))})
    return {
        "fired": sum(1 for d in out if d["hits"]),
        "total": len(out),
        "detections": out,
        "_blobs": blobs,
    }


def detection_rows(did: str, limit: int = 200) -> dict[str, Any]:
    detections = load_all()
    if did not in detections:
        raise ConsoleError(f"unknown detection id: {did}")
    if not _has_telemetry():
        raise ConsoleError("no telemetry yet - run attacks first")
    det = detections[did]
    con = connect(DATA)
    try:
        rel = con.sql(det.sql)
        cols = [d[0] for d in rel.description]
        rows = rel.fetchmany(limit)
    except duckdb.Error as exc:
        raise ConsoleError(f"detection query failed: {str(exc).splitlines()[0]}") from exc
    return {
        **_detection_meta(det), "sql": det.sql,
        "columns": cols,
        "rows": [[None if c is None else str(c) for c in row] for row in rows],
    }


def matrix() -> dict[str, Any]:
    run = run_detections()
    blobs = run.pop("_blobs")
    results = {d["id"]: (d["hits"], set(d["sessions"])) for d in run["detections"]}
    attacks = discover_attacks()
    det_ids = sorted(results)

    grid, gaps = [], []
    for aid, (manifest, _) in attacks.items():
        cells = []
        for did in det_ids:
            _, sessions = results[did]
            hit = f"atk-{aid}" in sessions or f"base-{aid}" in sessions
            if not hit and manifest.markers:
                hit = any(m in blobs.get(did, "") for m in manifest.markers)
            expected = did in manifest.expect
            if hit and expected:
                state = "hit_expected"
            elif hit:
                state = "hit_unexpected"
            elif expected:
                state = "missed"
                gaps.append({"attack": aid, "detection": did})
            else:
                state = "none"
            cells.append(state)
        grid.append({"attack": aid, "name": manifest.name, "cells": cells})

    return {
        "detections": det_ids,
        "grid": grid,
        "gaps": gaps,
        "fired": run["fired"],
        "total": run["total"],
        "silent": [d["id"] for d in run["detections"] if not d["hits"]],
    }


# --- incident response ------------------------------------------------------

def list_runbooks() -> list[dict[str, Any]]:
    return [
        {
            "id": b.id, "title": b.title, "detections": b.detections,
            "severity": b.severity, "nist_csf": b.nist_csf, "atlas": b.atlas,
            "owasp": b.owasp, "triage": b.triage,
            "collect": [{"name": c.get("name"), "description": c.get("description", "")}
                        for c in b.collect],
            "contain": [{"action": c.get("action"), "reason": c.get("reason", "")}
                        for c in b.contain],
            "recover": b.recover,
        }
        for b in load_runbooks().values()
    ]


def run_ir(mode: str, runbook_ids: list[str] | None) -> dict[str, Any]:
    if mode not in {"triage", "respond"}:
        raise ConsoleError("mode must be 'triage' or 'respond'")
    if not _has_telemetry():
        raise ConsoleError("no telemetry yet - run attacks first")

    books = load_runbooks()
    selected = runbook_ids or list(books)
    unknown = [r for r in selected if r not in books]
    if unknown:
        raise ConsoleError(f"unknown runbook(s): {', '.join(unknown)}")

    detections = load_all()
    con = connect(DATA)
    fired: dict[str, int] = {}
    for did, det in detections.items():
        rows, _ = execute(con, det)
        fired[did] = len(rows)

    st = store()
    opened = []
    for rid in selected:
        book = books[rid]
        hits = {d: fired.get(d, 0) for d in book.detections if fired.get(d, 0)}
        if not hits:
            continue
        dest, metrics = run_runbook(con, book, hits, st, respond=(mode == "respond"))
        opened.append({
            "runbook": book.id, "title": book.title, "severity": book.severity,
            "triggered_by": hits, "incident": dest.name,
            "metrics": asdict(metrics),
        })
    return {
        "mode": mode,
        "opened": len(opened),
        "considered": len(selected),
        "incidents": opened,
        "containment_active": st.active_count(),
    }


def list_incidents() -> list[dict[str, Any]]:
    out = []
    for path in sorted(INCIDENTS.glob("INC-*"), reverse=True):
        if not path.is_dir():
            continue
        metrics = {}
        mpath = path / "metrics.json"
        if mpath.exists():
            try:
                metrics = json.loads(mpath.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metrics = {}
        out.append({
            "id": path.name,
            "runbook": path.name.rsplit("-", 1)[-1],
            "evidence_packs": len(list((path / "evidence").glob("*.json"))),
            "metrics": metrics,
        })
    return out


def incident_detail(incident_id: str) -> dict[str, Any]:
    path = INCIDENTS / incident_id
    if not path.is_dir() or not incident_id.startswith("INC-"):
        raise ConsoleError(f"no such incident: {incident_id}")
    evidence = {}
    for pack in sorted((path / "evidence").glob("*.json")):
        try:
            evidence[pack.stem] = json.loads(pack.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    def read(name: str) -> str:
        p = path / name
        return p.read_text(encoding="utf-8") if p.exists() else ""
    return {
        "id": incident_id,
        "timeline": read("timeline.md"),
        "postmortem": read("postmortem.md"),
        "metrics": json.loads(read("metrics.json") or "{}"),
        "containment": json.loads(read("containment.json") or "{}"),
        "evidence": evidence,
    }


def lift_containment() -> dict[str, Any]:
    st = store()
    lifted = st.lift_all(reason="lifted from the AIRCAP console")
    restored, retained = [], []
    qdir = DATA / "quarantine"
    if qdir.is_dir():
        for p in sorted(qdir.glob("*.md")):
            if p.name in BASELINE_CORPUS:
                p.replace(CORPUS / p.name)
                restored.append(p.name)
            else:
                retained.append(p.name)
    return {"lifted": lifted, "restored": restored, "retained_as_evidence": retained}


# --- discovery --------------------------------------------------------------

def discovery_register() -> dict[str, Any] | None:
    path = DATA / "discover/inventory.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConsoleError(f"cannot read discovery register: {exc}") from exc


def run_discovery() -> dict[str, Any]:
    inv = shadow.load_inventory()
    findings = (
        shadow.scan_processes(inv)
        + shadow.scan_listeners(inv)
        + shadow.scan_browser(inv)
        + shadow.scan_egress(inv)
    )
    register = shadow.build_register(
        findings,
        ["process", "listener", "browser", "egress"],
        [
            "The egress lens reverse-resolves peer IPs, so CDN-fronted providers are "
            "often missed. Live SNI capture needs packet-capture privileges and is only "
            "available from the CLI: discover/scan.py --capture",
        ],
    )
    out = DATA / "discover"
    out.mkdir(parents=True, exist_ok=True)
    (out / "inventory.json").write_text(json.dumps(register, indent=2), encoding="utf-8")
    return register


def cloud_egress(parse: bool = False) -> dict[str, Any] | None:
    path = DATA / "discover/cloud_egress.json"
    if parse or not path.exists():
        idx = cloudlogs.host_index()
        findings = (
            cloudlogs.parse_vpc(cloudlogs.SAMPLES / "vpc-flow-logs.txt", idx)
            + cloudlogs.parse_route53(cloudlogs.SAMPLES / "route53-resolver-queries.jsonl", idx)
            + cloudlogs.parse_nsg(cloudlogs.SAMPLES / "azure-nsg-flow-logs.json", idx)
        )
        payload = {"summary": cloudlogs.summarise(findings), "findings": findings}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConsoleError(f"cannot read cloud egress data: {exc}") from exc


# --- atlas, query, reset ----------------------------------------------------

def atlas_coverage() -> dict[str, Any]:
    path = REPO / "mappings/ATLAS_COVERAGE.md"
    if not path.exists():
        raise ConsoleError("ATLAS coverage not generated yet - run 'make atlas'")
    return {"markdown": path.read_text(encoding="utf-8")}


DOCS = {
    "aws": ("Detection -> AWS controls", REPO / "mappings/AWS_CONTROLS.md"),
    "azure": ("Detection -> Azure controls", REPO / "mappings/AZURE_CONTROLS.md"),
    "atlas": ("MITRE ATLAS coverage", REPO / "mappings/ATLAS_COVERAGE.md"),
    "results": ("Measured results", REPO / "docs/RESULTS.md"),
    "metrics": ("What the metrics mean", REPO / "engine/METRICS.md"),
    "tabletop": ("Tabletop: multi-tenant leak", REPO / "docs/TABLETOP-multi-tenant-leak.md"),
    "iac": ("AWS infrastructure", REPO / "iac/aws/README.md"),
}


def list_docs() -> list[dict[str, Any]]:
    return [
        {"key": k, "title": t, "available": p.exists()}
        for k, (t, p) in DOCS.items()
    ]


def read_doc(key: str) -> dict[str, Any]:
    if key not in DOCS:
        raise ConsoleError(f"unknown document: {key}")
    title, path = DOCS[key]
    if not path.exists():
        raise ConsoleError(f"{title} has not been generated yet ({path.name} missing)")
    return {"key": key, "title": title, "markdown": path.read_text(encoding="utf-8")}


def ad_hoc_query(sql: str, limit: int = 200) -> dict[str, Any]:
    stripped = sql.strip().rstrip(";")
    if not stripped:
        raise ConsoleError("empty query")
    lowered = stripped.lower()
    if not lowered.startswith(("select", "with")):
        raise ConsoleError("only SELECT and WITH queries are permitted")
    for word in _FORBIDDEN_SQL:
        if word in lowered:
            raise ConsoleError(f"statement rejected: '{word.strip()}' is not permitted")
    if not _has_telemetry():
        raise ConsoleError("no telemetry yet - run attacks first")
    con = connect(DATA)
    try:
        rel = con.sql(stripped)
        cols = [d[0] for d in rel.description]
        rows = rel.fetchmany(limit)
    except duckdb.Error as exc:
        raise ConsoleError(str(exc).splitlines()[0]) from exc
    return {
        "columns": cols,
        "rows": [[None if c is None else str(c) for c in row] for row in rows],
        "truncated": len(rows) == limit,
    }


def views() -> list[dict[str, Any]]:
    if not _has_telemetry():
        return []
    con = connect(DATA)
    rel = con.sql(
        "SELECT view_name, column_count FROM duckdb_views() "
        "WHERE NOT internal ORDER BY view_name"
    )
    return [{"view": r[0], "columns": r[1]} for r in rel.fetchall()]


def reset_lab() -> dict[str, Any]:
    result = lift_containment()
    for stream in ("bedrock-logs", "cloudtrail", "agent-traces", "quarantine", "discover"):
        shutil.rmtree(DATA / stream, ignore_errors=True)
    (DATA / "containment.json").unlink(missing_ok=True)
    removed_incidents = 0
    for path in INCIDENTS.glob("INC-*"):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            removed_incidents += 1
    removed_docs = []
    for path in CORPUS.glob("*.md"):
        if path.name not in BASELINE_CORPUS:
            path.unlink()
            removed_docs.append(path.name)
    return {
        "containment_lifted": result["lifted"],
        "incidents_removed": removed_incidents,
        "corpus_pollution_removed": removed_docs,
        "telemetry_cleared": True,
    }
