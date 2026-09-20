#!/usr/bin/env python3
"""Generate the ATLAS coverage matrix from the official STIX 2.1 bundle.

Hand-maintained framework mappings rot. This pulls MITRE ATLAS as published, validates
every technique id claimed by an attack, detection or runbook against it, and writes
mappings/ATLAS_COVERAGE.md.

  atlas_coverage.py            fetch (cached), validate, write the matrix
  atlas_coverage.py --offline  use the cache only; fail if absent

A claimed id that does not exist in the bundle is reported as an error, not silently
rendered - a coverage matrix that cannot be wrong is not evidence of anything.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("aircap.atlas")

STIX_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json"
CACHE = REPO / "mappings" / ".cache" / "stix-atlas.json"
OUT = REPO / "mappings" / "ATLAS_COVERAGE.md"
_ATLAS_ID = re.compile(r"AML\.[TM]\d{4}(?:\.\d{3})?")


class AtlasError(RuntimeError):
    """Raised when the ATLAS bundle cannot be obtained or parsed."""


def fetch(offline: bool) -> dict:
    if CACHE.exists():
        logger.info("using cached bundle %s", CACHE.relative_to(REPO))
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            if offline:
                raise AtlasError(f"cached bundle is corrupt: {exc}") from exc
            logger.warning("cached bundle corrupt, refetching")

    if offline:
        raise AtlasError(f"no cache at {CACHE} and --offline was requested")

    logger.info("fetching %s", STIX_URL)
    try:
        with urllib.request.urlopen(STIX_URL, timeout=120) as resp:  # noqa: S310 - fixed https URL
            raw = resp.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AtlasError(
            f"cannot fetch ATLAS bundle: {exc}. Re-run with --offline once a cache exists."
        ) from exc
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AtlasError(f"ATLAS bundle is not valid JSON: {exc}") from exc

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(raw, encoding="utf-8")
    logger.info("cached %.1f MB to %s", len(raw) / 1e6, CACHE.relative_to(REPO))
    return bundle


def index_techniques(bundle: dict) -> dict[str, dict]:
    """Map ATLAS id -> {name, tactics, is_subtechnique} from the STIX objects."""
    out: dict[str, dict] = {}
    tactic_names: dict[str, str] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            for ref in obj.get("external_references", []):
                if ref.get("source_name", "").startswith("mitre-atlas"):
                    tactic_names[obj.get("x_mitre_shortname", "")] = obj.get("name", "")

    for obj in bundle.get("objects", []):
        if obj.get("type") not in {"attack-pattern", "course-of-action"}:
            continue
        atlas_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references", [])
                if str(ref.get("external_id", "")).startswith("AML.")
            ),
            None,
        )
        if not atlas_id:
            continue
        phases = [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])]
        out[atlas_id] = {
            "name": obj.get("name", ""),
            "tactics": [tactic_names.get(p, p) for p in phases],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
        }
    return out


def collect_claims() -> dict[str, dict[str, list[str]]]:
    """Every ATLAS id claimed in the repo, and by what."""
    claims: dict[str, dict[str, list[str]]] = {}

    def add(atlas_id: str, kind: str, owner: str) -> None:
        claims.setdefault(atlas_id, {"attacks": [], "detections": [], "runbooks": []})
        claims[atlas_id][kind].append(owner)

    from attacks.runner import discover  # noqa: PLC0415

    for aid, (manifest, _) in discover().items():
        for tid in manifest.atlas:
            add(tid, "attacks", aid)

    from detections.run import load_all  # noqa: PLC0415

    for did, det in load_all().items():
        for tid in _ATLAS_ID.findall(det.atlas):
            add(tid, "detections", did)

    for path in sorted((REPO / "runbooks").glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for tid in data.get("atlas", []):
            add(tid, "runbooks", data["id"])

    return claims


def main() -> int:
    ap = argparse.ArgumentParser(description="ATLAS coverage matrix generator")
    ap.add_argument("--offline", action="store_true", help="use the cached bundle only")
    args = ap.parse_args()

    try:
        bundle = fetch(args.offline)
        techniques = index_techniques(bundle)
        claims = collect_claims()
    except AtlasError as exc:
        logger.error("%s", exc)
        return 2

    if not techniques:
        logger.error("no ATLAS techniques parsed from the bundle - format may have changed")
        return 2

    invalid = sorted(t for t in claims if t not in techniques)
    stale = sorted(
        t for t in claims if t in techniques and (techniques[t]["revoked"] or techniques[t]["deprecated"])
    )

    total_techniques = sum(1 for t in techniques.values() if not t["revoked"] and not t["deprecated"])
    covered = sorted(t for t in claims if t in techniques)

    lines = [
        "# MITRE ATLAS coverage",
        "",
        "> Generated by `mappings/atlas_coverage.py` from the official ATLAS STIX 2.1 bundle.",
        "> Do not edit by hand.",
        "",
        f"- ATLAS objects parsed: **{len(techniques)}** ({total_techniques} current)",
        f"- Techniques claimed by AIRCAP: **{len(covered)}**",
        f"- Invalid ids claimed: **{len(invalid)}**",
        "",
        "Coverage here means *this repo exercises or detects the technique*, not that the",
        "technique is fully mitigated. Several are detect-only - see the residual risk table",
        "in the README.",
        "",
        "## Covered techniques",
        "",
        "| ATLAS id | Name | Tactic(s) | Attacks | Detections | Runbooks |",
        "|---|---|---|---|---|---|",
    ]
    for tid in covered:
        info, claim = techniques[tid], claims[tid]
        lines.append(
            f"| [{tid}](https://atlas.mitre.org/techniques/{tid}) | {info['name']} | "
            f"{', '.join(info['tactics']) or '-'} | {', '.join(claim['attacks']) or '-'} | "
            f"{', '.join(claim['detections']) or '-'} | {', '.join(claim['runbooks']) or '-'} |"
        )

    if invalid:
        lines += [
            "",
            "## Invalid claims (must be fixed)",
            "",
            "These ids appear in the repo but not in the ATLAS bundle:",
            "",
        ]
        lines += [f"- `{t}` claimed by {claims[t]}" for t in invalid]
    if stale:
        lines += ["", "## Revoked or deprecated in ATLAS", ""] + [
            f"- `{t}` ({techniques[t]['name']})" for t in stale
        ]

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)}: {len(covered)} techniques covered, {len(invalid)} invalid")
    for t in invalid:
        logger.error("invalid ATLAS id claimed: %s by %s", t, claims[t])
    return 1 if invalid else 0


if __name__ == "__main__":
    sys.exit(main())
