#!/usr/bin/env python3
"""Attack runner.

  runner.py --all                 run every attack under its own posture
  runner.py --id A05 A07          run specific attacks
  runner.py --all --hardened      run every attack with all controls ON (control test)
  runner.py --registry            regenerate attacks/registry.yml from the manifests
"""

from __future__ import annotations

import argparse
import importlib
import logging
import pkgutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

from attacks.base import AttackContext, AttackResult, Manifest  # noqa: E402
from lab.app.config import base  # noqa: E402
from lab.telemetry.emitter import TelemetrySink  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(name)s %(message)s")
logger = logging.getLogger("aircap.runner")

ATTACK_DIR = Path(__file__).resolve().parent


class AttackLoadError(RuntimeError):
    """Raised when an attack module is malformed."""


def discover() -> dict[str, tuple[Manifest, object]]:
    found: dict[str, tuple[Manifest, object]] = {}
    for info in sorted(pkgutil.iter_modules([str(ATTACK_DIR)]), key=lambda i: i.name):
        if not info.name.startswith("a") or info.name in {"base"}:
            continue
        module = importlib.import_module(f"attacks.{info.name}")
        manifest = getattr(module, "MANIFEST", None)
        if not isinstance(manifest, Manifest):
            raise AttackLoadError(f"attacks.{info.name} has no MANIFEST")
        if not callable(getattr(module, "run", None)):
            raise AttackLoadError(f"attacks.{info.name} has no run()")
        if manifest.id in found:
            raise AttackLoadError(f"duplicate attack id {manifest.id}")
        found[manifest.id] = (manifest, module)
    return found


def write_registry(attacks: dict[str, tuple[Manifest, object]]) -> Path:
    payload = [
        {
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "posture": m.posture or {},
            "atlas": list(m.atlas),
            "owasp": list(m.owasp),
            "expect_detections": list(m.expect),
            "notes": m.notes,
        }
        for m, _ in attacks.values()
    ]
    out = ATTACK_DIR / "registry.yml"
    out.write_text(
        "# GENERATED from attack MANIFESTs by attacks/runner.py --registry. Do not edit.\n"
        + yaml.safe_dump(payload, sort_keys=False, width=100),
        encoding="utf-8",
    )
    return out


def run_one(manifest: Manifest, module, sink: TelemetrySink, hardened: bool) -> AttackResult:
    ctx = AttackContext(sink, manifest.id, hardened=hardened)
    try:
        return module.run(ctx)
    except Exception as exc:  # noqa: BLE001 - one broken attack must not stop the suite
        logger.error("attack %s raised: %s: %s", manifest.id, type(exc).__name__, exc)
        return AttackResult(False, f"{type(exc).__name__}: {exc}")
    finally:
        ctx.cleanup()


def main() -> int:
    ap = argparse.ArgumentParser(description="AIRCAP attack runner")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--all", action="store_true")
    g.add_argument("--id", nargs="+", metavar="ID")
    g.add_argument("--registry", action="store_true")
    ap.add_argument(
        "--hardened",
        action="store_true",
        help="run with all controls on; attacks are expected to FAIL",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    try:
        attacks = discover()
    except AttackLoadError as exc:
        logger.error("%s", exc)
        return 2

    if args.registry:
        print(f"wrote {write_registry(attacks).relative_to(REPO)} ({len(attacks)} attacks)")
        return 0

    selected = list(attacks) if args.all else args.id
    unknown = [i for i in selected if i not in attacks]
    if unknown:
        logger.error("unknown attack id(s): %s; known: %s", ", ".join(unknown), ", ".join(attacks))
        return 2

    cfg = base()
    sink = TelemetrySink(cfg.data_dir, cfg.account_id, cfg.region)
    mode = "HARDENED (controls on, attacks should fail)" if args.hardened else "VULNERABLE"
    print(f"\nAIRCAP attack run - {mode}\n{'=' * 78}")

    results: list[tuple[Manifest, AttackResult]] = []
    for aid in selected:
        manifest, module = attacks[aid]
        result = run_one(manifest, module, sink, args.hardened)
        results.append((manifest, result))
        verdict = "SUCCEEDED" if result.succeeded else "blocked/failed"
        print(f"\n{manifest.id}  {manifest.name}")
        print(f"     posture : {'hardened baseline' if args.hardened else (manifest.posture or 'hardened baseline')}")
        print(f"     atlas   : {', '.join(manifest.atlas) or '-'}")
        print(f"     result  : {verdict}")
        print(f"     detail  : {result.detail}")
        if args.hardened:
            expected = not manifest.baseline_prevents
            flag = "as expected" if result.succeeded == expected else "UNEXPECTED"
            print(f"     control : layer={manifest.control_layer} "
                  f"baseline_prevents={manifest.baseline_prevents} -> {flag}")

    succeeded = sum(1 for _, r in results if r.succeeded)
    print(f"\n{'=' * 78}")
    print(f"{succeeded}/{len(results)} attacks succeeded  (telemetry run_id={sink.run_id})")

    if not args.hardened:
        return 0

    # A hardened run is a regression test against each manifest's stated expectation,
    # not an assertion that nothing can succeed. Four of these attacks are expected to
    # succeed hardened because no preventive control exists for them yet; treating that
    # as a failure would only encourage weakening the expectation until it passes.
    mismatches = [
        (m, r) for m, r in results if r.succeeded != (not m.baseline_prevents)
    ]
    residual = [m for m, r in results if r.succeeded and not m.baseline_prevents]

    print("\nresidual risk - succeeded against the hardened baseline:")
    for m in residual:
        print(f"  {m.id}  {m.name}  (control layer: {m.control_layer})")
    if not residual:
        print("  none")

    if mismatches:
        print("\nCONTROL TEST FAILED - outcome did not match the manifest:")
        for m, r in mismatches:
            want = "prevented" if m.baseline_prevents else "expected to succeed"
            got = "succeeded" if r.succeeded else "prevented"
            print(f"  {m.id}: expected {want}, got {got} - {r.detail}")
        return 1

    prevented = sum(1 for m, _ in results if m.baseline_prevents)
    print(
        f"\nCONTROL TEST PASSED: {prevented} app-layer attacks prevented by the baseline, "
        f"{len(residual)} documented residual risks reproduced as expected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
