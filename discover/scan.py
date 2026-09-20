#!/usr/bin/env python3
"""Shadow-AI discovery for a managed endpoint.

Four lenses, none of which requires root:

  process  - locally-running inference runtimes, and whether they hold the GPU
  listener - unauthenticated local model APIs bound to a port
  browser  - AI extensions installed in browser profiles
  egress   - established connections to known model/agent destinations

A fifth lens, live SNI capture, needs packet-capture privileges and is therefore
opt-in (--capture). It reuses the tshark approach from sni-monitor.sh. Everything
else runs as an ordinary user, which matters: a discovery tool that needs root is
a discovery tool that does not get deployed.

Output is a risk-scored asset register at data/discover/inventory.json.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("aircap.discover")

DESTINATIONS = Path(__file__).resolve().parent / "ai_destinations.yml"
OUT_DIR = REPO / "data" / "discover"

RISK_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5}
# An unsanctioned finding is the governance problem; a sanctioned one is just inventory.
UNSANCTIONED_PENALTY = 20
UNAUTH_LISTENER_PENALTY = 15


class DiscoveryError(RuntimeError):
    """Raised when the destination inventory cannot be loaded."""


@dataclass
class Finding:
    lens: str
    asset: str
    category: str
    detail: str
    sanctioned: bool
    data_egress_risk: str
    risk_score: int
    evidence: dict[str, Any] = field(default_factory=dict)


def load_inventory() -> dict[str, Any]:
    try:
        data = yaml.safe_load(DESTINATIONS.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DiscoveryError(f"cannot load {DESTINATIONS}: {exc}") from exc
    for key in ("providers", "local_runtimes", "browser_extensions"):
        if key not in data:
            raise DiscoveryError(f"{DESTINATIONS} missing '{key}'")
    return data


def _score(risk: str, sanctioned: bool, extra: int = 0) -> int:
    return min(100, RISK_WEIGHT.get(risk, 5) + (0 if sanctioned else UNSANCTIONED_PENALTY) + extra)


def _run(cmd: list[str], timeout: int = 15) -> str:
    """Run a read-only command, returning '' rather than raising."""
    if not shutil.which(cmd[0]):
        logger.debug("%s not installed, skipping", cmd[0])
        return ""
    try:
        res = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return res.stdout
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("%s failed: %s", cmd[0], exc)
        return ""


# --- lens 1: processes -------------------------------------------------------

def scan_processes(inv: dict) -> list[Finding]:
    out: list[Finding] = []
    ps = _run(["ps", "-eo", "pid,comm,args"])
    if not ps:
        return out

    gpu_pids: dict[str, str] = {}
    gpu = _run(["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory",
                "--format=csv,noheader"])
    for line in gpu.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 3 and parts[0].isdigit():
            gpu_pids[parts[0]] = f"{parts[1]} using {parts[2]}"

    for runtime in inv["local_runtimes"]:
        names = {n.lower() for n in runtime["processes"]}
        for line in ps.splitlines()[1:]:
            fields = line.split(maxsplit=2)
            if len(fields) < 2:
                continue
            pid, comm = fields[0], fields[1]
            if comm.lower() not in names:
                continue
            evidence = {"pid": pid, "comm": comm, "args": (fields[2] if len(fields) > 2 else "")[:200]}
            extra = 0
            if pid in gpu_pids:
                evidence["gpu"] = gpu_pids[pid]
                extra = 10          # holding the GPU means real inference, not an idle binary
            out.append(
                Finding(
                    lens="process",
                    asset=runtime["name"],
                    category="local_runtime",
                    detail=f"running as pid {pid}"
                    + (f", {gpu_pids[pid]}" if pid in gpu_pids else ""),
                    sanctioned=False,
                    data_egress_risk=runtime["data_egress_risk"],
                    risk_score=_score(runtime["data_egress_risk"], False, extra),
                    evidence=evidence,
                )
            )
    return out


# --- lens 2: listeners -------------------------------------------------------

def scan_listeners(inv: dict) -> list[Finding]:
    out: list[Finding] = []
    ss = _run(["ss", "-tlnp"])
    if not ss:
        return out

    by_port: dict[int, dict] = {}
    for runtime in inv["local_runtimes"]:
        for port in runtime["default_ports"]:
            by_port[port] = runtime

    for line in ss.splitlines()[1:]:
        match = re.search(r":(\d+)\s", line)
        if not match:
            continue
        port = int(match.group(1))
        runtime = by_port.get(port)
        if not runtime:
            continue
        local = line.split()[3] if len(line.split()) > 3 else ""
        exposed = not local.startswith(("127.0.0.1", "[::1]"))
        out.append(
            Finding(
                lens="listener",
                asset=runtime["name"],
                category="local_model_api",
                detail=f"listening on {local}"
                + (" - REACHABLE FROM THE NETWORK" if exposed else " (loopback only)"),
                sanctioned=False,
                data_egress_risk=runtime["data_egress_risk"],
                risk_score=_score(
                    "critical" if exposed else runtime["data_egress_risk"],
                    False,
                    UNAUTH_LISTENER_PENALTY + (15 if exposed else 0),
                ),
                evidence={"port": port, "local_address": local, "network_exposed": exposed,
                          "note": runtime.get("note", "")},
            )
        )
    return out


# --- lens 3: browser extensions ---------------------------------------------

def scan_browser(inv: dict) -> list[Finding]:
    out: list[Finding] = []
    known = inv["browser_extensions"]["chromium_ids"]
    patterns = [p.lower() for p in inv["browser_extensions"]["firefox_patterns"]]
    home = Path.home()

    # Chromium-family: extension ids are directory names.
    for base in (
        home / ".config/google-chrome", home / ".config/chromium",
        home / ".config/microsoft-edge", home / ".config/BraveSoftware/Brave-Browser",
    ):
        if not base.is_dir():
            continue
        for ext_dir in base.glob("*/Extensions/*"):
            ext_id = ext_dir.name
            if ext_id not in known:
                continue
            name = known[ext_id]
            benign = "benign control sample" in name
            out.append(
                Finding(
                    lens="browser",
                    asset=name,
                    category="browser_extension",
                    detail=f"installed in {base.name}",
                    sanctioned=benign,
                    data_egress_risk="low" if benign else "high",
                    risk_score=0 if benign else _score("high", False),
                    evidence={"extension_id": ext_id, "browser": base.name,
                              "path": str(ext_dir.relative_to(home))},
                )
            )

    # Firefox: extensions.json in each profile.
    for profile in (home / ".mozilla/firefox").glob("*"):
        manifest = profile / "extensions.json"
        if not manifest.is_file():
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            logger.warning("cannot parse %s", manifest)
            continue
        for addon in data.get("addons", []):
            name = str(addon.get("defaultLocale", {}).get("name", "") or addon.get("id", ""))
            if not any(p in name.lower() for p in patterns):
                continue
            out.append(
                Finding(
                    lens="browser",
                    asset=name,
                    category="browser_extension",
                    detail=f"installed in Firefox profile {profile.name}",
                    sanctioned=False,
                    data_egress_risk="high",
                    risk_score=_score("high", False),
                    evidence={"addon_id": addon.get("id", ""), "profile": profile.name,
                              "active": addon.get("active", None)},
                )
            )
    return out


# --- lens 4: egress ----------------------------------------------------------

def _host_index(inv: dict) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for provider in inv["providers"]:
        for host in provider["hosts"]:
            idx[host.lower()] = provider
    return idx


def scan_egress(inv: dict) -> list[Finding]:
    """Established connections whose peer resolves to a known AI destination.

    Reverse-resolves peer IPs, which is imperfect - shared CDN fronting means a miss
    is common. Live SNI capture (--capture) is the accurate lens; this one needs no
    privileges, and the gap between them is worth knowing rather than hiding.
    """
    out: list[Finding] = []
    idx = _host_index(inv)
    conns = _run(["ss", "-tnp", "state", "established"])
    if not conns:
        return out

    seen: set[str] = set()
    for line in conns.splitlines():
        peer = re.search(r"\s(\d+\.\d+\.\d+\.\d+):(\d+)\s+users:", line)
        if not peer:
            continue
        ip, port = peer.group(1), peer.group(2)
        if ip.startswith(("127.", "192.168.", "10.", "172.")):
            continue
        try:
            rdns = socket.gethostbyaddr(ip)[0].lower()
        except (OSError, socket.herror):
            continue
        provider = next((p for host, p in idx.items() if rdns.endswith(host)), None)
        if not provider or f"{provider['name']}:{ip}" in seen:
            continue
        seen.add(f"{provider['name']}:{ip}")
        proc = re.search(r'users:\(\("([^"]+)"', line)
        out.append(
            Finding(
                lens="egress",
                asset=provider["name"],
                category=provider["category"],
                detail=f"established connection to {rdns} ({ip}:{port})",
                sanctioned=provider["sanctioned"],
                data_egress_risk=provider["data_egress_risk"],
                risk_score=_score(provider["data_egress_risk"], provider["sanctioned"]),
                evidence={"peer_ip": ip, "peer_port": port, "rdns": rdns,
                          "process": proc.group(1) if proc else "unknown"},
            )
        )
    return out


# --- lens 5: live SNI capture (opt-in, needs privileges) ---------------------

def scan_capture(inv: dict, iface: str, seconds: int) -> list[Finding]:
    if not shutil.which("tshark"):
        logger.error("tshark not installed; cannot capture")
        return []
    if os.geteuid() != 0:
        logger.error(
            "live capture needs packet-capture privileges. Run with sudo, or grant "
            "them once: sudo setcap cap_net_raw,cap_net_admin+eip $(which dumpcap)"
        )
        return []

    idx = _host_index(inv)
    logger.info("capturing TLS SNI and QUIC SNI on %s for %ds", iface, seconds)
    raw = _run(
        ["tshark", "-i", iface, "-a", f"duration:{seconds}", "-Y",
         "tls.handshake.extensions_server_name or quic.tls.handshake.extensions_server_name",
         "-T", "fields", "-e", "tls.handshake.extensions_server_name",
         "-e", "quic.tls.handshake.extensions_server_name", "-Q"],
        timeout=seconds + 30,
    )
    counts: dict[str, int] = {}
    for line in raw.splitlines():
        for sni in (f.strip().lower() for f in line.split("\t") if f.strip()):
            counts[sni] = counts.get(sni, 0) + 1

    out: list[Finding] = []
    for sni, hits in sorted(counts.items(), key=lambda kv: -kv[1]):
        provider = next((p for host, p in idx.items() if sni.endswith(host)), None)
        if not provider:
            continue
        out.append(
            Finding(
                lens="capture",
                asset=provider["name"],
                category=provider["category"],
                detail=f"{hits} TLS/QUIC handshake(s) to {sni}",
                sanctioned=provider["sanctioned"],
                data_egress_risk=provider["data_egress_risk"],
                risk_score=_score(provider["data_egress_risk"], provider["sanctioned"]),
                evidence={"sni": sni, "handshakes": hits, "interface": iface},
            )
        )
    return out


def default_interface() -> str:
    out = _run(["ip", "route", "show", "default"])
    match = re.search(r"dev\s+(\S+)", out)
    return match.group(1) if match else "any"


def build_register(findings: list[Finding], lenses_run: list[str], notes: list[str]) -> dict:
    unsanctioned = [f for f in findings if not f.sanctioned]
    top = max((f.risk_score for f in findings), default=0)
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": socket.gethostname(),
        "lenses_run": lenses_run,
        "summary": {
            "findings_total": len(findings),
            "unsanctioned": len(unsanctioned),
            "highest_risk_score": top,
            "posture": (
                "critical" if top >= 70 else
                "elevated" if top >= 40 else
                "monitored" if top else "clean"
            ),
            "by_lens": {
                lens: sum(1 for f in findings if f.lens == lens) for lens in lenses_run
            },
            "by_category": {
                cat: sum(1 for f in findings if f.category == cat)
                for cat in sorted({f.category for f in findings})
            },
        },
        "notes": notes,
        "findings": [asdict(f) for f in sorted(findings, key=lambda f: -f.risk_score)],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="AIRCAP shadow-AI endpoint discovery")
    ap.add_argument("--capture", action="store_true", help="add live SNI capture (needs privileges)")
    ap.add_argument("--iface", default=None, help="capture interface (default: default route)")
    ap.add_argument("--seconds", type=int, default=20, help="capture duration")
    ap.add_argument("--json", action="store_true", help="print the register instead of a summary")
    args = ap.parse_args()

    try:
        inv = load_inventory()
    except DiscoveryError as exc:
        logger.error("%s", exc)
        return 2

    findings: list[Finding] = []
    lenses = ["process", "listener", "browser", "egress"]
    notes = [
        "The egress lens reverse-resolves peer IPs, so CDN-fronted providers are often "
        "missed. Use --capture for an accurate network view; the gap between the two is "
        "a known limitation, not a bug.",
    ]

    findings += scan_processes(inv)
    findings += scan_listeners(inv)
    findings += scan_browser(inv)
    findings += scan_egress(inv)

    if args.capture:
        iface = args.iface or default_interface()
        captured = scan_capture(inv, iface, args.seconds)
        if captured or os.geteuid() == 0:
            lenses.append("capture")
            findings += captured
        else:
            notes.append("live capture was requested but could not run (see log above)")

    register = build_register(findings, lenses, notes)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / "inventory.json"
    path.write_text(json.dumps(register, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(register, indent=2))
        return 0

    s = register["summary"]
    print(f"\nAIRCAP shadow-AI discovery - {register['host']}\n{'=' * 78}")
    print(f"posture: {s['posture'].upper()}   findings: {s['findings_total']}   "
          f"unsanctioned: {s['unsanctioned']}   top risk: {s['highest_risk_score']}/100")
    print(f"lenses: {', '.join(lenses)}\n")
    if not findings:
        print("  no AI assets found by any lens")
    else:
        print(f"  {'RISK':>4}  {'LENS':9} {'ASSET':26} DETAIL")
        print("  " + "-" * 74)
        for f in register["findings"]:
            flag = " " if f["sanctioned"] else "!"
            print(f"  {f['risk_score']:>4}{flag} {f['lens']:9} {f['asset'][:26]:26} {f['detail'][:34]}")
        print("\n  ! = unsanctioned")
    print(f"\nregister: {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
