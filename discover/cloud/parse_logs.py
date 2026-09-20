#!/usr/bin/env python3
"""Classify AI egress in cloud network telemetry.

Three parsers, each reading the real wire format:

  vpc      - VPC Flow Logs v2 (space-delimited text)
  route53  - Route 53 Resolver query logs (JSONL) - the highest-signal source, because
             it carries the queried *hostname* rather than an IP that needs resolving
  nsg      - Azure NSG flow logs v2 (nested JSON with comma-packed flow tuples)

Ships synthetic samples so it runs at zero cloud cost. The samples are labelled
synthetic in the output; nothing here pretends to be a real capture.

  parse_logs.py --all
  parse_logs.py --route53 path/to/logs.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("aircap.cloudlogs")

HERE = Path(__file__).resolve().parent
SAMPLES = HERE / "samples"
DESTINATIONS = HERE.parent / "ai_destinations.yml"

# IPs appearing in the shipped samples, so the IP-only parsers can attribute a
# provider without DNS. In a real deployment this table is built from Route 53
# answers or a threat-intel feed - which is exactly why Route 53 logs are the
# lens worth enabling first.
SAMPLE_IP_MAP = {
    "104.18.32.47": "api.openai.com",
    "160.79.104.10": "api.anthropic.com",
    "3.5.29.100": "bedrock-runtime.us-east-1.amazonaws.com",
    "140.82.121.6": "api.githubcopilot.com",
    "76.76.21.21": "registry.modelcontextprotocol.io",
    "20.53.12.9": "openai.azure.com",
    "169.254.169.254": "instance-metadata-service",
}


class ParseError(RuntimeError):
    """Raised when a log file cannot be read or parsed."""


def host_index() -> dict[str, dict[str, Any]]:
    data = yaml.safe_load(DESTINATIONS.read_text(encoding="utf-8"))
    return {h.lower(): p for p in data["providers"] for h in p["hosts"]}


def classify(hostname: str, idx: dict[str, dict]) -> dict[str, Any] | None:
    host = hostname.rstrip(".").lower()
    for known, provider in idx.items():
        if host.endswith(known):
            return provider
    return None


def parse_vpc(path: Path, idx: dict) -> list[dict]:
    """VPC Flow Logs v2. Bytes matter here: volume distinguishes a health check
    from a repository being uploaded to a coding assistant."""
    out: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc

    for line in lines:
        f = line.split()
        if len(f) < 14:
            continue
        srcaddr, dstaddr, dstport, packets, nbytes, action = f[3], f[4], f[6], f[5], f[9], f[12]
        hostname = SAMPLE_IP_MAP.get(dstaddr)
        if dstaddr == "169.254.169.254":
            out.append({
                "source": "vpc_flow_logs", "src": srcaddr, "dst": dstaddr,
                "hostname": "instance metadata service", "provider": "N/A",
                "category": "imds_access", "sanctioned": False,
                "data_egress_risk": "critical", "bytes": int(nbytes), "action": action,
                "note": "IMDS reached from a workload - the pivot from app-layer injection "
                        "to cloud credentials. See detection D008.",
            })
            continue
        if not hostname:
            continue
        provider = classify(hostname, idx)
        if not provider:
            continue
        out.append({
            "source": "vpc_flow_logs", "src": srcaddr, "dst": dstaddr, "dst_port": dstport,
            "hostname": hostname, "provider": provider["name"],
            "category": provider["category"], "sanctioned": provider["sanctioned"],
            "data_egress_risk": provider["data_egress_risk"],
            "bytes": int(nbytes), "packets": int(packets), "action": action,
        })
    return out


def parse_route53(path: Path, idx: dict) -> list[dict]:
    """Route 53 Resolver query logs. Carries the hostname, so no IP attribution needed."""
    out: list[dict] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ParseError(f"cannot read {path}: {exc}") from exc

    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.warning("%s line %d is not JSON: %s", path.name, n, exc)
            continue
        name = str(rec.get("query_name", ""))
        provider = classify(name, idx)
        if not provider:
            continue
        out.append({
            "source": "route53_resolver", "ts": rec.get("query_timestamp"),
            "src": rec.get("srcaddr"), "instance": rec.get("srcids", {}).get("instance"),
            "hostname": name.rstrip("."), "provider": provider["name"],
            "category": provider["category"], "sanctioned": provider["sanctioned"],
            "data_egress_risk": provider["data_egress_risk"],
            "answers": [a.get("Rdata") for a in rec.get("answers", [])],
        })
    return out


def parse_nsg(path: Path, idx: dict) -> list[dict]:
    """Azure NSG flow logs v2. Flow tuples are comma-packed strings inside nested JSON:
    ts,src,dst,srcport,dstport,proto,direction,decision,state,packets_out,bytes_out,
    packets_in,bytes_in - with the counters empty on the first tuple of a flow."""
    out: list[dict] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseError(f"cannot parse {path}: {exc}") from exc

    for record in doc.get("records", []):
        nsg = str(record.get("resourceId", "")).rsplit("/", 1)[-1]
        for rule in record.get("properties", {}).get("flows", []):
            rule_name = rule.get("rule", "")
            for group in rule.get("flows", []):
                for tup in group.get("flowTuples", []):
                    parts = tup.split(",")
                    if len(parts) < 8:
                        continue
                    src, dst = parts[1], parts[2]
                    hostname = SAMPLE_IP_MAP.get(dst)
                    if not hostname:
                        continue
                    provider = classify(hostname, idx)
                    if not provider:
                        continue
                    bytes_out = int(parts[10]) if len(parts) > 10 and parts[10] else 0
                    out.append({
                        "source": "azure_nsg_flow", "nsg": nsg, "rule": rule_name,
                        "src": src, "dst": dst, "dst_port": parts[4], "hostname": hostname,
                        "provider": provider["name"], "category": provider["category"],
                        "sanctioned": provider["sanctioned"],
                        "data_egress_risk": provider["data_egress_risk"],
                        "bytes_out": bytes_out, "decision": parts[7],
                    })
    return out


def summarise(findings: list[dict]) -> dict:
    by_provider: dict[str, dict] = defaultdict(
        lambda: {"flows": 0, "bytes": 0, "sanctioned": None, "risk": None, "sources": set()}
    )
    for f in findings:
        p = by_provider[f["provider"]]
        p["flows"] += 1
        p["bytes"] += int(f.get("bytes", 0) or f.get("bytes_out", 0) or 0)
        p["sanctioned"] = f["sanctioned"]
        p["risk"] = f["data_egress_risk"]
        p["sources"].add(f["source"])
    return {
        "synthetic": True,
        "note": "Parsed from synthetic sample logs shipped with this repo. Formats are "
                "faithful to AWS VPC Flow Logs v2, Route 53 Resolver query logs and Azure "
                "NSG flow logs v2; the contents are fabricated and no cloud account was used.",
        "flows_total": len(findings),
        "unsanctioned_flows": sum(1 for f in findings if not f["sanctioned"]),
        "providers": {
            name: {**v, "sources": sorted(v["sources"])} for name, v in sorted(by_provider.items())
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Classify AI egress in cloud network logs")
    ap.add_argument("--all", action="store_true", help="parse all shipped samples")
    ap.add_argument("--vpc", type=Path, help="VPC Flow Logs v2 file")
    ap.add_argument("--route53", type=Path, help="Route 53 Resolver query log (JSONL)")
    ap.add_argument("--nsg", type=Path, help="Azure NSG flow log (JSON)")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    if not any([args.all, args.vpc, args.route53, args.nsg]):
        ap.error("choose --all or at least one of --vpc / --route53 / --nsg")

    idx = host_index()
    findings: list[dict] = []
    try:
        if args.all or args.vpc:
            findings += parse_vpc(args.vpc or SAMPLES / "vpc-flow-logs.txt", idx)
        if args.all or args.route53:
            findings += parse_route53(args.route53 or SAMPLES / "route53-resolver-queries.jsonl", idx)
        if args.all or args.nsg:
            findings += parse_nsg(args.nsg or SAMPLES / "azure-nsg-flow-logs.json", idx)
    except ParseError as exc:
        logger.error("%s", exc)
        return 2

    summary = summarise(findings)
    out_dir = REPO / "data" / "discover"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cloud_egress.json").write_text(
        json.dumps({"summary": summary, "findings": findings}, indent=2), encoding="utf-8"
    )

    if args.json:
        print(json.dumps({"summary": summary, "findings": findings}, indent=2))
        return 0

    print(f"\nAIRCAP cloud AI-egress classification (SYNTHETIC SAMPLES)\n{'=' * 78}")
    print(f"{summary['flows_total']} classified flow(s), "
          f"{summary['unsanctioned_flows']} unsanctioned\n")
    print(f"  {'PROVIDER':28} {'RISK':9} {'FLOWS':>5} {'BYTES':>10}  SOURCES")
    print("  " + "-" * 74)
    for name, v in summary["providers"].items():
        flag = " " if v["sanctioned"] else "!"
        print(f"  {name[:28]:28}{flag}{str(v['risk']):8} {v['flows']:>5} {v['bytes']:>10}  "
              f"{','.join(s.split('_')[0] for s in v['sources'])}")
    imds = [f for f in findings if f.get("category") == "imds_access"]
    if imds:
        print(f"\n  IMDS access observed from {imds[0]['src']} - correlate with detection D008")
    print("\n  ! = unsanctioned")
    print(f"\nwritten: data/discover/cloud_egress.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
