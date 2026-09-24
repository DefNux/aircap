#!/usr/bin/env python3
"""Audit whether an AWS account can reconstruct what its AI workloads were asked.

WHAT THIS ANSWERS
    "We process AI traffic through AWS. If something goes wrong, can we prove what
    was asked, by whom, and what came back?"

    Bedrock model invocation logging and CloudTrail data events for Bedrock are BOTH
    OFF BY DEFAULT. Invocation logging is the only record of prompt and completion
    bodies; CloudTrail data events are the only record of who called the model. Data
    events bill per event, so they are commonly left disabled. An account can
    therefore run millions of tokens of traffic with no forensic record at all.

    This script measures that gap and quantifies it, by pairing usage evidence
    (CloudWatch metrics, which are always on) against logging configuration.

STRICTLY READ-ONLY. Every API call this script can make, for security review:

    sts:GetCallerIdentity
    organizations:DescribeOrganization              (optional, to flag multi-account)
    bedrock:GetModelInvocationLoggingConfiguration  <-- the central check
    bedrock:ListGuardrails
    bedrock:ListFoundationModels
    cloudtrail:DescribeTrails
    cloudtrail:GetTrailStatus
    cloudtrail:GetEventSelectors
    cloudwatch:GetMetricStatistics                  (AWS/Bedrock namespace only)
    ce:GetCostAndUsage                              (optional, --cost)
    iam:GetAccountAuthorizationDetails              (optional, --iam)

    No Create/Put/Update/Delete/Start/Stop call appears anywhere in this file.
    It never reads a prompt, a completion, or any log body - only configuration,
    aggregate metrics and cost totals.

SCOPE LIMIT WORTH KNOWING
    This sees Bedrock only. Spend on Anthropic, OpenAI, Cursor or Copilot via vendor
    APIs is invisible to AWS entirely and needs each vendor's admin/audit API. Do not
    present this as total AI exposure.

USAGE
    python3 aws_ai_telemetry_audit.py                      # current account, common regions
    python3 aws_ai_telemetry_audit.py --regions us-east-1 eu-west-1
    python3 aws_ai_telemetry_audit.py --all-regions --cost --iam
    python3 aws_ai_telemetry_audit.py --json report.json

    Multi-account: run per account, or with a role that can be assumed org-wide via
    --assume-role arn:aws:iam::<acct>:role/<AuditRole>. Read-only permissions are
    sufficient; SecurityAudit or ViewOnlyAccess covers everything above.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:  # pragma: no cover
    print("boto3 is required:  pip install boto3", file=sys.stderr)
    raise SystemExit(2) from None

logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("ai-telemetry-audit")

# Regions where Bedrock is commonly enabled. Override with --regions / --all-regions.
DEFAULT_REGIONS = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-south-1",
                   "ap-southeast-1", "ap-northeast-1"]

BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"},
                     connect_timeout=15, read_timeout=45)

DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
          "AuthorizationError")


class AuditError(RuntimeError):
    """Raised when the audit cannot start at all."""


def _session(assume_role: str | None, external_id: str | None) -> boto3.Session:
    base = boto3.Session()
    if not assume_role:
        return base
    try:
        sts = base.client("sts", config=BOTO_CONFIG)
        kwargs: dict[str, Any] = {
            "RoleArn": assume_role,
            "RoleSessionName": "ai-telemetry-audit",
        }
        if external_id:
            kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
    except (ClientError, BotoCoreError) as exc:
        raise AuditError(f"cannot assume {assume_role}: {exc}") from exc
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _call(fn, *args, **kwargs) -> tuple[Any, str | None]:
    """Invoke a read-only API. Returns (result, error_label). Never raises."""
    try:
        return fn(*args, **kwargs), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in DENIED:
            return None, "access_denied"
        if code in ("ResourceNotFoundException", "ValidationException"):
            return None, "not_configured"
        if code in ("UnrecognizedClientException", "InvalidClientTokenId",
                    "EndpointConnectionError", "OptInRequired"):
            return None, "region_unavailable"
        logger.debug("%s -> %s", getattr(fn, "__name__", "call"), code)
        return None, code
    except (BotoCoreError, NoCredentialsError) as exc:
        return None, type(exc).__name__


# --- individual checks ------------------------------------------------------

def check_invocation_logging(session: boto3.Session, region: str) -> dict[str, Any]:
    """The central question: is there any record of prompts and completions?"""
    client = session.client("bedrock", region_name=region, config=BOTO_CONFIG)
    resp, err = _call(client.get_model_invocation_logging_configuration)

    if err == "not_configured":
        return {"enabled": False, "reason": "no logging configuration exists"}
    if err:
        return {"enabled": None, "error": err}

    cfg = (resp or {}).get("loggingConfig") or {}
    if not cfg:
        return {"enabled": False, "reason": "logging configuration is empty"}

    s3 = cfg.get("s3Config") or {}
    cw = cfg.get("cloudWatchConfig") or {}
    return {
        "enabled": bool(s3 or cw),
        "text_data_delivery": cfg.get("textDataDeliveryEnabled"),
        "image_data_delivery": cfg.get("imageDataDeliveryEnabled"),
        "embedding_data_delivery": cfg.get("embeddingDataDeliveryEnabled"),
        "s3_bucket": s3.get("bucketName"),
        "s3_prefix": s3.get("keyPrefix"),
        "cloudwatch_log_group": cw.get("logGroupName"),
        # Bodies are only captured when text delivery is on. Logging "enabled" with
        # text delivery off records metadata and no prompts - a common misconfiguration
        # that looks compliant on a dashboard.
        "captures_prompt_bodies": bool(cfg.get("textDataDeliveryEnabled")),
    }


def check_cloudtrail_bedrock(session: boto3.Session, region: str) -> dict[str, Any]:
    """Do any trails capture bedrock:InvokeModel? Data events are opt-in and billed."""
    client = session.client("cloudtrail", region_name=region, config=BOTO_CONFIG)
    resp, err = _call(client.describe_trails, includeShadowTrails=False)
    if err:
        return {"trails": [], "bedrock_data_events": None, "error": err}

    trails_out: list[dict[str, Any]] = []
    covered = False

    for trail in (resp or {}).get("trailList", []):
        name = trail.get("Name", "")
        entry: dict[str, Any] = {
            "name": name,
            "multi_region": trail.get("IsMultiRegionTrail", False),
            "org_trail": trail.get("IsOrganizationTrail", False),
            "log_file_validation": trail.get("LogFileValidationEnabled", False),
            "cloudwatch_logs": bool(trail.get("CloudWatchLogsLogGroupArn")),
            "kms_encrypted": bool(trail.get("KmsKeyId")),
            "bedrock_data_events": False,
            "selector_style": None,
        }

        status, serr = _call(client.get_trail_status, Name=trail.get("TrailARN", name))
        entry["is_logging"] = None if serr else (status or {}).get("IsLogging")

        sel, selerr = _call(client.get_event_selectors, TrailName=trail.get("TrailARN", name))
        if selerr:
            entry["selector_error"] = selerr
            trails_out.append(entry)
            continue

        sel = sel or {}
        advanced = sel.get("AdvancedEventSelectors") or []
        basic = sel.get("EventSelectors") or []

        if advanced:
            entry["selector_style"] = "advanced"
            for s in advanced:
                fields = s.get("FieldSelectors") or []
                is_data = any(
                    f.get("Field") == "eventCategory" and "Data" in (f.get("Equals") or [])
                    for f in fields
                )
                hits_bedrock = any(
                    f.get("Field") == "resources.type"
                    and any("Bedrock" in v for v in (f.get("Equals") or []))
                    for f in fields
                )
                # A selector that names eventCategory=Data with no resources.type
                # restriction captures every data-event source, Bedrock included.
                unrestricted = is_data and not any(
                    f.get("Field") == "resources.type" for f in fields
                )
                if is_data and (hits_bedrock or unrestricted):
                    entry["bedrock_data_events"] = True
                    entry["matched_selector"] = s.get("Name") or "(unnamed)"
        elif basic:
            entry["selector_style"] = "basic"
            # Basic selectors only support S3 and Lambda data events. Bedrock data
            # events require advanced selectors, so a basic-only trail cannot cover it.
            entry["bedrock_data_events"] = False
            entry["note"] = "basic event selectors cannot capture Bedrock data events"

        covered = covered or entry["bedrock_data_events"]
        trails_out.append(entry)

    return {"trails": trails_out, "bedrock_data_events": covered}


def check_usage(session: boto3.Session, region: str, days: int) -> dict[str, Any]:
    """CloudWatch AWS/Bedrock metrics. Always on, so this is usage ground truth."""
    cw = session.client("cloudwatch", region_name=region, config=BOTO_CONFIG)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    out: dict[str, Any] = {"window_days": days}

    for metric, key in (("Invocations", "invocations"),
                        ("InputTokenCount", "input_tokens"),
                        ("OutputTokenCount", "output_tokens"),
                        ("InvocationClientErrors", "client_errors"),
                        ("InvocationThrottles", "throttles")):
        resp, err = _call(
            cw.get_metric_statistics,
            Namespace="AWS/Bedrock", MetricName=metric,
            StartTime=start, EndTime=end, Period=86400, Statistics=["Sum"],
        )
        if err:
            out[key] = None
            out.setdefault("errors", {})[metric] = err
            continue
        pts = (resp or {}).get("Datapoints") or []
        out[key] = int(sum(p.get("Sum", 0) for p in pts))
        if metric == "Invocations":
            out["active_days"] = len(pts)
    return out


def check_guardrails(session: boto3.Session, region: str) -> dict[str, Any]:
    client = session.client("bedrock", region_name=region, config=BOTO_CONFIG)
    resp, err = _call(client.list_guardrails)
    if err:
        return {"count": None, "error": err}
    items = (resp or {}).get("guardrails") or []
    return {
        "count": len(items),
        "guardrails": [
            {"id": g.get("id"), "name": g.get("name"), "status": g.get("status")}
            for g in items
        ],
    }


def check_models(session: boto3.Session, region: str) -> dict[str, Any]:
    client = session.client("bedrock", region_name=region, config=BOTO_CONFIG)
    resp, err = _call(client.list_foundation_models)
    if err:
        return {"count": None, "error": err}
    models = (resp or {}).get("modelSummaries") or []
    providers: dict[str, int] = {}
    for m in models:
        providers[m.get("providerName", "unknown")] = providers.get(m.get("providerName", "unknown"), 0) + 1
    return {"count": len(models), "providers": providers}


def check_cost(session: boto3.Session, days: int) -> dict[str, Any]:
    """Cost Explorer lives only in us-east-1. Bedrock spend only - not vendor APIs."""
    ce = session.client("ce", region_name="us-east-1", config=BOTO_CONFIG)
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=days)
    resp, err = _call(
        ce.get_cost_and_usage,
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        Filter={"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Bedrock"]}},
        GroupBy=[{"Type": "DIMENSION", "Key": "REGION"}],
    )
    if err:
        return {"error": err,
                "hint": "needs ce:GetCostAndUsage and Cost Explorer enabled in the payer account"}
    total = 0.0
    by_region: dict[str, float] = {}
    for period in (resp or {}).get("ResultsByTime", []):
        for group in period.get("Groups", []):
            amt = float(group["Metrics"]["UnblendedCost"]["Amount"])
            total += amt
            by_region[group["Keys"][0]] = by_region.get(group["Keys"][0], 0.0) + amt
    return {"window_days": days, "currency": "USD", "total": round(total, 2),
            "by_region": {k: round(v, 2) for k, v in sorted(by_region.items(),
                                                            key=lambda kv: -kv[1])}}


def check_iam_invokers(session: boto3.Session) -> dict[str, Any]:
    """Which principals carry a policy allowing bedrock:InvokeModel.

    One heavy read call, paginated. Reports whether each grant is guardrail-conditioned
    and whether the model resource is a wildcard - the two things that decide whether
    detection D003/D004 are preventable or only observable.
    """
    iam = session.client("iam", config=BOTO_CONFIG)
    paginator = iam.get_paginator("get_account_authorization_details")
    principals: list[dict[str, Any]] = []
    policy_docs: dict[str, Any] = {}
    err_label = None

    def scan(doc: Any) -> tuple[bool, bool, bool]:
        """(grants_invoke, guardrail_conditioned, wildcard_resource)"""
        if isinstance(doc, str):
            return False, False, False
        stmts = doc.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        for st in stmts:
            if st.get("Effect") != "Allow":
                continue
            actions = st.get("Action", [])
            actions = [actions] if isinstance(actions, str) else actions
            if not any(
                a == "*" or a.lower().startswith("bedrock:invokemodel")
                or a.lower() in ("bedrock:*", "bedrock:converse", "bedrock:conversestream")
                for a in actions
            ):
                continue
            cond = st.get("Condition") or {}
            guardrailed = "bedrock:GuardrailIdentifier" in json.dumps(cond)
            res = st.get("Resource", [])
            res = [res] if isinstance(res, str) else res
            wildcard = any(r == "*" for r in res)
            return True, guardrailed, wildcard
        return False, False, False

    try:
        for page in paginator.paginate():
            for pol in page.get("Policies", []):
                for ver in pol.get("PolicyVersionList", []):
                    if ver.get("IsDefaultVersion"):
                        policy_docs[pol["Arn"]] = ver.get("Document")
            for kind, key in (("role", "RoleDetailList"), ("user", "UserDetailList"),
                              ("group", "GroupDetailList")):
                for ent in page.get(key, []):
                    name = ent.get("RoleName") or ent.get("UserName") or ent.get("GroupName")
                    found = guard = wild = False
                    for inline in ent.get("RolePolicyList", []) + ent.get("UserPolicyList", []) \
                            + ent.get("GroupPolicyList", []):
                        f, g, w = scan(inline.get("PolicyDocument"))
                        found, guard, wild = found or f, guard or g, wild or w
                    for att in ent.get("AttachedManagedPolicies", []):
                        doc = policy_docs.get(att.get("PolicyArn"))
                        if doc is not None:
                            f, g, w = scan(doc)
                            found, guard, wild = found or f, guard or g, wild or w
                    if found:
                        principals.append({
                            "type": kind, "name": name,
                            "guardrail_conditioned": guard,
                            "wildcard_model_resource": wild,
                        })
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        err_label = "access_denied" if code in DENIED else code
    except BotoCoreError as exc:
        err_label = type(exc).__name__

    if err_label:
        return {"error": err_label,
                "hint": "needs iam:GetAccountAuthorizationDetails (SecurityAudit covers it)"}

    return {
        "principals_allowed_to_invoke": len(principals),
        "without_guardrail_condition": sum(1 for p in principals if not p["guardrail_conditioned"]),
        "with_wildcard_model_resource": sum(1 for p in principals if p["wildcard_model_resource"]),
        "principals": sorted(principals, key=lambda p: (p["type"], p["name"]))[:200],
    }


# --- orchestration ----------------------------------------------------------

def audit(session: boto3.Session, regions: list[str], days: int,
          want_cost: bool, want_iam: bool) -> dict[str, Any]:
    ident, err = _call(session.client("sts", config=BOTO_CONFIG).get_caller_identity)
    if err:
        raise AuditError(f"cannot establish identity ({err}) - check credentials")

    report: dict[str, Any] = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "account_id": (ident or {}).get("Account"),
        "audited_as": (ident or {}).get("Arn"),
        "window_days": days,
        "read_only": True,
        "scope_note": ("Bedrock only. Spend and usage on Anthropic, OpenAI, Cursor or "
                       "Copilot vendor APIs is invisible to AWS and needs each vendor's "
                       "own admin/audit API."),
        "regions": {},
    }

    org, oerr = _call(session.client("organizations", config=BOTO_CONFIG).describe_organization)
    if not oerr and org:
        report["organization"] = {
            "id": org["Organization"].get("Id"),
            "management_account": org["Organization"].get("MasterAccountId"),
            "note": "Multi-account org: this report covers ONE account. Run per account.",
        }

    for region in regions:
        logger.info("auditing %s", region)
        logging_cfg = check_invocation_logging(session, region)
        usage = check_usage(session, region, days)
        if (logging_cfg.get("enabled") is None
                and logging_cfg.get("error") == "region_unavailable"):
            continue
        report["regions"][region] = {
            "invocation_logging": logging_cfg,
            "cloudtrail": check_cloudtrail_bedrock(session, region),
            "usage": usage,
            "guardrails": check_guardrails(session, region),
            "models": check_models(session, region),
        }

    if want_cost:
        report["cost"] = check_cost(session, days)
    if want_iam:
        report["iam"] = check_iam_invokers(session)

    report["findings"] = derive_findings(report)
    return report


def derive_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn configuration + usage into statements a reader can act on."""
    out: list[dict[str, Any]] = []

    for region, data in report["regions"].items():
        log = data["invocation_logging"]
        ct = data["cloudtrail"]
        use = data["usage"]
        invocations = use.get("invocations") or 0
        tokens = (use.get("input_tokens") or 0) + (use.get("output_tokens") or 0)
        active = invocations > 0

        if active and log.get("enabled") is False:
            out.append({
                "severity": "critical", "region": region,
                "finding": "Model invocation logging is DISABLED while the region is in active use",
                "evidence": f"{invocations:,} invocations and {tokens:,} tokens in the last "
                            f"{use.get('window_days')} days, with no prompt or completion record",
                "impact": "No forensic reconstruction is possible. An AI incident here cannot "
                          "be investigated after the fact - the evidence was never written.",
                "remediation": "Enable Bedrock model invocation logging with text data "
                               "delivery to S3 (aws_bedrock_model_invocation_logging_configuration)",
            })
        elif active and log.get("enabled") and not log.get("captures_prompt_bodies"):
            out.append({
                "severity": "high", "region": region,
                "finding": "Invocation logging is enabled but text data delivery is OFF",
                "evidence": f"{invocations:,} invocations logged as metadata only",
                "impact": "Looks compliant on a dashboard while capturing no prompts or "
                          "completions. This is the worst of both worlds: cost without evidence.",
                "remediation": "Set textDataDeliveryEnabled = true",
            })

        if active and ct.get("bedrock_data_events") is False:
            out.append({
                "severity": "high", "region": region,
                "finding": "No CloudTrail trail captures Bedrock data events",
                "evidence": f"{len(ct.get('trails') or [])} trail(s) present, none with an "
                            "advanced event selector for AWS::Bedrock::Model",
                "impact": "Cannot establish WHICH principal invoked a model. A stolen "
                          "credential used against Bedrock leaves no attributable record.",
                "remediation": "Add an advanced event selector: eventCategory=Data, "
                               "resources.type=AWS::Bedrock::Model (billed per event)",
            })

        if active and (data["guardrails"].get("count") == 0):
            out.append({
                "severity": "medium", "region": region,
                "finding": "No Bedrock guardrails are defined in an actively used region",
                "evidence": f"{invocations:,} invocations, 0 guardrails",
                "impact": "No PII redaction, no prompt-attack filtering, and the "
                          "bedrock:GuardrailIdentifier IAM condition cannot be used because "
                          "there is no guardrail to require.",
                "remediation": "Create a baseline guardrail, then enforce it with an IAM "
                               "condition key and an SCP",
            })

    iam = report.get("iam") or {}
    if iam.get("principals_allowed_to_invoke"):
        nog = iam.get("without_guardrail_condition", 0)
        if nog:
            out.append({
                "severity": "high", "region": "global",
                "finding": f"{nog} of {iam['principals_allowed_to_invoke']} principals can "
                           "invoke a model without a mandatory-guardrail condition",
                "evidence": f"{iam.get('with_wildcard_model_resource', 0)} also allow a "
                            "wildcard model resource",
                "impact": "Any of these principals can call any model with no guardrail. "
                          "This is the single most preventable AI risk in AWS and it is open.",
                "remediation": 'Add Condition StringEquals "bedrock:GuardrailIdentifier" to '
                               "each policy, and deny unguarded invocation at the org level "
                               "with an SCP",
            })

    if not out:
        out.append({
            "severity": "info", "region": "all",
            "finding": "No telemetry gaps detected in the regions and checks that completed",
            "evidence": "Review access_denied entries before treating this as a clean result",
            "impact": "", "remediation": "",
        })
    return out


def render(report: dict[str, Any]) -> None:
    line = "=" * 78
    print(f"\nAWS AI TELEMETRY AUDIT  (read-only)\n{line}")
    print(f"account   : {report['account_id']}")
    print(f"audited as: {report['audited_as']}")
    print(f"generated : {report['generated']}   window: {report['window_days']} days")
    if "organization" in report:
        print(f"org       : {report['organization']['id']} "
              f"-- {report['organization']['note']}")
    print(f"\nscope     : {report['scope_note']}")

    print(f"\n{line}\nPER-REGION\n{line}")
    hdr = f"{'REGION':16} {'INVOCATIONS':>12} {'TOKENS':>14} {'PROMPT LOG':>11} {'CT DATA':>8} {'GRDRL':>6}"
    print(hdr)
    print("-" * 78)
    any_active = False
    for region, d in report["regions"].items():
        use, log, ct, gr = d["usage"], d["invocation_logging"], d["cloudtrail"], d["guardrails"]
        inv = use.get("invocations")
        tok = (use.get("input_tokens") or 0) + (use.get("output_tokens") or 0)
        if inv:
            any_active = True
        plog = ("YES" if log.get("captures_prompt_bodies")
                else "meta-only" if log.get("enabled")
                else "NO" if log.get("enabled") is False else "?")
        ctd = ("YES" if ct.get("bedrock_data_events")
               else "NO" if ct.get("bedrock_data_events") is False else "?")
        grc = gr.get("count")
        print(f"{region:16} {(f'{inv:,}' if inv is not None else '?'):>12} "
              f"{(f'{tok:,}' if tok else '-'):>14} {plog:>11} {ctd:>8} "
              f"{(str(grc) if grc is not None else '?'):>6}")

    if not any_active:
        print("\n  No Bedrock invocations recorded in any audited region for this window.")
        print("  Either Bedrock is genuinely unused, or usage is in a region not audited")
        print("  (try --all-regions), or cloudwatch:GetMetricStatistics was denied.")

    if "cost" in report:
        c = report["cost"]
        print(f"\n{line}\nBEDROCK SPEND\n{line}")
        if c.get("error"):
            print(f"  unavailable: {c['error']}\n  {c.get('hint','')}")
        else:
            print(f"  ${c['total']:,.2f} over {c['window_days']} days")
            for r, v in c["by_region"].items():
                print(f"    {r:20} ${v:,.2f}")
            print("  NOTE: Bedrock only. Anthropic/OpenAI/Cursor invoices are not in AWS.")

    if "iam" in report:
        i = report["iam"]
        print(f"\n{line}\nWHO CAN INVOKE A MODEL\n{line}")
        if i.get("error"):
            print(f"  unavailable: {i['error']}\n  {i.get('hint','')}")
        else:
            print(f"  {i['principals_allowed_to_invoke']} principal(s) permitted")
            print(f"  {i['without_guardrail_condition']} without a guardrail condition")
            print(f"  {i['with_wildcard_model_resource']} with a wildcard model resource")

    print(f"\n{line}\nFINDINGS\n{line}")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(report["findings"], key=lambda x: order.get(x["severity"], 9)):
        print(f"\n[{f['severity'].upper()}] {f['region']}  {f['finding']}")
        if f.get("evidence"):
            print(f"  evidence    : {f['evidence']}")
        if f.get("impact"):
            print(f"  impact      : {f['impact']}")
        if f.get("remediation"):
            print(f"  remediation : {f['remediation']}")

    denied = [
        f"{region}/{check}"
        for region, d in report["regions"].items()
        for check, val in d.items()
        if isinstance(val, dict) and val.get("error") == "access_denied"
    ]
    if denied:
        print(f"\n{line}")
        print(f"INCOMPLETE: {len(denied)} check(s) denied by IAM - this report is not a")
        print("clean bill of health. Re-run with SecurityAudit or ViewOnlyAccess:")
        for d in denied[:12]:
            print(f"  {d}")
    print()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Read-only audit of AWS AI (Bedrock) telemetry coverage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Makes only Get/List/Describe calls. See the module docstring for the "
               "exact API list to hand to a reviewer.",
    )
    ap.add_argument("--regions", nargs="+", metavar="REGION", default=None)
    ap.add_argument("--all-regions", action="store_true",
                    help="every region the SDK knows Bedrock in (slower)")
    ap.add_argument("--days", type=int, default=30, help="usage/cost window (default 30)")
    ap.add_argument("--cost", action="store_true", help="include Cost Explorer spend")
    ap.add_argument("--iam", action="store_true",
                    help="enumerate principals allowed to invoke a model")
    ap.add_argument("--assume-role", metavar="ARN", default=None)
    ap.add_argument("--external-id", metavar="ID", default=None)
    ap.add_argument("--json", metavar="FILE", default=None, help="also write the raw report")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)

    if args.all_regions:
        regions = sorted(boto3.Session().get_available_regions("bedrock")) or DEFAULT_REGIONS
    else:
        regions = args.regions or DEFAULT_REGIONS

    try:
        session = _session(args.assume_role, args.external_id)
        report = audit(session, regions, args.days, args.cost, args.iam)
    except AuditError as exc:
        logger.error("%s", exc)
        return 2

    render(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"raw report written to {args.json}\n")

    worst = min((f["severity"] for f in report["findings"]),
                key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 9))
    return 1 if worst in ("critical", "high") else 0


if __name__ == "__main__":
    sys.exit(main())
