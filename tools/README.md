# tools/

Standalone utilities. Unlike the rest of this repo these are meant to run against
**real** environments, so they are read-only by construction and dependency-light.

## `aws_ai_telemetry_audit.py`

Answers one question: **if an AI incident happened in this AWS account, could you
investigate it?**

Bedrock model invocation logging and CloudTrail data events for Bedrock are both **off
by default**. Invocation logging is the only record of prompt and completion bodies;
CloudTrail data events are the only record of *which principal* called the model, and
they bill per event so they are commonly left disabled. An account can therefore run
millions of tokens with no forensic record whatsoever.

This script pairs **usage evidence** (CloudWatch `AWS/Bedrock` metrics, which are always
on and cannot be turned off) against **logging configuration**, so the output is not
"logging is off" but:

> *N invocations and M tokens in the last 30 days, with no prompt or completion record.*

That framing is the finding. The gap is only interesting once it is quantified.

### Safety

Read-only by construction. The complete set of AWS API calls it can make:

```
sts:GetCallerIdentity                           cloudtrail:DescribeTrails
organizations:DescribeOrganization  (optional)  cloudtrail:GetTrailStatus
bedrock:GetModelInvocationLoggingConfiguration  cloudtrail:GetEventSelectors
bedrock:ListGuardrails                          cloudwatch:GetMetricStatistics
bedrock:ListFoundationModels                    ce:GetCostAndUsage      (--cost)
                                                iam:GetAccountAuthorizationDetails (--iam)
```

No Create/Put/Update/Delete/Start/Stop call appears in the file — verify with:

```bash
grep -nE '\.(create_|put_|update_|delete_|start_|stop_|attach_|detach_|modify_)' \
  tools/aws_ai_telemetry_audit.py
```

It reads configuration, aggregate metrics and cost totals only. It **never** reads a log
body, and contains no reference to `inputBodyJson` or `outputBodyJson`, so it cannot emit
prompt or completion text even by accident. `SecurityAudit` or `ViewOnlyAccess` is
sufficient; denied checks are reported as denied rather than silently skipped, and the
report says plainly that a run with denials is not a clean bill of health.

### Usage

```bash
pip install boto3

python3 tools/aws_ai_telemetry_audit.py                        # common regions
python3 tools/aws_ai_telemetry_audit.py --all-regions --cost --iam
python3 tools/aws_ai_telemetry_audit.py --json report.json
python3 tools/aws_ai_telemetry_audit.py --assume-role arn:aws:iam::111122223333:role/AuditRole
```

Exit code 1 if any critical or high finding, 0 otherwise, 2 if it could not start.

### What it does NOT cover

**Bedrock only.** Spend and usage on Anthropic, OpenAI, Cursor or GitHub Copilot via
vendor APIs is invisible to AWS and needs each vendor's own admin or audit API. Do not
present this report as total AI exposure — the script says so in its own output.

**One account per run.** It flags when it detects an AWS Organization but audits only the
credentials it was given. Use `--assume-role` per account for org-wide coverage.

### Findings it derives

| Severity | Condition |
|---|---|
| critical | region is actively used AND invocation logging is disabled |
| high | logging enabled but `textDataDeliveryEnabled` is false — looks compliant, captures no prompts |
| high | no trail has an advanced event selector for `AWS::Bedrock::Model` |
| high | principals can invoke a model with no `bedrock:GuardrailIdentifier` condition |
| medium | actively used region with zero guardrails defined |
