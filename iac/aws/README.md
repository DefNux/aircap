# AIRCAP AWS infrastructure

Terraform for the production telemetry plane and the preventive controls that answer the
residual risks the lab can only detect.

## Status: plan-verified, not apply-verified

**No AWS account was used.** Under this project's zero-spend constraint the verification
that was actually performed is:

```
terraform validate    Success
terraform plan         57 to add, 0 to change, 0 to destroy
terraform fmt -check   clean
checkov                146 passed, 0 failed, 12 skipped (each with a written reason)
```

`terraform apply` has **never been run**. Anything below could still fail on first apply
for reasons a plan cannot see — service quotas, Bedrock model access not being requested
in the account, guardrail content-policy validation, or region availability. Treat this as
reviewed design, not proven infrastructure.

### Why `offline_plan` exists

The AWS provider calls `sts:GetCallerIdentity` at plan time, so a plan normally needs live
credentials. `-var offline_plan=true` sets `skip_credentials_validation`,
`skip_requesting_account_id` and `skip_metadata_api_check` so verification runs at zero
cost. It defaults to **false** — never apply with it on.

```bash
cd iac/aws
terraform init
terraform validate
AWS_ACCESS_KEY_ID=offline AWS_SECRET_ACCESS_KEY=offline AWS_REGION=us-east-1 \
  terraform plan -var account_id=123456789012 -var offline_plan=true
```

## What it builds

| File | Contents |
|---|---|
| `telemetry.tf` | KMS key, invocation-log and CloudTrail buckets, Bedrock invocation logging, CloudTrail with Bedrock **data** event selectors |
| `controls.tf` | Bedrock guardrail (prompt-attack, PII, denied topics), least-privilege invoke policy with a **mandatory-guardrail condition key**, generated SCP |
| `analytics.tf` | Athena workgroup with a scan ceiling, Glue database and table with partition projection |
| `response.tf` | EventBridge → Lambda → SNS alert path, cost and guardrail-intervention alarms |
| `audit.tf` | S3 access logging, CloudTrail → CloudWatch Logs, Lambda DLQ and concurrency cap |

## The control that matters most

```hcl
Condition = {
  StringEquals = {
    "bedrock:GuardrailIdentifier" = aws_bedrock_guardrail.baseline.guardrail_id
  }
}
```

Plus the SCP `Null` deny in `generated/scp-mandatory-guardrail.json`. Together these make
an unguarded model invocation impossible for any principal in the organisation — closing
residual risk **A10**, which the lab could only detect. Terraform does not attach the SCP;
that is an organisation-level action to take deliberately.

## Cost warning

This is **not** free-tier infrastructure. CloudTrail data events bill per event, Bedrock
invocation logging bills for storage, Athena bills $5/TB scanned, and KMS bills per key
and per request. The Athena workgroup carries a 10 GB per-query scan ceiling for exactly
this reason. Estimate before applying.

## Security posture

Every bucket: public access blocked, KMS-encrypted (except the access-log target, which
AWS requires to be SSE-S3), versioned, lifecycle-expired, and TLS-enforced by policy.
Prompt bodies expire at 180 days by default — long enough to investigate, short enough to
limit exposure of the most sensitive objects in the account.

The Lambda **does not contain automatically**. See `lambda/handler.py`: a containment
action inherits the false positives of the detection that triggered it, and this project
has already had a runbook quarantine two legitimate documents. It publishes an enriched
alert with a proposed action instead.
