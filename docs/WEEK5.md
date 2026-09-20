# Week 5 — cloud portability

## Delivered

- `iac/aws/` — 57 Terraform resources across 6 files: KMS, telemetry buckets with
  lifecycle and TLS-enforcing policies, Bedrock invocation logging, CloudTrail with
  **Bedrock data event selectors**, a Bedrock guardrail, a least-privilege invoke policy
  carrying the **mandatory-guardrail condition key**, a generated SCP, Athena + Glue with
  partition projection, an EventBridge → Lambda → SNS alert path, S3 access logging, and
  CloudTrail → CloudWatch Logs for near-real-time delivery.
- `mappings/AWS_CONTROLS.md` — every detection mapped to its detective and preventive
  AWS control, **including where AWS has no answer**.
- `mappings/AZURE_CONTROLS.md` — Azure parity, with the licence gating stated plainly.
- Console **Reference** view, so the mappings, ATLAS matrix, results and metrics notes are
  readable from the UI rather than only on disk.

## Verification, stated precisely

```
terraform validate    Success
terraform plan         57 to add, 0 to change, 0 to destroy
terraform fmt -check   clean
checkov                146 passed, 0 failed, 12 skipped (each with a written reason)
```

`terraform apply` has **never been run**. Zero-spend constraint. This is reviewed design,
not proven infrastructure, and the `iac/aws/README.md` says so in its first section.

### The plan-without-credentials problem

The plan document assumed `terraform plan` would run offline. It does not: the AWS provider
calls `sts:GetCallerIdentity` at plan time regardless of whether any data source needs it,
so the first plan attempt failed with `InvalidClientTokenId`.

Rather than hide that, offline verification is now an explicit opt-in — `-var
offline_plan=true` sets `skip_credentials_validation`, `skip_requesting_account_id` and
`skip_metadata_api_check`. It defaults to **false**, so a real apply cannot silently inherit
it. Pretending the plan was credential-verified would have been the easy lie.

## The control that closes a residual risk

Four of the lab's attacks succeed against a fully hardened baseline. Exactly one of them is
answered by the cloud layer, and completely:

```hcl
Condition = {
  StringEquals = {
    "bedrock:GuardrailIdentifier" = aws_bedrock_guardrail.baseline.guardrail_id
  }
}
```

Plus an SCP `Null` deny. Together these make an unguarded model invocation impossible for
any principal in the organisation — closing **A10**, which the lab could only detect. It is
the single highest-value control in the whole mapping and it is one condition key.

## Guardrail honesty, and why it matters

`PROMPT_ATTACK` with `input_strength = HIGH` is genuinely effective against direct
injection and genuinely does **not** cover content arriving through retrieval. So A01
(indirect injection) survives guardrails entirely.

Azure is better here: Content Safety **Prompt Shields** includes an indirect-attack
(document) shield, which is the one place Azure's AI security genuinely beats Bedrock's for
this attack class. That is recorded in the Azure mapping rather than glossed over, because
a deployment that enables guardrails and considers prompt injection solved has bought
partial coverage at full confidence — worse than knowing the gap.

## Checkov: 19 failures down to 0

Fixed, because they were real: S3 access logging on all three telemetry buckets (reading
invocation logs means reading every prompt — that should itself be audited), CloudTrail →
CloudWatch Logs, CloudTrail SNS notification, bucket versioning and lifecycle gaps, Lambda
DLQ, reserved concurrency, and X-Ray tracing.

Suppressed with written reasons, because they were not:

- **Cross-region replication (×4)** — replicating prompt bodies to a second region doubles
  both the storage bill and the blast radius of the most sensitive objects in the account.
- **S3 event notifications (×4)** — detection reads these buckets via Athena on a schedule;
  an unused notification path is not a control.
- **Lambda in a VPC** — the function reaches only SNS and CloudWatch Logs. A VPC adds NAT
  cost and a new failure mode in the alerting path.
- **Lambda code signing** — needs a Signer profile and a publishing pipeline; worth adding
  when this deploys from CI.
- **KMS on the access-log bucket** — S3 server access logging cannot deliver to an SSE-KMS
  bucket. An AWS platform constraint, not a choice.

Every suppression is an inline `checkov:skip` with the reason next to the resource, so a
reviewer sees the argument at the point of the decision.

## The Lambda does not contain

`iac/aws/lambda/handler.py` publishes an enriched alert with a *proposed* containment
action and explicitly does not act. The reason is in the module docstring: a containment
action inherits the false positives of the detection that triggered it, and this project
already had a runbook quarantine two legitimate documents in Week 3. Promoting an action to
automatic is a per-action decision with a documented blast radius, not a default.

## Carried into Week 6

- Measured results, CV bullets, tabletop exercise, final README.
