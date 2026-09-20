# Detection → AWS control mapping

How each AIRCAP detection becomes a production control on AWS, and — more usefully —
where AWS has no answer and the gap has to be owned.

The Terraform in [`iac/aws/`](../iac/aws) implements the preventive column. It is
**plan-verified, not apply-verified**: 57 resources, `terraform validate` clean,
checkov 146 passed / 0 failed / 12 suppressed with written reasons. No AWS account was
used, per the project's zero-spend constraint.

## Telemetry prerequisites

Nothing below works without these two, and neither is on by default:

| Source | Carries | Terraform | Why it matters |
|---|---|---|---|
| Bedrock model invocation logging | prompts + completions | `aws_bedrock_model_invocation_logging_configuration` | The **only** source of what a model was asked to do. Without it, prompt-level detection is impossible. |
| CloudTrail data events, `AWS::Bedrock::Model` | who called, from where | `aws_cloudtrail.advanced_event_selector` | Proves the invocation happened. Billed per event, which is why most accounts don't have it. |

The asymmetry is the first thing to internalise: **CloudTrail never contains a prompt.**
An account with CloudTrail but no invocation logging can tell you a model was called
10,000 times and nothing about what was said.

## Mapping

| Detection | Detective control | Preventive control | Gap |
|---|---|---|---|
| **D001** oversized prompt | CloudWatch metric filter on the app's rejection log | Per-request size ceiling in the app | AWS has no request-size quota for Bedrock. App-side only. |
| **D002** credential material in prompt | Athena over invocation logs; Macie on the log bucket | Guardrail `sensitive_information_policy_config` — `AWS_ACCESS_KEY`, `AWS_SECRET_KEY`, `PASSWORD` set to BLOCK | Guardrail patterns are fixed; custom secret formats need `regexes_config`. |
| **D003** no guardrail attached | Athena: `guardrailId IS NULL` | **IAM condition `bedrock:GuardrailIdentifier`** + SCP `Null` deny | Fully preventable. This is the strongest control in the whole mapping. |
| **D004** unauthorized principal | CloudTrail → CloudWatch Logs metric filter → alarm; GuardDuty for the credential compromise itself | Least-privilege identity policy scoped to `allowed_model_ids`; SCP backstop | Fully preventable, but only if the role list is actually maintained. |
| **D005** planted tool directive | Athena over `input.inputBodyJson` | Guardrail `PROMPT_ATTACK` filter, `input_strength = HIGH` | **Partial, and this is the important caveat:** `PROMPT_ATTACK` applies to input tagged as user input. Content arriving through *retrieval* is not covered, so indirect injection (A01) survives it. |
| **D006** tool call denied | Application logs → CloudWatch Logs Insights | Tool allowlist + argument validation in the app | No AWS-native equivalent. Agent-layer concern. |
| **D007** path traversal in tool args | Application logs | Sandboxed tool implementation | App-side only. |
| **D008** egress to metadata/private space | VPC Flow Logs; Route 53 Resolver query logs; GuardDuty `UnauthorizedAccess:EC2/MetadataDNSRebind` | **IMDSv2 required + hop limit 1**; egress via proxy; no NAT route for the agent's subnet | Fully preventable and frequently left undone. |
| **D009** excessive tool depth | Agent traces → CloudWatch | Depth ceiling; Bedrock Agents action-group limits | App-side. AWS has no chain-depth quota. |
| **D010** credential in response | Athena over `output.outputBodyJson` | Guardrail output filters + PII BLOCK actions | Partial — a filter is a mitigation, not a fix for the read that produced the data. |
| **D011** retrieval ranking anomaly | Athena over agent traces | **Nothing in AWS.** Knowledge Base ingestion allowlisting and document signing are yours to build. | **This is the real gap.** Bedrock Knowledge Bases will happily ingest a poisoned document. |
| **D012** sustained invocation volume | CloudWatch `AWS/Bedrock` `Invocations` alarm; Cost Anomaly Detection | Provisioned-throughput caps; per-principal budget enforced in the app | AWS quotas are per-account, not per-principal. A noisy tenant still starves the others. |
| **D013** restricted record access | Application logs | **Nothing.** Per-user authorization between agent and tool must be built. | Structural: the agent holds one identity, so the audit trail cannot answer "who asked". |
| **D014** sensitive file read via tool | Application logs; Macie on the source bucket | Scoped IAM for the tool's own role; sandboxed paths | App-side, but the tool's role should never have had access in the first place. |

## Where AWS genuinely cannot help

Three of the four residual risks the lab documents stay residual on AWS:

- **A02 / D011 RAG poisoning** — no corpus-integrity primitive exists. Knowledge Bases
  ingest what you point them at.
- **A03 tool-definition poisoning** — tool descriptions render into the system prompt.
  Nothing validates a tool catalogue's integrity.
- **A04 / D013 confused deputy** — Bedrock Agents invoke action groups with the agent's
  identity, not the end user's. Per-user authorization is application work.

**A10 is the exception, and it is fully answered**: `bedrock:GuardrailIdentifier` as an
IAM condition key plus an SCP `Null` deny makes an unguarded invocation impossible for
any principal in the organisation. That single condition key closes the residual risk
the lab could only detect.

## Guardrail honesty

`PROMPT_ATTACK` is genuinely good at direct injection and genuinely does not cover
retrieved content. A deployment that enables guardrails and considers prompt injection
solved has bought partial coverage at full confidence — which is worse than knowing the
gap. Detection D005 reports *which region* carried the directive (`retrieved_context`
vs `system_prompt`) precisely because the response differs: quarantine a document, or
treat the tool catalogue as compromised.
