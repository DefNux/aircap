# Detection → Azure control mapping

The Azure parity chapter. Azure's AI security story is more product-complete than AWS's
but far more **licence-gated**, which changes the advice: on AWS the question is "have
you turned the telemetry on"; on Azure it is "do you have the SKU".

No Azure resources were deployed. This is a mapping document, not an implementation —
the implementation target under a zero-spend constraint was AWS.

## Telemetry prerequisites

| Source | Carries | Where | Licence |
|---|---|---|---|
| Azure OpenAI / AI Foundry diagnostic logs | request metadata, token counts | Diagnostic settings → Log Analytics | Included |
| Azure OpenAI **prompt/completion capture** | prompts + completions | Not on by default; abuse-monitoring storage is Microsoft-side | Requires explicit enablement; in many tenants the data is not customer-accessible at all |
| Microsoft Defender for Cloud — AI workload protection | prompt-injection and anomaly alerts | Defender plan | Defender for Cloud AI plan (paid) |
| Microsoft Purview DSPM for AI | prompt/response content, sensitivity labels | Purview | E5 / Purview add-on |
| Entra Internet Access — Shadow AI detection | AI destinations per user | Global Secure Access | Entra Suite / Internet Access (GA 31 Mar 2026) |
| Agent 365 | local AI agent discovery + runtime blocking on managed endpoints | Agent 365 (GA 1 May 2026) | Separate SKU |

**The material difference from AWS:** on AWS you can get full prompt bodies into your own
S3 bucket for the price of storage. On Azure, customer-accessible prompt capture for Azure
OpenAI is more constrained, and the richest content signal (Purview DSPM for AI) is an E5-
class entitlement. A detection library that assumes prompt access will not port cleanly
into a tenant without those licences.

## Mapping

| Detection | Azure detective control | Azure preventive control |
|---|---|---|
| **D001** oversized prompt | Log Analytics KQL over gateway logs | APIM policy: request size limit + token quota |
| **D002** credential in prompt | Purview DSPM for AI; Defender for Cloud AI alerts | Azure AI Content Safety custom blocklists; Purview DLP policy on AI apps |
| **D003** no guardrail attached | Azure Policy compliance state | **Azure Policy deny** on Azure OpenAI deployments without a content filter; APIM as mandatory front door |
| **D004** unauthorized principal | Entra ID sign-in logs + `AzureDiagnostics` for the AI resource; Defender for Cloud alerts | **Disable API keys entirely**, Entra-only auth, Conditional Access, RBAC scoped to `Cognitive Services OpenAI User` |
| **D005** planted tool directive | Defender for Cloud AI **prompt-injection alerts**; Sentinel analytics rule | Azure AI Content Safety **Prompt Shields** — includes an indirect-attack (document) shield, which is the one thing Azure does better than Bedrock guardrails here |
| **D006** tool call denied | App traces → Application Insights | Tool allowlist in the app / AI Foundry agent config |
| **D007** path traversal | App traces | Sandboxed tool implementation |
| **D008** egress to metadata/private space | NSG flow logs; Defender for Cloud | **IMDS requires the `Metadata: true` header** (no v1 equivalent to abuse); NSG egress deny; Private Endpoints only |
| **D009** excessive tool depth | Application Insights traces | AI Foundry agent step limits |
| **D010** credential in response | Purview DSPM for AI | Content Safety output filtering; Purview DLP |
| **D011** retrieval ranking anomaly | Custom KQL over AI Search query logs | **Prompt Shields indirect-attack detection** partially covers this — closer to a real control than anything on AWS, though it detects injected *instructions*, not attacker-supplied *facts* |
| **D012** sustained volume | Azure Monitor metrics; Cost Management anomaly alerts | APIM **token-based rate limiting per subscription key** — genuinely per-principal, unlike Bedrock's account-level quotas |
| **D013** restricted record access | App traces | On-behalf-of token flow so the agent acts as the user, not as itself |
| **D014** sensitive file read via tool | App traces; Purview | Scoped managed identity; Private Endpoints |

## Where Azure is genuinely stronger

- **Prompt Shields has an indirect-attack (document) shield.** Bedrock's `PROMPT_ATTACK`
  filter covers user input only. This is the single most meaningful difference for the
  attack class this project is built around.
- **APIM token rate limiting is per-subscription-key**, so a noisy tenant can be capped
  without starving the others. Bedrock quotas are account-level.
- **On-behalf-of flow** gives a real answer to the confused-deputy problem (D013/A04),
  which AWS leaves entirely to the application.
- **Shadow AI discovery is a product**, not a project — Entra Internet Access plus Agent
  365 cover the network and endpoint lenses `discover/scan.py` had to build by hand.

## Where Azure is weaker

- **Customer access to prompt bodies is more restricted.** The AWS path — invocation
  logging straight into your own bucket, queryable with Athena — has no clean equivalent.
- **Everything good is licence-gated.** Prompt Shields, Defender for Cloud AI, Purview
  DSPM for AI, Entra Internet Access and Agent 365 are four or five separate
  entitlements. A tenant on E3 gets almost none of it.
- **`discover/scan.py` exists because of that gating.** Its four lenses reimplement, on
  open-source primitives and with no licence, roughly what Entra Internet Access and Agent
  365 do — which is the honest reason to build it rather than buy it in a lab.

## Porting the detections

The SQL in `detections/sql/` maps to KQL structurally. The only real work is the source
table and the prompt-access question:

```kql
// D004 equivalent: model invoked by an unexpected principal
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where OperationName in ("ChatCompletions_Create", "Completions_Create")
| extend principal = tostring(parse_json(properties_s).callerIdentity)
| where principal !has "aircap-app-identity"
| project TimeGenerated, principal, CallerIPAddress, OperationName, ResourceId
```

The Sigma rules in `detections/sigma/` convert to Sentinel analytics rules with
`sigma convert -t kusto`, which is the cheapest route to parity.
