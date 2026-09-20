# Week 6 — making it legible

## Delivered

- `docs/RESULTS.md` — every measured figure, with an explicit "what is not measured"
  section covering MTTR, detection rate, false-positive rate and UI behaviour.
- `docs/TABLETOP-multi-tenant-leak.md` — a 90-minute, five-inject exercise whose evidence
  is *generated* by the lab rather than invented. The hard inject is legal asking "which
  customers' data was accessed, and by whom?" — which the telemetry structurally cannot
  answer, because the agent holds one identity. That is the finding.
- Console **Reference** view over all seven reference documents.
- Final README with the results table and CV bullets.

## A defect found while writing this up

Generating the results table surfaced a real bug: R001's `prompt_size_distribution`
evidence query used `width_bucket()`, which **is not a DuckDB function**. The pack had been
failing silently on every run — visible only because the engine records collect failures as
incident problems rather than swallowing them.

Rewritten as integer-division buckets, and the output immediately justified the query's
existence: **12 invocations clustered at 6,959–6,960 characters** against an 8,000-character
ceiling. That is A08's signature — a flood shaped to sit just under the limit, which is
precisely the pattern the runbook's triage guidance tells a responder to look for. A
distribution that tight does not happen by accident.

The lesson is the same one from Week 2's D011 bug: the engine's habit of recording its own
failures is what made both findable.

## CV bullets

Drafted from `docs/RESULTS.md`. Every number is reproducible with one command, which is the
only reason any of them belong on a CV.

- Built and open-sourced **AIRCAP**, a reproducible AI incident response capability: 10
  attacks against an LLM agent, 14 detections (DuckDB SQL, Sigma, Wazuh), and 9 executable
  runbooks that auto-collect prompt-chain evidence — **188 evidence rows across 9 incidents
  in 0.33 s**, with containment verified by re-running each attack and confirming it fails.
- Engineered AI-workload detection against **Bedrock-schema invocation logs and CloudTrail
  data events** — prompt injection, guardrail bypass, confused-deputy tool abuse,
  model-driven SSRF to instance metadata, token-flood DoS and unauthorized model invocation
  — with documented mappings to GuardDuty/Security Hub and Microsoft Sentinel/Defender.
- Delivered **shadow-AI discovery for managed endpoints** using osquery, Wazuh and DNS/SNI
  egress classification across 5 lenses and 43 provider destinations, producing a
  risk-scored AI asset register; risk scoring inverts for local runtimes, which keep prompts
  on-device but are invisible to network-only DLP.
- Authored **57 Terraform resources** for the AWS telemetry plane and preventive controls
  (`terraform validate` clean, **checkov 146 passed / 0 failed**), closing the unauthorized-
  invocation risk outright with a `bedrock:GuardrailIdentifier` IAM condition key and an SCP
  backstop.
- Mapped the capability to **NIST SP 800-61r3 (CSF 2.0)**, **MITRE ATLAS v5.4** (8
  techniques, validated against the official STIX 2.1 bundle) and **OWASP GenAI Top 10
  (2026)**, and published the **4 attacks that defeat a fully hardened baseline** as
  documented residual risk rather than asserting them away.

### How to use these in an interview

The last bullet is the strongest and the most likely to be probed. The honest answer to
"why didn't you fix them?" is that three of the four have no AWS-native control either —
`mappings/AWS_CONTROLS.md` documents which, and Azure's Prompt Shields is the one place a
cloud provider does better. Knowing that is the point of the project.

Do not quote MTTR. `engine/METRICS.md` explains why it is absent, and being able to explain
why a number is *missing* reads considerably better than quoting one you cannot defend.

## Honest limitations, consolidated

| Limitation | Why it stands |
|---|---|
| Telemetry contents are locally generated | Bedrock has no free tier. Schemas are faithful; contents are not real captures, and every output says so. |
| `terraform apply` never run | Zero-spend constraint. Plan- and policy-verified only. |
| MTTR not claimed | Human response was never measured. |
| No false-positive rate | No benign baseline traffic exists to measure against. D011 and D012 thresholds are lab values. |
| UI verified headlessly | No browser extension was available; visual layout and click-through are unverified. |
| osquery pack not executed | osquery is not installed on the build host; the pack is schema-validated only. |
| Cloud log parsing uses synthetic samples | Formats are faithful, contents fabricated, labelled as such in the output and the UI. |
