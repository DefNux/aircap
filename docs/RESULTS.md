# Measured results

Every figure here was produced by running the code in this repository. Reproduce with
`make clean-data && make attack && make detect && make ir-triage`.

**Read [`engine/METRICS.md`](../engine/METRICS.md) before quoting any timing number.**
The short version: time-to-detectable, triage duration, containment duration and evidence
volume are *measured*; MTTD is *modelled*; MTTR is *not claimed*.

## Coverage

| | Count |
|---|---|
| Attacks, reproducible | 10 |
| Detections (DuckDB SQL, authoritative) | 14 |
| Sigma rule ports | 14 |
| Wazuh rules (detection + discovery) | 23 |
| Executable runbooks | 9 |
| Detections covered by a runbook | 14 / 14 |
| ATLAS techniques exercised, validated against the STIX bundle | 8 |
| Shadow-AI discovery lenses | 5 |
| Terraform resources, plan-verified | 57 |
| Console API endpoints | 21 |

## Attack and detection outcomes

```
Vulnerable posture     10/10 attacks succeeded
Detections             14/14 fired
Expectation gaps        0      (every predicted detection fired)
Hardened baseline       5/10 attacks still succeed   <- the finding
```

## Residual risk: attacks that succeed with every control enabled

| Attack | Why not prevented | Coverage |
|---|---|---|
| A02 RAG corpus poisoning | provenance markers stop the model *obeying* retrieved instructions, not *answering from* attacker facts. No corpus-integrity control exists. | detect-only (D011) |
| A03 Tool-definition poisoning | tool descriptions render into the trusted system prompt; nothing inspects the catalogue | detect-only (D005, region-aware) |
| A04 Confused deputy | one application identity, no per-user authorization between agent and tools | detect-only (D013) |
| A08 Token-flood DoS | per-prompt size ceiling exists; per-principal rate budget does not | detect-only (D012) |
| A10 Unauthorized principal | prevention is IAM, absent from the lab by design | **answered in AWS** via `bedrock:GuardrailIdentifier` + SCP |

A10 is the only one the cloud layer closes outright. The other four remain open, and
[`mappings/AWS_CONTROLS.md`](../mappings/AWS_CONTROLS.md) documents that three of them have
no AWS-native answer either.

## Incident response, measured

Nine runbooks fired against one attack run:

| Runbook | Time to detectable | Triage | Evidence rows | Containment |
|---|---|---|---|---|
| R001 unbounded consumption | 6.36 s | 0.024 s | 3 | none available (by design) |
| R004 unauthorized invocation | 21.04 s | 0.042 s | 9 | 0.008 s |
| R005 prompt injection | 20.69 s | 0.048 s | 85 | 0.009 s |
| R007 data exfiltration | 13.43 s | 0.047 s | 10 | 0.011 s |
| R008 agent SSRF | 10.71 s | 0.040 s | 4 | 0.011 s |
| R009 excessive agency | 2.32 s | 0.040 s | 12 | 0.013 s |
| R010 confirmed disclosure | 0.00 s | 0.019 s | 3 | 0.010 s |
| R011 RAG poisoning | 20.14 s | 0.032 s | 58 | 0.008 s |
| R013 restricted record access | 0.00 s | 0.034 s | 4 | 0.001 s |

**Totals:** 9 incidents, **188 evidence rows collected in 0.33 s**, mean time-to-detectable
**10.5 s** (median 10.7 s, max 21.0 s).

Two runbooks show `0.00 s` time-to-detectable. That is **not** instant detection — it means
the detection was satisfiable by the very first event, so there was no accumulation window
to measure. The engine annotates the timeline automatically rather than letting the number
speak for itself.

## Containment, verified

`make ir-demo` runs the loop end to end:

```
5 attacks run                        -> 5/5 SUCCEEDED
detections                           -> 9/14 fired
runbooks execute, containment applied -> 8 actions in effect
quarantine directory                 -> 5 documents removed from retrieval
THE SAME 5 ATTACKS RE-RUN            -> 5/5 blocked
```

Containment is real state the running application honours, and it deliberately outranks the
vulnerability toggles: an incident-response decision must not be undone by whatever posture
the app happens to be running in. `make ir-lift` reverses it.

## Infrastructure verification

```
terraform validate    Success
terraform plan         57 to add, 0 to change, 0 to destroy
terraform fmt -check   clean
checkov                146 passed, 0 failed, 12 skipped (each with a written reason)
```

`terraform apply` has **never been run** — zero-spend constraint. This is reviewed design,
not proven infrastructure.

## What is not measured

- **MTTR.** Human triage, decision-making and recovery were never observed. Reporting
  automated containment as MTTR would understate real response by orders of magnitude.
- **Detection rate as a percentage.** 14 detections firing on 10 attacks written alongside
  them is a closed loop, not a hit rate. A real figure needs attacks the detections were not
  designed against.
- **False-positive rate.** There is no benign baseline traffic to measure against. D011's
  threshold and D012's 10-invocations-per-5-minutes are lab values that would need tuning
  against observed traffic before either could be called a production detection.
- **UI behaviour in a browser.** Render paths are exercised headlessly; visual layout and
  click-through are unverified.
