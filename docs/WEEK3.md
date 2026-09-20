# Week 3 — the IR engine

## Delivered

- **9 executable runbooks** (`runbooks/`) covering all 14 detections, each with triage
  guidance, 3–4 evidence queries, containment actions with SQL-resolved targets, and a
  recovery procedure. Mapped to NIST SP 800-61r3 / CSF 2.0 functions, ATLAS and OWASP GenAI.
- **Containment that actually bites** (`lab/app/containment.py`): quarantined documents are
  skipped by the retriever, disabled tools are refused, blocked hosts are refused, revoked
  principals are rejected by the API, and enforced redaction overrides the config toggle.
  Atomic writes, idempotent, fully reversible, with an audit log.
- **IR engine** (`engine/ir.py`): opens an incident per fired runbook and writes
  `evidence/*.json`, `metrics.json`, `containment.json`, `timeline.md`, `postmortem.md`.
  Triage mode is a dry run; respond mode acts.
- **ATLAS coverage generated from the STIX 2.1 bundle** (`mappings/atlas_coverage.py`) —
  8 techniques claimed, all 8 validated against the published bundle, 0 invalid ids.
- **`make ir-demo`** — the end-to-end proof loop.

## The proof loop

```
make ir-demo
  STEP 1  5 attacks run                       -> 5/5 SUCCEEDED
  STEP 2  detections                          -> 9/14 fired
  STEP 3  runbooks execute, containment applied -> 8 actions in effect
  STEP 4  quarantine directory                -> 5 documents moved out of retrieval
  STEP 5  THE SAME 5 ATTACKS RE-RUN           -> 5/5 blocked/failed
  STEP 6  incident artifacts                  -> 10 markdown reports + evidence packs
```

Step 5 is the whole point. Containment that cannot be re-tested is a claim, not a control.
After containment A02 returns the genuine expense policy ("Travel over 500 USD requires
manager pre-approval") instead of the attacker's rewrite.

## Two defects found, one of them serious

**1. A containment action took down legitimate documents.** Running R011 in respond mode
quarantined `onboarding.md` and `expenses.md` — real corpus documents. Root cause was a
SQL bug: `regexp_extract(chunk_id, '^([a-z0-9-]+)#')` in the two-argument form returns the
whole match *including the `#`*, so `'onboarding#' NOT IN ('onboarding', …)` was always
true. D011 had been firing on every document since Week 2, and the Week 2 notes
rationalised the inflated hit count as a design property rather than investigating it.

Fixed two ways, because the bug and the blast radius are separate problems:

- the capture-group index, so D011 now fires 7 times instead of 20, only on planted docs;
- a `PROTECTED_DOCUMENTS` floor in the engine that **refuses** to quarantine a baseline
  document even when a detection selects it, recording the refusal as an incident problem.

The general lesson is worth more than the fix: *a containment action inherits the false
positives of the detection that triggered it, and a false-positive containment action is a
self-inflicted outage.* Automated response needs a blast-radius floor that does not depend
on the detection being right.

**2. Quarantine silently no-opped.** The attack harness cleaned up its planted documents
before IR could act on them, so every quarantine reported "not present in corpus". The
engine recorded each as a problem rather than reporting success — which is how the issue
was noticed at all. Added `--keep-artifacts` to the runner so the IR path has something
real to act on.

## Metrics: what is claimed and what is not

Full detail in [`engine/METRICS.md`](../engine/METRICS.md). Summary:

- **Measured**: time-to-detectable (from telemetry, not the clock), triage duration,
  containment duration, evidence row counts.
- **Modelled**: MTTD = time-to-detectable + a stated 60s poll interval. Labelled modelled
  everywhere it appears, because a batch query cannot observe when an alert reaches a human.
- **Not claimed**: MTTR (human response was never measured, so reporting automated
  containment as MTTR would understate real response by orders of magnitude), and detection
  rate as a percentage (14 detections firing on 10 attacks written alongside them is a
  closed loop, not a hit rate).

`time_to_detectable = 0s` appears for several runbooks and is *not* a good result — it
means the detection was satisfiable by the first event, so there was no accumulation
window. The engine annotates the timeline automatically rather than letting `0.000s` read
as instant detection.

## Runbook design notes

**R001 has no containment action, deliberately.** There is nothing to switch off that stops
a sub-ceiling token flood, because no per-principal rate budget exists. The runbook says so
and the postmortem prints "**No containment action exists for this runbook.** That is a
finding, not an omission." A runbook that invents a containment step it cannot perform is
worse than one that admits the gap.

**R004's recovery section states its own limitation.** Revoking a principal in this lab only
blocks the application's entry point; there is no IAM plane to revoke against. The real
control is an IAM condition key plus an SCP, which Week 5 delivers as Terraform.

**R013 tells the responder not to attempt attribution.** The telemetry structurally cannot
identify who asked — the agent holds one identity — so the runbook directs effort at
recording the gap instead of mining logs that cannot contain the answer.

## Carried into Week 4

- Shadow-AI endpoint discovery: osquery packs, Wazuh rules, DNS/SNI egress classification,
  AI asset register with risk scoring.
- Re-use `sni-monitor.sh` from `/mnt/HDD/Tools` for the capture path rather than rewriting.
