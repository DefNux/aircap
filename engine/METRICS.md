# What these metrics do and do not mean

Read this before quoting any number from this repo. Response-time figures are the easiest
thing in security to overstate, and an interviewer who knows the subject will ask exactly
how they were derived.

## Measured

| Metric | Derivation | Trustworthy for |
|---|---|---|
| `measured_time_to_detectable_s` | Last timestamp the detection needed, minus the first event in the affected sessions. Read from the telemetry itself, not the clock. | How long an attack accumulates evidence before it *can* be caught. Real and defensible. |
| `measured_triage_duration_s` | Wall-clock to execute every evidence query in the runbook. | How long automated evidence collection takes. Real. |
| `measured_containment_duration_s` | Wall-clock from the start of containment to the last action applied. | How long automated containment takes. Real. |
| `measured_evidence_rows` | Row count across all evidence packs. | Volume of evidence gathered without human effort. Real. |

## Modelled — not measured

`modelled_mttd_s` = `measured_time_to_detectable_s` + an **assumed 60-second detection
poll interval**.

The assumption exists because detection here is a batch SQL query run on demand. The
moment a query happens to be run is an artefact of when someone typed a command; it says
nothing about when an alert would have reached a responder. Rather than report the
meaningless difference, the engine adds a stated pipeline latency and labels the result
modelled. Substitute your own alerting latency before using it for anything.

## Deliberately not claimed

**MTTR is not reported.** Mean time to *resolve* includes human triage, decision-making,
escalation and recovery. This lab measures automated containment only, which is one step
inside MTTR. Reporting `containment_duration` as MTTR would understate real response time
by orders of magnitude, so the field does not exist.

**Detection rate is not reported as a percentage.** 14 detections firing on 10 attacks
that were written alongside them is not a hit rate — it is a closed loop. A meaningful
figure needs attacks the detections were not designed against.

**`time_to_detectable = 0s` is common and is not a triumph.** It means the detection was
satisfiable by the very first event, so there was no accumulation window. The engine adds
that note to the timeline automatically rather than letting 0.000s read as instant
detection.

## The honest summary line

> Automated triage collects N evidence packs in under a second and applies containment in
> under a second; containment is verified by re-running the attack, which then fails.
> Time-to-detectable is measured from telemetry. MTTD is modelled on a stated 60s poll
> interval. MTTR is not claimed, because human response time was not measured.
