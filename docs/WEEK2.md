# Week 2 — attack pack and detection library

## Delivered

- **10 attacks** (`attacks/`), each a module with a `MANIFEST` and `run(ctx)`. `registry.yml`
  is generated from the manifests, so the coverage matrix cannot drift from the code.
- **14 detections** in three formats: `detections/sql/` (DuckDB, authoritative),
  `detections/sigma/` (14 rules, incl. a two-document correlation rule for D012),
  `detections/wazuh/` (16 rules across ids 100200–100215, plus `localfile` config).
- **Runners**: `attacks/runner.py` (with `--hardened` control test), `detections/run.py`
  (with `--matrix`). Both wired into `make verify` as one pipeline.
- **Posture refactor**: configuration resolves per-request through a `ContextVar`, so the
  whole suite runs in one process. Unknown override keys raise rather than silently pass —
  a typo in a manifest must not make an attack quietly run hardened.

## Results

```
10/10 attacks succeeded under their own posture
14/14 detections fired
0    expectation gaps (every attack's predicted detections fired)
5/10 attacks still succeed against the hardened baseline  <- the real finding
```

### The four residual risks

These succeed with **every control enabled**. There is no toggle for them because no
preventive control exists yet. This is the most useful output of the week, and it is
deliberately not hidden behind a passing test.

| # | Attack | Why the baseline cannot stop it | Coverage |
|---|---|---|---|
| A02 | RAG corpus poisoning | Provenance markers stop the model *obeying* retrieved instructions; nothing stops it *answering from* attacker-supplied facts. No corpus-integrity control. | detect-only (D011) |
| A03 | Tool-definition poisoning | Tool descriptions render into the system prompt, so a poisoned tool catalogue lands inside the trusted region. Nothing inspects it. The sandbox still contained the impact — defence in depth, not prevention. | detect-only (D005 reports `system_prompt` region) |
| A04 | Confused deputy | The agent holds one application identity with **no per-user authorization** between agent and tools. Argument validation is not authorization: a well-formed id for another scope succeeds. | detect-only (D013) |
| A08 | Token-flood DoS | A per-prompt size ceiling exists; a per-principal rate or volume budget does not. Individually legitimate prompts in volume are accepted in every posture. | detect-only (D012) |

A10 also succeeds hardened, but by design: its preventive control lives in IAM policy,
SCPs and mandatory-guardrail conditions, none of which exist in this lab. Week 5's cloud
mapping is where that one is actually answered.

The control test asserts against each manifest's `baseline_prevents` value rather than
"nothing may succeed". Making it a pass/fail on zero successes would only create pressure
to weaken the expectation until it went green.

## Defects found and fixed

Five real bugs, all surfaced by running the suite rather than by reading the code:

1. **Traversal resolved against the process CWD.** The vulnerable `read_file` branch used
   `Path(path).expanduser()`, so `../DECOY…` resolved outside the repo and failed with
   ENOENT — the attack appeared blocked for entirely the wrong reason. Real traversal
   joins to the sandbox root and skips the *containment check*, which is now what it does.
2. **The stub never saw the system prompt,** so A03 (tool-definition poisoning) could not
   work at all. Directives reaching the system prompt are now always obeyed — that is the
   whole point of poisoning the trusted region.
3. **No tool chain could exceed depth 1.** The stub summarised the first tool result and
   stopped. It now honours repetition cues ("repeat it", "every turn"), which is how an
   unbounded chain becomes reachable; A09 now reaches depth 10.
4. **A06 called a denied request a bypass.** The success assertion checked only the egress
   destination, not the outcome, so a correctly-blocked IMDS fetch reported as a win.
   Attempted-but-denied now reads as blocked.
5. **The runner mutated `MANIFEST.posture`** to force hardened mode, corrupting manifests
   in-process. Hardened mode is now a flag on `AttackContext`, and the same attack code
   serves as its own control test.

## Observability gap found

A prompt rejected by the size ceiling produced **no telemetry anywhere**: the exception
fired ahead of every emit, and CloudTrail never sees a call that was never made. The
control worked and was completely silent. `AgentInvocationLog` gained `rejected` and
`rejectionReason`, and D001 keys off them. Worth stating in the writeup as a general
lesson: *a preventive control that emits nothing is indistinguishable from an absent one.*

## Attribution

Model- and control-plane detections cannot be tied to a session directly — Bedrock
invocation logs and CloudTrail carry no session id, and inventing one would break schema
fidelity. Instead `invocation_sessions` recovers it by stripping the `-d<depth>` suffix
the application stamps onto request ids, which is the same correlation an analyst does in
Athena. Attacks with no agent trace at all (A10, which calls the model API directly)
declare `markers` — the principals they used — since the absence of a session is itself
the signal.

## Expectation corrected

A04 predicted D006 (tool denied). Wrong: in A04's own posture the allowlist is disabled,
so the call is *permitted*, not denied — D013 is the real signal. The matrix caught it.
This is what the `!` cells are for, and the fix was to the prediction, not the detection.

## Known limitations

- **D011 fires on 6 of 10 attacks** because most attacks plant a corpus document, and
  planting *is* a corpus-integrity violation. Correct, but it makes D011 a
  delivery-mechanism detection rather than a payload detection. It also depends entirely
  on a maintained corpus baseline; without one it is pure noise.
- **D012's threshold (10 invocations / 5 min) is a lab value.** A09's legitimate 10-deep
  chain trips it. Tune to an observed baseline before claiming a real detection rate.
- **Wazuh cannot express intra-array conjunctions.** `data.toolCalls.name` matching is
  true if *any* array element matches, so "denied AND read_file in the same call" is not
  expressible. Documented in the rules file; the SQL detection is authoritative.
- **No MTTD/MTTR numbers yet.** They need the Week 3 IR engine to timestamp
  detection→containment. Nothing here should be quoted as a response-time figure.

## Carried into Week 3

- Executable runbooks keyed to detection ids, with evidence collection and containment.
- MTTD/MTTR measurement, which is the headline number for the writeup.
- Generate the ATLAS coverage matrix from the STIX 2.1 bundle instead of the hand-written
  `atlas:` headers.
