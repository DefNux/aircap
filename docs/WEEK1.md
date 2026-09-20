# Week 1 — target app + AWS-faithful telemetry

## Delivered

- `lab/app/` — FastAPI RAG + agent app; 3 tools (`read_file`, `http_fetch`, `lookup_ticket`);
  5 vulnerability toggles; layered controls (path sandbox, egress allowlist with private-range
  denial, tool allowlist, argument validation, output redaction).
- `lab/app/model.py` — pluggable model plane: `stub` (deterministic, GPU-free) and `ollama`.
- `lab/telemetry/` — pydantic-validated emitters for three streams in AWS-identical S3 key layout.
- `query/` — five DuckDB views plus a query runner with actionable errors.
- `scripts/smoke.py` — acceptance test running hardened and trusting postures over one planted doc.

## Design decisions worth recording

**Why a stub model backend.** Attack and detection tests must be reproducible; a sampled LLM is not.
The stub simulates a gullible but delimiter-aware assistant: it obeys imperative directives found in
untrusted context *only* when that context arrives without provenance markers. So the same attack
script yields a deterministic hit with `TRUST_RETRIEVED_CONTENT=true` and a deterministic miss
without it. Ollama then serves realism for the demo, not correctness for the test suite.

**Why filesystem paths that mimic S3 prefixes.** `bedrock-logs/AWSLogs/<acct>/BedrockModelInvocationLogs/<region>/YYYY/MM/DD/HH/`
is what AWS actually writes. Same layout locally means the same SQL, and an `aws s3 sync` is the only
step between this lab and a real account.

**Why CloudTrail carries no bodies.** Faithful to AWS, and it forces the right lesson: control-plane
logs alone cannot answer "what was the model asked to do".

## Verification (reproduced 2026-09-20)

```
$ make smoke
[hardened] trust_retrieved_content=False tools=0 exfil_attempted=False denied=False
[trusting] trust_retrieved_content=True  tools=1 exfil_attempted=True  denied=True
telemetry files per stream: {'bedrock-logs': 2, 'cloudtrail': 2, 'agent-traces': 2}
SMOKE PASS
```

Retrieval ranking confirms the poisoning primitive: the planted `sla-addendum#0` chunk scored 0.6
against the legitimate `support-sla#0` at 0.4, so it wins the context window.

## Carried into Week 2

- Ollama v0.34.2 installed rootless to `~/.local/bin/ollama` (1.4 GB `.tar.zst`, sha256
  `e155b835…` verified). Not yet on `PATH`; the Makefile calls it by absolute path. The model
  itself is still to pull: `make ollama-pull` (~2 GB for `llama3.2:3b-instruct-q4_K_M`).
  Note the release asset is `.tar.zst`, not the `.tgz` most install guides still reference.
- The smoke test reloads modules to change posture because `Settings` is read at import time. For the
  attack harness, make posture a per-request override instead so attacks can run in one process.
