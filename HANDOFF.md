# AIRCAP: Handoff

**AI Incident Response Capability.** A lab that runs a known set of test scenarios against a demo AI assistant. It then checks that the detections fire, applies containment, and re-runs the scenarios to confirm the containment works.

- Repo: https://github.com/DefNux/aircap (public, MIT)
- Local: `/mnt/HDD/Tools/aircap`
- Status: all 6 phases done. Tree is clean and matches `origin/main`.

## Start here

```bash
cd /mnt/HDD/Tools/aircap
make venv        # first time only
make console     # http://127.0.0.1:8099 (loopback only)
make verify      # full pipeline check
make help        # all targets
```

Nothing was left running when the session ended.

## Components

| Area | Path |
|---|---|
| Demo assistant and telemetry emitters | `lab/` |
| Analytics views (DuckDB) | `query/` |
| Test scenarios, 10 | `attacks/` |
| Detections: 14 SQL, 14 Sigma, 16 Wazuh | `detections/` |
| Runbooks, 9 | `runbooks/` |
| IR engine and containment | `engine/` |
| Shadow-AI discovery | `discover/` |
| Operator console | `console/` |
| AWS Terraform (plan-verified only) | `iac/aws/` |
| AWS/Azure mappings, ATLAS coverage | `mappings/` |
| Read-only AWS telemetry audit | `tools/` |
| Build log and results | `docs/` |

## Verified

- All 10 scenarios reproduce and all 14 detections fire, with 0 expectation gaps.
- Containment works: after it is applied, the same scenarios fail when re-run.
- A fresh clone passes the full pipeline.
- Terraform: `validate` is clean and `plan` shows 57 to add. Checkov: 146 passed, 0 failed.

## Not verified

- The console UI in a real browser. Only a headless render check was done.
- The osquery pack. It is schema-checked only.
- Terraform `apply`. It was never run because the project has a zero-spend rule.
- The real-model backend (Ollama). All the numbers come from the stub.
- The Sigma and Wazuh rules inside a live SIEM.

## Caveats

- Telemetry is generated locally. The schemas match AWS; the data is not real.
- MTTR is not claimed. See `engine/METRICS.md`.
- Five scenarios still succeed against the hardened baseline. This is documented in `docs/RESULTS.md`.

## Next steps

1. Open the console in a browser and click through every view.
2. Pull an Ollama model and re-run the scenarios against a real model.
3. Load the Wazuh rules into a real Wazuh instance.

## Key docs

`README.md`, `docs/RESULTS.md`, `engine/METRICS.md`, `mappings/AWS_CONTROLS.md`, `docs/WEEK1.md`–`WEEK6.md`
