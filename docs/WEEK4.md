# Week 4 — shadow-AI discovery and the operator console

## Delivered

**Shadow-AI discovery** (`discover/`)

- `ai_destinations.yml` — 17 providers / 43 hostnames, 8 local runtimes, 7 extension ids.
  `sanctioned` is the only field meant to be edited per-organisation; it decides whether an
  observation is governance data or an incident.
- `scan.py` — four lenses, **none requiring root**: local inference processes (with GPU
  attribution), listening model APIs, browser extensions, and egress to known destinations.
  A fifth lens, live TLS/QUIC SNI capture, reuses the `tshark` approach from your existing
  `sni-monitor.sh` and is opt-in because it needs packet-capture privileges.
- `osquery/ai-shadow.conf` — 6 queries for fleet deployment, including model weights on disk
  (dormant shadow AI) and extensions holding `<all_urls>`/`clipboardRead`, which is the
  capability that matters regardless of which AI product it belongs to.
- `wazuh/aircap_discover_rules.xml` — 7 rules, ids 100300–100306.
- `cloud/parse_logs.py` — VPC Flow Logs v2, Route 53 Resolver query logs and Azure NSG flow
  logs v2, with synthetic samples so it runs at zero cloud cost.

**Operator console** (`console/`) — FastAPI + a self-contained single-page UI, 21 endpoints,
eight views: Overview, Attacks, Detections, Matrix, Response, Shadow AI, Query, ATLAS.
`make console` → http://127.0.0.1:8099.

## Why a local console and not a published page

A hosted/published artifact cannot drive this system: its CSP blocks requests to localhost,
so it could never run an attack, query DuckDB or apply containment. The console therefore
runs locally and binds to loopback only — which is also the correct security posture, since
it is an administrative interface over a deliberately vulnerable application. It can run
attacks, execute containment and wipe the lab.

The console calls the same functions the CLIs call — no subprocess shelling — so it cannot
drift from what `make verify` does.

## Design decisions

**Risk scoring inverts for local runtimes.** Local inference keeps prompts on the device, so
egress risk is *low* — but the runtime is unmanaged, unpatched, and invisible to a DLP stack
that only watches the network. A network-exposed Ollama API scores critical (it has no
authentication by default); loopback-only scores elevated.

**The scanner was validated by making it fire.** A scanner that only ever returns "clean" is
untested, so Ollama was started and the process and listener lenses both caught it, correctly
scoring the loopback bind as elevated rather than critical.

**Extension ids, not names.** Display names are publisher- and user-controllable; ids are not.
The osquery pack also has a product-agnostic rule for any extension with `<all_urls>` or
clipboard access, because tomorrow's AI extension is not on today's list.

**The SQL console is read-only by construction.** Only `SELECT`/`WITH` are accepted, with a
keyword denylist on top (`copy`, `attach`, `install`, `pragma`, …). Verified against DROP,
DELETE, trailing `COPY`, `ATTACH /etc/passwd` and `INSTALL httpfs` — all rejected.

**The egress lens states its own blind spot.** It reverse-resolves peer IPs, so CDN-fronted
providers are frequently missed. That limitation is printed in the register's `notes` rather
than left for a reader to discover.

## Verification

All 21 endpoints exercised over HTTP, plus the full workflow through the API:

```
attacks 10/10 succeeded -> detections 14/14 fired -> matrix 0 gaps
-> respond: 9 incidents, 13 containment actions
-> re-run A01/A05/A06: all three blocked
-> reset: telemetry cleared, 9 incidents removed, 13 actions lifted
```

Error paths return structured messages: unknown attack/detection/incident ids, invalid IR
mode (422 from the pattern constraint), and the corpus-pollution guard.

**UI rendering was verified headlessly**, not visually — no browser extension was available
in this session. A Node harness with a minimal DOM shim executes every view's `render()` and
`bind()` against the live API and asserts no `undefined`/`NaN`/`[object Object]` leaks into
the output. All 8 views render; the markdown renderer produces every block type. A
cross-check confirms all 20 API calls in the frontend match real backend routes.

**What that does not cover:** actual visual layout, theme switching in a real browser, and
click-through interaction. Those need someone to open the page.

## Known limitations

- **Cloud log parsing uses synthetic samples.** The formats are faithful; the contents are
  fabricated. The output says so in its own `note` field, and the UI badges it
  "synthetic samples".
- **`SAMPLE_IP_MAP` is a crutch.** The VPC and NSG parsers need IP→hostname attribution,
  which in reality comes from Route 53 answers or threat intel. Hardcoding it for the samples
  is honest for a demo and is exactly why Route 53 Resolver logs are the lens worth enabling
  first — they carry the hostname directly.
- **osquery is not installed here**, so the pack is schema-validated (6 queries, valid JSON,
  correct table and column names) but has not been executed against a live osquery instance.
- **Browser lens is Firefox-only in practice** on this machine, since no Chromium-family
  browser is installed to test the extension-id path against.
- **The console has no authentication.** Loopback binding is the only control. That is
  appropriate for a single-operator lab and would not be appropriate for anything shared.
