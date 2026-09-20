-- id: D012
-- title: Sustained model invocation volume from a single session
-- severity: medium
-- plane: model
-- atlas: AML.T0034
-- owasp: LLM10:2026 Unbounded Consumption
-- nist: DE.AE-02
-- description: The economic attack is volume, not any single request. Every prompt here
--   passed the size ceiling and is individually legitimate, so only aggregation sees it.
--   Threshold is deliberately low for a lab; tune to observed baseline before production.
SELECT
    t.session_id,
    count(*)                    AS invocations,
    sum(b.input_tokens)         AS total_input_tokens,
    min(b.ts)                   AS first_seen,
    max(b.ts)                   AS last_seen,
    format('{} invocations, {} input tokens in {}s',
           count(*), sum(b.input_tokens),
           round(epoch(max(b.ts) - min(b.ts)), 1))          AS evidence
FROM bedrock_invocations b
JOIN agent_traces t ON t.request_id = regexp_replace(b.request_id, '-d[0-9]+$', '')
GROUP BY t.session_id
HAVING count(*) >= 10
ORDER BY invocations DESC;
