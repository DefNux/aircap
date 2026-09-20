-- id: D011
-- title: Retrieval ranking anomaly - unrecognised source outranked the corpus
-- severity: high
-- plane: agent
-- atlas: AML.T0070
-- owasp: LLM08:2026 Vector and Embedding Weaknesses
-- nist: DE.CM-09
-- description: The top-ranked chunk came from a document outside the approved corpus
--   baseline. Poisoning needs no injection and no tool call - the agent simply answers
--   from attacker text - so ranking provenance is the only agent-plane signal available.
WITH approved AS (
    SELECT unnest(['onboarding', 'expenses', 'support-sla', 'kb-runbook']) AS doc
), ranked AS (
    SELECT ts, session_id, chunk_id, source_uri, score,
           row_number() OVER (PARTITION BY request_id ORDER BY score DESC) AS rank,
           regexp_extract(chunk_id, '^([a-z0-9-]+)#', 1) AS doc
    FROM retrievals
)
SELECT ts, session_id, chunk_id, score,
       format('unapproved document {} ranked #1 (score {})', doc, score) AS evidence
FROM ranked
WHERE rank = 1 AND doc NOT IN (SELECT doc FROM approved)
ORDER BY ts;
