-- id: D005
-- title: Planted tool directive present in model input
-- severity: high
-- plane: model
-- atlas: AML.T0051
-- owasp: LLM01:2026 Prompt Injection
-- nist: DE.AE-02
-- description: A concrete tool-invocation directive naming a real tool appears in the
--   model's input. The system prompt's format example uses a <name> placeholder, so it
--   cannot match. Reports which region carried it: retrieved context, or the system
--   prompt itself (which means the tool catalogue is compromised, not the corpus).
SELECT b.ts, b.request_id, s.session_id,
       CASE
         WHEN regexp_matches(coalesce(b.system_prompt, ''), 'TOOL:\s*(read_file|http_fetch|lookup_ticket)\s*\{')
           THEN 'system_prompt (tool catalogue compromised)'
         ELSE 'retrieved_context'
       END AS injection_region,
       regexp_extract(
         coalesce(b.system_prompt, '') || ' ' || b.prompt,
         'TOOL:\s*(read_file|http_fetch|lookup_ticket)\s*\{[^}]*\}'
       ) AS evidence
FROM bedrock_invocations b
LEFT JOIN invocation_sessions s ON s.request_id = b.request_id
WHERE regexp_matches(
        coalesce(b.system_prompt, '') || ' ' || b.prompt,
        'TOOL:\s*(read_file|http_fetch|lookup_ticket)\s*\{'
      )
ORDER BY b.ts;
