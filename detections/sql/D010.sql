-- id: D010
-- title: Credential material in a user-facing response
-- severity: critical
-- plane: agent
-- atlas: AML.T0057
-- owasp: LLM02:2026 Sensitive Information Disclosure
-- nist: DE.CM-09
-- description: Confirmed leak, not an attempt: secret-shaped values left the system in a
--   response with no redaction applied. This is the detection that turns an incident from
--   "attempted" into "data disclosed" and drives the notification decision.
SELECT ts, session_id, request_id,
       regexp_extract(final_response, '(AIRCAP_FAKE_[A-Z_]+\s*=\s*\S+)') AS evidence,
       output_filtered
FROM agent_traces
WHERE regexp_matches(final_response, 'AIRCAP_FAKE_[A-Z_]+\s*=\s*\S+')
  AND NOT output_filtered
ORDER BY ts;
