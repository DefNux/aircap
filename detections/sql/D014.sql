-- id: D014
-- title: Sensitive file read through an agent tool
-- severity: critical
-- plane: agent
-- atlas: AML.T0057
-- owasp: LLM02:2026 Sensitive Information Disclosure
-- nist: DE.CM-09
-- description: A credential-bearing file was successfully read by a tool. Distinct from
--   D007, which fires on the attempt: this one fires only when bytes were returned, so it
--   is the trigger for the exfiltration runbook rather than the injection runbook.
SELECT ts, session_id, tool_name, arguments AS evidence, result_bytes, depth
FROM tool_calls
WHERE tool_name = 'read_file'
  AND outcome = 'ok'
  AND regexp_matches(arguments, '(DECOY|SECRET|secret|\.env|credential)')
ORDER BY ts;
