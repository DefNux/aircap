-- id: D007
-- title: Path traversal in a tool argument
-- severity: high
-- plane: agent
-- atlas: AML.T0057
-- owasp: LLM02:2026 Sensitive Information Disclosure
-- nist: DE.CM-09
-- description: A relative-path escape appeared in a tool argument. Fires whether or not
--   the sandbox held, because the attempt is the signal.
SELECT ts, session_id, tool_name, arguments AS evidence, outcome, result_bytes
FROM tool_calls
WHERE tool_name = 'read_file' AND arguments LIKE '%..%'
ORDER BY ts;
