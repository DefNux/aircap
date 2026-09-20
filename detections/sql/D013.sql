-- id: D013
-- title: Agent read a restricted ticket record
-- severity: high
-- plane: agent
-- atlas: AML.T0053
-- owasp: LLM06:2026 Excessive Agency
-- nist: DE.CM-09
-- description: TKT-1003 is the SOC's own incident record. The agent holds one application
--   identity with no per-user authorization, so any caller who can reach the agent can
--   reach this record through it. The audit trail shows only the application principal.
SELECT ts, session_id, tool_name, arguments AS evidence, outcome, result_bytes
FROM tool_calls
WHERE tool_name = 'lookup_ticket'
  AND outcome = 'ok'
  AND arguments LIKE '%TKT-1003%'
ORDER BY ts;
