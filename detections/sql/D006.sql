-- id: D006
-- title: Tool invocation denied by a control
-- severity: medium
-- plane: agent
-- atlas: AML.T0053
-- owasp: LLM06:2026 Excessive Agency
-- nist: DE.CM-09
-- description: A control refused a tool call. The refusal means containment worked, but
--   the agent should never have attempted it - so each hit is evidence of an upstream
--   injection rather than a user error.
SELECT ts, session_id, tool_name, arguments AS evidence, error, depth
FROM tool_calls
WHERE outcome = 'denied'
ORDER BY ts;
