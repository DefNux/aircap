-- id: D009
-- title: Excessive tool-call chain depth
-- severity: high
-- plane: agent
-- atlas: AML.T0053
-- owasp: LLM06:2026 Excessive Agency
-- nist: DE.AE-02
-- description: Depth separates an agent doing its job from an agent being driven. The
--   hardened ceiling is 3; anything deeper means the ceiling was raised or absent.
SELECT ts, session_id, max_tool_depth, tool_call_count,
       format('tool chain reached depth {}', max_tool_depth) AS evidence
FROM agent_traces
WHERE max_tool_depth > 3
ORDER BY max_tool_depth DESC;
