-- id: D001
-- title: Oversized prompt rejected by the size ceiling
-- severity: medium
-- plane: agent
-- atlas: AML.T0034
-- owasp: LLM10:2026 Unbounded Consumption
-- nist: DE.AE-02
-- description: A request was refused before reaching the model. Benign clients do not
--   send prompts multiples of the ceiling; repeated rejections indicate probing or a
--   cost attack. Without the rejection event this attempt leaves no trace at all.
SELECT ts, session_id, principal_arn, rejection_reason AS evidence,
       length(user_prompt) AS truncated_prompt_chars
FROM agent_traces
WHERE rejected
ORDER BY ts;
