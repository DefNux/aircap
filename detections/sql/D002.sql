-- id: D002
-- title: Credential material present in a model prompt
-- severity: high
-- plane: model
-- atlas: AML.T0057
-- owasp: LLM02:2026 Sensitive Information Disclosure
-- nist: DE.CM-09
-- description: Secret-shaped strings reached the model's input. In an agent loop this is
--   usually tool output being fed back into context, meaning data has already left its
--   store and is now inside an inference request.
SELECT b.ts, b.request_id, s.session_id, b.principal_arn,
       regexp_extract(b.prompt, '(AIRCAP_FAKE_[A-Z_]+|(AKIA|ASIA)[0-9A-Z]{16})') AS evidence,
       b.prompt_chars
FROM bedrock_invocations b
LEFT JOIN invocation_sessions s ON s.request_id = b.request_id
WHERE regexp_matches(b.prompt, '(AIRCAP_FAKE_[A-Z_]+\s*=|(AKIA|ASIA)[0-9A-Z]{16})')
ORDER BY b.ts;
