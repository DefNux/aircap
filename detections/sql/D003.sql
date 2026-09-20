-- id: D003
-- title: Model invoked without a guardrail attached
-- severity: high
-- plane: model
-- atlas: AML.T0044
-- owasp: LLM03:2026 Supply Chain
-- nist: PR.PS-01
-- description: The application always attaches a guardrail, so an invocation without one
--   did not come from the application. In real AWS this is enforceable with an IAM
--   condition key on bedrock:GuardrailIdentifier; detecting it is the fallback.
SELECT b.ts, b.request_id, s.session_id, b.principal_arn, b.model_id,
       'no guardrailIdentifier on InvokeModel' AS evidence
FROM bedrock_invocations b
LEFT JOIN invocation_sessions s ON s.request_id = b.request_id
WHERE b.guardrail_id IS NULL
ORDER BY b.ts;
