-- id: D004
-- title: Model invoked by an unauthorized principal
-- severity: critical
-- plane: control
-- atlas: AML.T0044
-- owasp: LLM03:2026 Supply Chain
-- nist: DE.CM-01
-- description: Only the application role should call the model. Anything else is stolen
--   credentials, an over-broad role, or a developer bypassing the app - and it produces
--   no agent-plane trace, so control-plane telemetry is the only witness.
SELECT ts, principal_arn, source_ip, user_agent, access_key_id,
       'principal outside the application role' AS evidence
FROM cloudtrail_bedrock
WHERE principal_arn NOT LIKE '%aircap-app-role%'
ORDER BY ts;
