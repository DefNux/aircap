-- id: D008
-- title: Agent egress to a private or metadata address
-- severity: critical
-- plane: agent
-- atlas: AML.T0053
-- owasp: LLM06:2026 Excessive Agency
-- nist: DE.CM-01
-- description: The agent attempted an outbound request to link-local or RFC1918 space.
--   169.254.169.254 is the cloud instance metadata service and the standard pivot from
--   an application-layer injection to cloud credentials.
SELECT ts, session_id, egress_host,
       CASE WHEN egress_host = '169.254.169.254' THEN 'instance metadata service'
            ELSE 'private address space' END AS evidence,
       outcome, arguments
FROM tool_calls
WHERE egress_host IS NOT NULL
  AND (egress_host = '169.254.169.254'
       OR regexp_matches(egress_host, '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)'))
ORDER BY ts;
