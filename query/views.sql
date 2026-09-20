-- AIRCAP analytics views over S3-shaped JSONL.
-- The same SELECTs run in Athena against real S3 prefixes: swap the
-- read_json_auto() path for an external table and nothing else changes.

CREATE OR REPLACE VIEW bedrock_invocations AS
SELECT
    CAST(timestamp AS TIMESTAMP)                 AS ts,
    accountId                                    AS account_id,
    region,
    requestId                                    AS request_id,
    modelId                                      AS model_id,
    operation,
    identity.arn                                 AS principal_arn,
    guardrailId                                  AS guardrail_id,
    guardrailAction                              AS guardrail_action,
    input.inputTokenCount                        AS input_tokens,
    output.outputTokenCount                      AS output_tokens,
    CAST(input.inputBodyJson ->> 'prompt' AS VARCHAR)      AS prompt,
    CAST(input.inputBodyJson ->> 'system' AS VARCHAR)      AS system_prompt,
    CAST(output.outputBodyJson ->> 'generation' AS VARCHAR) AS completion,
    length(CAST(input.inputBodyJson ->> 'prompt' AS VARCHAR)) AS prompt_chars
FROM read_json_auto(
        getvariable('data_dir') || '/bedrock-logs/**/*.jsonl',
        format = 'newline_delimited', union_by_name = true
     );

CREATE OR REPLACE VIEW cloudtrail_bedrock AS
SELECT
    CAST(eventTime AS TIMESTAMP)                 AS ts,
    eventName                                    AS event_name,
    awsRegion                                    AS region,
    sourceIPAddress                              AS source_ip,
    userAgent                                    AS user_agent,
    userIdentity.arn                             AS principal_arn,
    userIdentity.type                            AS principal_type,
    userIdentity.accessKeyId                     AS access_key_id,
    requestID                                    AS request_id,
    eventID                                      AS event_id,
    CAST(requestParameters ->> 'modelId' AS VARCHAR)              AS model_id,
    CAST(requestParameters ->> 'guardrailIdentifier' AS VARCHAR)  AS guardrail_id,
    errorCode                                    AS error_code,
    recipientAccountId                           AS account_id
FROM read_json_auto(
        getvariable('data_dir') || '/cloudtrail/**/*.jsonl',
        format = 'newline_delimited', union_by_name = true
     );

CREATE OR REPLACE VIEW agent_traces AS
SELECT
    CAST(timestamp AS TIMESTAMP)                 AS ts,
    requestId                                    AS request_id,
    sessionId                                    AS session_id,
    principalArn                                 AS principal_arn,
    userPrompt                                   AS user_prompt,
    finalResponse                                AS final_response,
    retrieved,
    toolCalls                                    AS tool_calls,
    maxToolDepth                                 AS max_tool_depth,
    vulnFlags                                    AS vuln_flags,
    outputFiltered                               AS output_filtered,
    latencyMs                                    AS latency_ms,
    coalesce(rejected, false)                    AS rejected,
    rejectionReason                              AS rejection_reason,
    len(toolCalls)                               AS tool_call_count,
    len(retrieved)                               AS retrieved_count
FROM read_json_auto(
        getvariable('data_dir') || '/agent-traces/**/*.jsonl',
        format = 'newline_delimited', union_by_name = true
     );

-- Flattened tool calls: one row per tool invocation. Most agent-plane
-- detections key off this view.
CREATE OR REPLACE VIEW tool_calls AS
SELECT
    t.ts,
    t.request_id,
    t.session_id,
    t.principal_arn,
    tc.name                                      AS tool_name,
    tc.arguments::VARCHAR                        AS arguments,
    tc.depth,
    tc.allowed,
    tc.outcome,
    tc.resultBytes                               AS result_bytes,
    tc.egressHost                                AS egress_host,
    tc.durationMs                                AS duration_ms,
    tc.error
FROM agent_traces t, UNNEST(t.tool_calls) AS u(tc);

-- Flattened retrieval provenance: one row per retrieved chunk.
CREATE OR REPLACE VIEW retrievals AS
SELECT
    t.ts,
    t.request_id,
    t.session_id,
    r.sourceUri                                  AS source_uri,
    r.chunkId                                    AS chunk_id,
    r.score,
    r.chars
FROM agent_traces t, UNNEST(t.retrieved) AS u(r);

-- Correlates model- and control-plane records back to the agent session that caused
-- them. The application stamps invocation request ids as "<trace-uuid>-d<depth>", so
-- stripping the suffix recovers the agent trace. Calls made directly against the model
-- API have no agent trace and therefore no session - which is itself the signal that
-- something bypassed the application.
CREATE OR REPLACE VIEW invocation_sessions AS
SELECT
    b.request_id,
    regexp_replace(b.request_id, '-d[0-9]+$', '') AS trace_id,
    t.session_id
FROM bedrock_invocations b
LEFT JOIN agent_traces t
       ON t.request_id = regexp_replace(b.request_id, '-d[0-9]+$', '');
