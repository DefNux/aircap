"""AWS-faithful telemetry schemas.

Detections written against these shapes transfer to real AWS unchanged. Three streams:

1. ModelInvocationLog  - Bedrock model invocation logging (holds prompt + completion bodies)
2. CloudTrailDataEvent - CloudTrail data event for bedrock:InvokeModel (proves the call, never the body)
3. AgentInvocationLog  - AIRCAP-native agent/tool trace; CloudTrail has no equivalent for tool calls

All timestamps are RFC3339 UTC. Bodies are stored as parsed JSON, matching Bedrock's
`inputBodyJson` / `outputBodyJson` fields when delivering to S3.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def rfc3339(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Identity(BaseModel):
    """Bedrock invocation-log identity block."""

    arn: str


class InvocationInput(BaseModel):
    inputContentType: str = "application/json"
    inputBodyJson: dict[str, Any]
    inputTokenCount: int = Field(ge=0)


class InvocationOutput(BaseModel):
    outputContentType: str = "application/json"
    outputBodyJson: dict[str, Any]
    outputTokenCount: int = Field(ge=0)


class ModelInvocationLog(BaseModel):
    """Mirrors an Amazon Bedrock model invocation log record."""

    schemaType: Literal["ModelInvocationLog"] = "ModelInvocationLog"
    schemaVersion: str = SCHEMA_VERSION
    timestamp: str
    accountId: str
    identity: Identity
    region: str
    requestId: str
    operation: Literal["InvokeModel", "InvokeModelWithResponseStream", "Converse"] = "InvokeModel"
    modelId: str
    input: InvocationInput
    output: InvocationOutput
    # Present only when a guardrail was attached to the call. Absence is itself a detection signal.
    guardrailId: str | None = None
    guardrailAction: Literal["NONE", "INTERVENED"] | None = None

    @field_validator("accountId")
    @classmethod
    def _account_is_12_digits(cls, v: str) -> str:
        if not (v.isdigit() and len(v) == 12):
            raise ValueError("accountId must be 12 digits")
        return v


class CloudTrailUserIdentity(BaseModel):
    type: str = "AssumedRole"
    principalId: str
    arn: str
    accountId: str
    accessKeyId: str
    sessionContext: dict[str, Any] | None = None


class CloudTrailResource(BaseModel):
    accountId: str
    type: str = "AWS::Bedrock::Model"
    ARN: str


class CloudTrailDataEvent(BaseModel):
    """Mirrors a CloudTrail data event for bedrock:InvokeModel.

    Deliberately carries no prompt or completion - that asymmetry with
    ModelInvocationLog is a core teaching point of the lab.
    """

    eventVersion: str = "1.09"
    userIdentity: CloudTrailUserIdentity
    eventTime: str
    eventSource: Literal["bedrock.amazonaws.com"] = "bedrock.amazonaws.com"
    eventName: str
    awsRegion: str
    sourceIPAddress: str
    userAgent: str
    requestParameters: dict[str, Any]
    responseElements: dict[str, Any] | None = None
    requestID: str
    eventID: str
    readOnly: bool = False
    resources: list[CloudTrailResource] = Field(default_factory=list)
    eventType: str = "AwsApiCall"
    managementEvent: bool = False
    recipientAccountId: str
    eventCategory: Literal["Data", "Management"] = "Data"
    errorCode: str | None = None
    errorMessage: str | None = None


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any]
    depth: int = Field(ge=0)
    allowed: bool
    outcome: Literal["ok", "denied", "error"]
    resultBytes: int = Field(default=0, ge=0)
    egressHost: str | None = None
    durationMs: int = Field(default=0, ge=0)
    error: str | None = None


class RetrievedChunk(BaseModel):
    sourceUri: str
    chunkId: str
    score: float
    chars: int = Field(ge=0)


class AgentInvocationLog(BaseModel):
    """Agent-plane trace: the tool calls and retrieval context behind an invocation.

    Real-world analogue: Bedrock AgentCore observability / OpenTelemetry agent spans.
    """

    schemaType: Literal["AgentInvocationLog"] = "AgentInvocationLog"
    schemaVersion: str = SCHEMA_VERSION
    timestamp: str
    accountId: str
    region: str
    requestId: str
    sessionId: str
    principalArn: str
    userPrompt: str
    finalResponse: str
    retrieved: list[RetrievedChunk] = Field(default_factory=list)
    toolCalls: list[ToolCall] = Field(default_factory=list)
    maxToolDepth: int = Field(default=0, ge=0)
    vulnFlags: dict[str, bool] = Field(default_factory=dict)
    outputFiltered: bool = False
    latencyMs: int = Field(default=0, ge=0)
