"""Telemetry emitter writing JSONL into an S3-identical key layout.

Local filesystem paths mirror the exact prefixes AWS uses, so the same DuckDB/Athena
SQL and the same S3 sync work against either. Nothing here talks to AWS.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .schemas import (
    AgentInvocationLog,
    CloudTrailDataEvent,
    CloudTrailResource,
    CloudTrailUserIdentity,
    Identity,
    InvocationInput,
    InvocationOutput,
    ModelInvocationLog,
    RetrievedChunk,
    ToolCall,
    rfc3339,
    utc_now,
)

logger = logging.getLogger("aircap.telemetry")


class TelemetryError(RuntimeError):
    """Raised when a telemetry record cannot be persisted."""


def _approx_tokens(text: str) -> int:
    """Deterministic token estimate (~4 chars/token). Deterministic beats accurate here:
    detection thresholds must be reproducible across runs."""
    return max(1, len(text) // 4)


class TelemetrySink:
    """Append-only JSONL sink with AWS-shaped partitioning.

    bedrock-logs/AWSLogs/<acct>/BedrockModelInvocationLogs/<region>/YYYY/MM/DD/HH/<uuid>.jsonl
    cloudtrail/AWSLogs/<acct>/CloudTrail/<region>/YYYY/MM/DD/<uuid>.jsonl
    agent-traces/dt=YYYY-MM-DD/<uuid>.jsonl
    """

    def __init__(self, data_dir: str | Path, account_id: str, region: str) -> None:
        self.root = Path(data_dir).expanduser().resolve()
        self.account_id = account_id
        self.region = region
        self._lock = threading.Lock()
        self.run_id = uuid.uuid4().hex[:12]

    def _bedrock_key(self, ts: datetime) -> Path:
        return (
            self.root
            / "bedrock-logs/AWSLogs"
            / self.account_id
            / "BedrockModelInvocationLogs"
            / self.region
            / f"{ts:%Y/%m/%d/%H}"
            / f"{self.run_id}.jsonl"
        )

    def _cloudtrail_key(self, ts: datetime) -> Path:
        return (
            self.root
            / "cloudtrail/AWSLogs"
            / self.account_id
            / "CloudTrail"
            / self.region
            / f"{ts:%Y/%m/%d}"
            / f"{self.run_id}.jsonl"
        )

    def _agent_key(self, ts: datetime) -> Path:
        return self.root / "agent-traces" / f"dt={ts:%Y-%m-%d}" / f"{self.run_id}.jsonl"

    def _append(self, path: Path, record: BaseModel) -> None:
        line = json.dumps(record.model_dump(exclude_none=False), separators=(",", ":"))
        try:
            with self._lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError as exc:
            raise TelemetryError(f"failed writing telemetry to {path}: {exc}") from exc

    # ---- public API -------------------------------------------------------

    def emit_invocation(
        self,
        *,
        request_id: str,
        principal_arn: str,
        model_id: str,
        prompt: str,
        completion: str,
        guardrail_id: str | None,
        guardrail_intervened: bool,
        source_ip: str,
        user_agent: str,
        system_prompt: str | None = None,
    ) -> None:
        """Emit the Bedrock invocation log and its paired CloudTrail data event."""
        ts = utc_now()
        body: dict[str, Any] = {"prompt": prompt, "max_gen_len": 1024, "temperature": 0.2}
        if system_prompt:
            body["system"] = system_prompt

        self._append(
            self._bedrock_key(ts),
            ModelInvocationLog(
                timestamp=rfc3339(ts),
                accountId=self.account_id,
                identity=Identity(arn=principal_arn),
                region=self.region,
                requestId=request_id,
                modelId=model_id,
                input=InvocationInput(
                    inputBodyJson=body, inputTokenCount=_approx_tokens(prompt)
                ),
                output=InvocationOutput(
                    outputBodyJson={"generation": completion, "stop_reason": "stop"},
                    outputTokenCount=_approx_tokens(completion),
                ),
                guardrailId=guardrail_id,
                guardrailAction=("INTERVENED" if guardrail_intervened else "NONE")
                if guardrail_id
                else None,
            ),
        )

        req_params: dict[str, Any] = {"modelId": model_id}
        if guardrail_id:
            req_params |= {"guardrailIdentifier": guardrail_id, "guardrailVersion": "1"}

        self._append(
            self._cloudtrail_key(ts),
            CloudTrailDataEvent(
                userIdentity=CloudTrailUserIdentity(
                    principalId=f"AROA{self.run_id.upper()}:aircap",
                    arn=principal_arn,
                    accountId=self.account_id,
                    accessKeyId=f"ASIA{self.run_id.upper()}",
                    sessionContext={
                        "sessionIssuer": {
                            "type": "Role",
                            "arn": principal_arn.rsplit("/", 1)[0],
                            "accountId": self.account_id,
                        }
                    },
                ),
                eventTime=rfc3339(ts),
                eventName="InvokeModel",
                awsRegion=self.region,
                sourceIPAddress=source_ip,
                userAgent=user_agent,
                requestParameters=req_params,
                requestID=request_id,
                eventID=str(uuid.uuid4()),
                resources=[
                    CloudTrailResource(
                        accountId=self.account_id,
                        ARN=f"arn:aws:bedrock:{self.region}::foundation-model/{model_id}",
                    )
                ],
                recipientAccountId=self.account_id,
            ),
        )

    def emit_agent_trace(
        self,
        *,
        request_id: str,
        session_id: str,
        principal_arn: str,
        user_prompt: str,
        final_response: str,
        retrieved: list[RetrievedChunk],
        tool_calls: list[ToolCall],
        vuln_flags: dict[str, bool],
        output_filtered: bool,
        latency_ms: int,
        rejected: bool = False,
        rejection_reason: str | None = None,
    ) -> None:
        ts = utc_now()
        self._append(
            self._agent_key(ts),
            AgentInvocationLog(
                timestamp=rfc3339(ts),
                accountId=self.account_id,
                region=self.region,
                requestId=request_id,
                sessionId=session_id,
                principalArn=principal_arn,
                userPrompt=user_prompt,
                finalResponse=final_response,
                retrieved=retrieved,
                toolCalls=tool_calls,
                maxToolDepth=max((t.depth for t in tool_calls), default=0),
                vulnFlags=vuln_flags,
                outputFiltered=output_filtered,
                latencyMs=latency_ms,
                rejected=rejected,
                rejectionReason=rejection_reason,
            ),
        )
        logger.info(
            "agent_trace emitted request_id=%s session=%s tools=%d retrieved=%d",
            request_id,
            session_id,
            len(tool_calls),
            len(retrieved),
        )
