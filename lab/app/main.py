"""AIRCAP lab API. Bind to localhost only - this app is intentionally attackable."""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field

from .agent import ModelUnavailable, PromptTooLarge, handle_turn
from .config import settings
from ..telemetry.emitter import TelemetryError, TelemetrySink
from ..telemetry.schemas import rfc3339, utc_now

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("aircap.api")

app = FastAPI(title="AIRCAP Lab", version="0.1.0", docs_url="/docs")
sink = TelemetrySink(settings.data_dir, settings.account_id, settings.region)


class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2_000_000)
    session_id: str = Field(default="anon", min_length=1, max_length=128)


@app.on_event("startup")
async def _startup() -> None:
    settings.log_posture()
    logger.info("telemetry run_id=%s data_dir=%s", sink.run_id, sink.root)


@app.get("/healthz")
def healthz() -> dict[str, object]:
    return {
        "status": "ok",
        "data": {
            "modelId": settings.model_id,
            "runId": sink.run_id,
            "vulnFlags": settings.vuln_flags,
            "guardrailId": settings.active_guardrail,
            "time": rfc3339(utc_now()),
        },
        "error": None,
    }


@app.post("/api/v1/chat")
def chat(body: ChatRequest, request: Request) -> dict[str, object]:
    try:
        result = handle_turn(
            question=body.question,
            session_id=body.session_id,
            sink=sink,
            source_ip=request.client.host if request.client else "127.0.0.1",
            user_agent=request.headers.get("user-agent", "aircap-client/0.1"),
        )
    except PromptTooLarge as exc:
        # Still a security-relevant event: token-flood attempts must be visible.
        logger.warning("prompt rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        ) from exc
    except ModelUnavailable as exc:
        logger.error("model plane down: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except TelemetryError as exc:
        logger.error("telemetry failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="telemetry write failed"
        ) from exc
    return {"status": "ok", "data": result, "error": None}
