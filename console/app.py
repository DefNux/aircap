"""AIRCAP console - local web UI for driving and inspecting the whole capability.

Binds to loopback only. This console can run attacks, execute containment and reset the
lab, so it is an administrative interface over a deliberately vulnerable application:
never expose it beyond 127.0.0.1.

  make console      ->  http://127.0.0.1:8099
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import service
from .service import ConsoleError

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("aircap.console.api")

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(
    title="AIRCAP Console",
    version="1.0.0",
    description="Operator console for the AI Incident Response Capability lab.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


def ok(data: Any) -> dict[str, Any]:
    return {"status": "ok", "data": data, "error": None}


@app.exception_handler(ConsoleError)
async def _console_error(_request, exc: ConsoleError) -> JSONResponse:
    logger.warning("console error: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"status": "error", "data": None, "error": str(exc)},
    )


# --- request models ---------------------------------------------------------

class AttackRunRequest(BaseModel):
    ids: list[str] | None = Field(default=None, description="attack ids, or null for all")
    hardened: bool = Field(default=False, description="run the control test")
    keep_artifacts: bool = Field(
        default=False, description="leave planted documents for IR to act on"
    )


class IRRunRequest(BaseModel):
    mode: str = Field(default="triage", pattern="^(triage|respond)$")
    runbooks: list[str] | None = None


class QueryRequest(BaseModel):
    sql: str = Field(min_length=1, max_length=20_000)
    limit: int = Field(default=200, ge=1, le=2000)


# --- pages ------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, Any]:
    return ok({"service": "aircap-console", "version": app.version})


# --- overview ---------------------------------------------------------------

@app.get("/api/v1/overview")
def get_overview() -> dict[str, Any]:
    return ok(service.overview())


@app.post("/api/v1/reset")
def post_reset() -> dict[str, Any]:
    logger.warning("lab reset requested")
    return ok(service.reset_lab())


# --- attacks ----------------------------------------------------------------

@app.get("/api/v1/attacks")
def get_attacks() -> dict[str, Any]:
    return ok(service.list_attacks())


@app.post("/api/v1/attacks/run")
def post_attacks_run(body: AttackRunRequest) -> dict[str, Any]:
    logger.info("attack run: ids=%s hardened=%s", body.ids or "all", body.hardened)
    return ok(
        service.run_attacks(
            body.ids, hardened=body.hardened, keep_artifacts=body.keep_artifacts
        )
    )


# --- detections -------------------------------------------------------------

@app.get("/api/v1/detections")
def get_detections() -> dict[str, Any]:
    return ok(service.list_detections())


@app.post("/api/v1/detections/run")
def post_detections_run() -> dict[str, Any]:
    result = service.run_detections()
    result.pop("_blobs", None)
    return ok(result)


@app.get("/api/v1/detections/{detection_id}/rows")
def get_detection_rows(detection_id: str, limit: int = Query(default=200, ge=1, le=2000)) -> dict[str, Any]:
    return ok(service.detection_rows(detection_id, limit))


@app.get("/api/v1/matrix")
def get_matrix() -> dict[str, Any]:
    return ok(service.matrix())


# --- incident response ------------------------------------------------------

@app.get("/api/v1/runbooks")
def get_runbooks() -> dict[str, Any]:
    return ok(service.list_runbooks())


@app.post("/api/v1/ir/run")
def post_ir_run(body: IRRunRequest) -> dict[str, Any]:
    logger.warning("IR run: mode=%s runbooks=%s", body.mode, body.runbooks or "all")
    return ok(service.run_ir(body.mode, body.runbooks))


@app.get("/api/v1/incidents")
def get_incidents() -> dict[str, Any]:
    return ok(service.list_incidents())


@app.get("/api/v1/incidents/{incident_id}")
def get_incident(incident_id: str) -> dict[str, Any]:
    return ok(service.incident_detail(incident_id))


@app.get("/api/v1/containment")
def get_containment() -> dict[str, Any]:
    return ok(service.store().state())


@app.post("/api/v1/containment/lift")
def post_containment_lift() -> dict[str, Any]:
    logger.warning("containment lift requested")
    return ok(service.lift_containment())


# --- discovery --------------------------------------------------------------

@app.get("/api/v1/discover")
def get_discover() -> dict[str, Any]:
    register = service.discovery_register()
    if register is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no discovery register yet - run a scan",
        )
    return ok(register)


@app.post("/api/v1/discover/scan")
def post_discover_scan() -> dict[str, Any]:
    return ok(service.run_discovery())


@app.get("/api/v1/cloud-egress")
def get_cloud_egress() -> dict[str, Any]:
    return ok(service.cloud_egress(parse=False))


@app.post("/api/v1/cloud-egress/parse")
def post_cloud_egress() -> dict[str, Any]:
    return ok(service.cloud_egress(parse=True))


# --- analytics --------------------------------------------------------------

@app.get("/api/v1/views")
def get_views() -> dict[str, Any]:
    return ok(service.views())


@app.post("/api/v1/query")
def post_query(body: QueryRequest) -> dict[str, Any]:
    return ok(service.ad_hoc_query(body.sql, body.limit))


@app.get("/api/v1/docs")
def get_docs() -> dict[str, Any]:
    return ok(service.list_docs())


@app.get("/api/v1/docs/{key}")
def get_doc(key: str) -> dict[str, Any]:
    return ok(service.read_doc(key))


@app.get("/api/v1/atlas")
def get_atlas() -> dict[str, Any]:
    return ok(service.atlas_coverage())


app.mount("/static", StaticFiles(directory=STATIC), name="static")
