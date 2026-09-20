"""EventBridge -> Lambda trigger for the AIRCAP IR engine.

Deliberately thin. Automated containment that fires without a human on a
false-positive detection is how a detection bug becomes an outage - a lesson this
project learned the hard way when a runbook quarantined two legitimate documents.
So this publishes an enriched alert and records what it WOULD contain; it does not
contain. Promoting an action to automatic is a per-action decision with a documented
blast radius, not a default.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
DRY_RUN = os.environ.get("CONTAIN_DRY_RUN", "true").lower() != "false"

# Detection id -> the containment action a responder should consider.
PROPOSED_CONTAINMENT = {
    "D003": "revoke the calling principal's session and require guardrail on re-issue",
    "D004": "disable the access key and quarantine the role",
    "D005": "quarantine the retrieved document; if region is system_prompt, rotate the tool catalogue",
    "D007": "disable the file-reading tool",
    "D008": "block the egress destination; treat as credential compromise",
    "D010": "enforce output redaction and rotate the disclosed credentials",
    "D014": "disable the tool and rotate every credential the file held",
}


def handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    detail = event.get("detail", {}) or {}
    detection = str(detail.get("detectionId", "unknown"))
    severity = str(detail.get("severity", "unknown"))

    proposal = PROPOSED_CONTAINMENT.get(detection, "no automated proposal - triage manually")
    logger.info(
        json.dumps({
            "msg": "aircap detection received",
            "detection": detection,
            "severity": severity,
            "proposed_containment": proposal,
            "dry_run": DRY_RUN,
        })
    )

    if not DRY_RUN:
        # Intentionally unimplemented. Wiring real containment here requires a
        # per-action blast-radius review; see runbooks/ for what each action touches.
        logger.warning(
            "CONTAIN_DRY_RUN=false but automated containment is not implemented by "
            "design - see the module docstring"
        )

    return {
        "statusCode": 200,
        "detection": detection,
        "severity": severity,
        "proposedContainment": proposal,
        "contained": False,
        "alertTopic": TOPIC_ARN or None,
    }
