"""Attack harness primitives.

Each attack is a module exposing ``MANIFEST`` and ``run(ctx)``. Attacks label their
telemetry with their own id as the session id, which is what lets the detection
matrix attribute every hit back to the attack that produced it.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from lab.app import rag  # noqa: E402
from lab.app.agent import PromptTooLarge, handle_turn  # noqa: E402
from lab.app.config import current, posture  # noqa: E402
from lab.telemetry.emitter import TelemetrySink  # noqa: E402

logger = logging.getLogger("aircap.attack")


@dataclass(frozen=True)
class Manifest:
    """Static description of one attack."""

    id: str
    name: str
    description: str
    posture: dict[str, Any] = field(default_factory=dict)
    atlas: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    expect: tuple[str, ...] = ()          # detection ids that must fire
    # Which layer owns the preventive control for this attack.
    #   "app"   - the lab's own controls can prevent it
    #   "cloud" - prevention belongs to IAM/SCP/guardrails, outside this lab
    #   "none"  - no preventive control exists here yet; residual risk
    control_layer: str = "app"
    # Extra strings that identify this attack in detection output when session-id
    # attribution is impossible - e.g. an attack that calls the model API directly
    # leaves no agent trace, so it is identified by the principal it used.
    markers: tuple[str, ...] = ()
    # Whether the hardened baseline is expected to PREVENT this attack. False means
    # the attack is expected to succeed even hardened - a documented residual risk,
    # not a test failure. The control test asserts against this value.
    baseline_prevents: bool = True
    notes: str = ""


@dataclass
class AttackResult:
    """Outcome of one attack run, as the attack itself judges it."""

    succeeded: bool
    detail: str
    turns: list[dict[str, Any]] = field(default_factory=list)


class AttackContext:
    """Services an attack needs: a telemetry sink, the agent, and the corpus."""

    def __init__(self, sink: TelemetrySink, attack_id: str, *, hardened: bool = False) -> None:
        self.sink = sink
        self.attack_id = attack_id
        self.hardened = hardened
        self.session_id = f"{'base' if hardened else 'atk'}-{attack_id}"
        self._planted: list[Path] = []
        self._effective = current()

    # -- corpus manipulation ------------------------------------------------

    def plant(self, filename: str, content: str) -> Path:
        """Write a document into the retrieval corpus. Cleaned up after the run."""
        if "/" in filename or filename.startswith("."):
            raise ValueError(f"unsafe corpus filename: {filename!r}")
        path = rag.CORPUS_DIR / filename
        path.write_text(content, encoding="utf-8")
        self._planted.append(path)
        logger.info("[%s] planted %s (%d chars)", self.attack_id, filename, len(content))
        return path

    def cleanup(self) -> None:
        for path in self._planted:
            path.unlink(missing_ok=True)
        self._planted.clear()

    # -- driving the target ------------------------------------------------

    def ask(self, question: str, **overrides: Any) -> dict[str, Any]:
        """Send one question to the agent under this attack's posture."""
        # In hardened mode every requested weakening is discarded, so the same
        # attack code doubles as the control test.
        merged = {} if self.hardened else {**getattr(self, "_posture", {}), **overrides}
        with posture(**merged) as effective:
            self._effective = effective
            try:
                return handle_turn(
                    question=question,
                    session_id=self.session_id,
                    sink=self.sink,
                    source_ip="127.0.0.1",
                    user_agent=f"aircap-attack/{self.attack_id}",
                )
            except PromptTooLarge as exc:
                # A rejected prompt is a real outcome, not an error: the control
                # worked, and the attempt must still be visible to detections.
                logger.info("[%s] prompt rejected by ceiling: %s", self.attack_id, exc)
                return {
                    "requestId": "rejected",
                    "sessionId": self.session_id,
                    "answer": "",
                    "toolCalls": [],
                    "retrieved": [],
                    "outputFiltered": False,
                    "filterHits": [],
                    "latencyMs": 0,
                    "rejected": True,
                    "rejectedReason": str(exc),
                }

    def set_posture(self, **overrides: Any) -> None:
        self._posture = overrides

    @property
    def settings(self):  # noqa: ANN201 - proxy type is intentionally opaque
        """Posture in force during the most recent ask(), not the ambient default."""
        return self._effective
