"""Containment state the running lab actually honours.

Containment is only credible if re-running the attack afterwards fails. So these are
not log lines: ``rag.retrieve`` skips quarantined documents, ``tools.invoke`` refuses
disabled tools, ``http_fetch`` refuses blocked hosts, and the API refuses revoked
principals. Every action is reversible, and every change is appended to an audit log so
the incident timeline can show who contained what and when.

State lives in one JSON file so it survives a process restart, which is what makes the
attack -> detect -> contain -> re-attack -> blocked sequence demonstrable.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("aircap.containment")

Action = Literal[
    "quarantine_document",
    "disable_tool",
    "block_egress_host",
    "revoke_principal",
    "enforce_output_filter",
]

_EMPTY: dict[str, Any] = {
    "quarantined_documents": [],
    "disabled_tools": [],
    "blocked_egress_hosts": [],
    "revoked_principals": [],
    "enforce_output_filter": False,
    "audit": [],
}


class ContainmentError(RuntimeError):
    """Raised when containment state cannot be read or written."""


class ContainmentStore:
    """Thread-safe JSON-backed containment state."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return json.loads(json.dumps(_EMPTY))
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContainmentError(f"cannot read containment state {self.path}: {exc}") from exc
        # Tolerate a state file written by an older schema.
        for key, default in _EMPTY.items():
            data.setdefault(key, json.loads(json.dumps(default)))
        return data

    def _write(self, data: dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.replace(self.path)          # atomic: a partial state file is worse than none
        except OSError as exc:
            raise ContainmentError(f"cannot write containment state {self.path}: {exc}") from exc

    # -- queries used by the running app -----------------------------------

    def is_document_quarantined(self, filename: str) -> bool:
        return filename in self._read()["quarantined_documents"]

    def is_tool_disabled(self, tool: str) -> bool:
        return tool in self._read()["disabled_tools"]

    def is_host_blocked(self, host: str | None) -> bool:
        return bool(host) and host in self._read()["blocked_egress_hosts"]

    def is_principal_revoked(self, arn: str) -> bool:
        return any(r in arn for r in self._read()["revoked_principals"])

    def output_filter_enforced(self) -> bool:
        return bool(self._read()["enforce_output_filter"])

    def state(self) -> dict[str, Any]:
        return self._read()

    def active_count(self) -> int:
        data = self._read()
        return (
            len(data["quarantined_documents"])
            + len(data["disabled_tools"])
            + len(data["blocked_egress_hosts"])
            + len(data["revoked_principals"])
            + int(bool(data["enforce_output_filter"]))
        )

    # -- mutations used by runbooks -----------------------------------------

    def apply(self, action: Action, target: str, *, incident: str, reason: str) -> dict[str, Any]:
        """Apply one containment action. Idempotent; returns an audit record."""
        field = {
            "quarantine_document": "quarantined_documents",
            "disable_tool": "disabled_tools",
            "block_egress_host": "blocked_egress_hosts",
            "revoke_principal": "revoked_principals",
        }.get(action)

        with self._lock:
            data = self._read()
            already = False
            if action == "enforce_output_filter":
                already = bool(data["enforce_output_filter"])
                data["enforce_output_filter"] = True
            elif field is None:
                raise ContainmentError(f"unknown containment action: {action}")
            else:
                already = target in data[field]
                if not already:
                    data[field].append(target)

            record = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "action": action,
                "target": target,
                "incident": incident,
                "reason": reason,
                "already_in_effect": already,
            }
            data["audit"].append(record)
            self._write(data)

        logger.warning(
            "CONTAINMENT %s target=%s incident=%s%s",
            action, target, incident, " (already in effect)" if already else "",
        )
        return record

    def lift_all(self, *, incident: str = "manual", reason: str = "lab reset") -> int:
        """Reverse every containment action. Returns how many were in effect."""
        with self._lock:
            data = self._read()
            count = self.active_count()
            audit = data["audit"]
            fresh = json.loads(json.dumps(_EMPTY))
            fresh["audit"] = audit + [
                {
                    "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    "action": "lift_all",
                    "target": "*",
                    "incident": incident,
                    "reason": reason,
                    "lifted": count,
                }
            ]
            self._write(fresh)
        logger.warning("CONTAINMENT lifted %d action(s)", count)
        return count


def default_store() -> ContainmentStore:
    from .config import settings  # noqa: PLC0415 - avoids a circular import at module load

    return ContainmentStore(Path(settings.data_dir) / "containment.json")
