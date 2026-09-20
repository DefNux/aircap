"""Agent tools with per-tool controls that the vulnerability toggles disable.

Hardened defaults:
  read_file    - confined to a sandbox root, symlinks and traversal rejected
  http_fetch   - host allowlist, private/link-local/loopback ranges denied
  lookup_ticket- fixed in-memory dataset, id format validated

With toggles on, each control is bypassed so the matching attack reproduces.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from .config import settings
from ..telemetry.schemas import ToolCall

logger = logging.getLogger("aircap.tools")

SANDBOX_ROOT = (Path(__file__).parent / "sandbox").resolve()
FETCH_ALLOWLIST = {"docs.internal.aircap.lab", "status.internal.aircap.lab", "127.0.0.1"}
TOOL_ALLOWLIST = {"read_file", "http_fetch", "lookup_ticket"}
_TICKET_ID = re.compile(r"^TKT-\d{4}$")

TICKETS: dict[str, dict[str, str]] = {
    "TKT-1001": {"subject": "VPN drops on reconnect", "owner": "helpdesk", "severity": "3"},
    "TKT-1002": {"subject": "SSO login loop", "owner": "identity-team", "severity": "2"},
    "TKT-1003": {"subject": "Suspected phishing report", "owner": "soc", "severity": "1"},
}


class ToolDenied(PermissionError):
    """Raised when a control blocks a tool call."""


class ToolFailed(RuntimeError):
    """Raised when a tool call fails for a non-security reason."""


def _is_private(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True  # unresolvable -> treat as unsafe
    for info in infos:
        addr = ipaddress.ip_address(info[4][0])
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return True
    return False


def read_file(path: str) -> str:
    if settings.no_tool_allowlist:
        target = Path(path).expanduser()
    else:
        candidate = (SANDBOX_ROOT / path.lstrip("/")).resolve()
        if not str(candidate).startswith(str(SANDBOX_ROOT) + "/"):
            raise ToolDenied(f"path escapes sandbox: {path}")
        if candidate.is_symlink():
            raise ToolDenied(f"symlink rejected: {path}")
        target = candidate
    try:
        return target.read_text(encoding="utf-8", errors="replace")[:4000]
    except OSError as exc:
        raise ToolFailed(f"cannot read {path}: {exc}") from exc


def http_fetch(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ToolDenied(f"scheme not permitted: {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not settings.allow_unscoped_fetch:
        if host not in FETCH_ALLOWLIST:
            raise ToolDenied(f"host not in allowlist: {host}")
        if host != "127.0.0.1" and _is_private(host):
            raise ToolDenied(f"host resolves to a private address: {host}")
    try:
        resp = httpx.get(url, timeout=10.0, follow_redirects=False)
        return resp.text[:4000]
    except httpx.HTTPError as exc:
        raise ToolFailed(f"fetch failed for {url}: {exc}") from exc


def lookup_ticket(ticket_id: str) -> str:
    if not settings.no_tool_allowlist and not _TICKET_ID.match(ticket_id):
        raise ToolDenied(f"malformed ticket id: {ticket_id!r}")
    record = TICKETS.get(ticket_id)
    if record is None:
        raise ToolFailed(f"no such ticket: {ticket_id}")
    return "; ".join(f"{k}={v}" for k, v in record.items())


REGISTRY: dict[str, Callable[..., str]] = {
    "read_file": read_file,
    "http_fetch": http_fetch,
    "lookup_ticket": lookup_ticket,
}

# Tool descriptions handed to the model. attacks/03 mutates these at runtime to
# reproduce tool-definition poisoning, so they are data, not string literals.
DESCRIPTIONS: dict[str, str] = {
    "read_file": "read_file(path) - read a document from the support knowledge sandbox",
    "http_fetch": "http_fetch(url) - fetch an internal documentation URL",
    "lookup_ticket": "lookup_ticket(ticket_id) - look up a ticket by id, format TKT-nnnn",
}


def invoke(name: str, arguments: dict[str, Any], depth: int) -> tuple[ToolCall, str]:
    """Execute a tool, returning its trace record and output. Never raises."""
    started = time.perf_counter()
    allowed = settings.no_tool_allowlist or name in TOOL_ALLOWLIST
    egress_host: str | None = None
    if name == "http_fetch":
        egress_host = urlparse(str(arguments.get("url", ""))).hostname

    def trace(outcome: str, result: str, error: str | None = None) -> tuple[ToolCall, str]:
        return (
            ToolCall(
                name=name,
                arguments=arguments,
                depth=depth,
                allowed=allowed,
                outcome=outcome,  # type: ignore[arg-type]
                resultBytes=len(result.encode()),
                egressHost=egress_host,
                durationMs=int((time.perf_counter() - started) * 1000),
                error=error,
            ),
            result,
        )

    if not allowed:
        logger.warning("tool not allowlisted: %s", name)
        return trace("denied", "", f"tool not allowlisted: {name}")

    fn = REGISTRY.get(name)
    if fn is None:
        return trace("error", "", f"unknown tool: {name}")

    try:
        out = fn(**arguments)
        return trace("ok", out)
    except ToolDenied as exc:
        logger.warning("tool %s denied: %s", name, exc)
        return trace("denied", "", str(exc))
    except TypeError as exc:
        return trace("error", "", f"bad arguments for {name}: {exc}")
    except ToolFailed as exc:
        logger.error("tool %s failed: %s", name, exc)
        return trace("error", "", str(exc))
