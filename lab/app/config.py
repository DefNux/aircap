"""Lab configuration. Every vulnerability is an explicit, logged opt-in.

Posture is resolved per-request through a ContextVar, not at import time, so an
attack harness can run many postures inside one process. Application code keeps
using the module-level ``settings`` object; it is a proxy that resolves against
whatever posture is active on the current context.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("aircap.config")

VULN_FLAGS = (
    "trust_retrieved_content",
    "no_tool_allowlist",
    "allow_unscoped_fetch",
    "no_output_filter",
    "drop_guardrail",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AIRCAP_", env_file=".env", extra="ignore", case_sensitive=False
    )

    model_backend: Literal["stub", "ollama"] = "stub"
    ollama_url: str = "http://127.0.0.1:11434"
    model_id: str = "llama3.2:3b-instruct-q4_K_M"
    data_dir: str = "./data"
    account_id: str = "123456789012"
    region: str = "us-east-1"
    role_name: str = "aircap-app-role"
    guardrail_id: str = "aircap-baseline-gr"

    # --- vulnerability toggles (all False == hardened baseline) ---
    trust_retrieved_content: bool = False
    no_tool_allowlist: bool = False
    allow_unscoped_fetch: bool = False
    no_output_filter: bool = False
    drop_guardrail: bool = False

    max_tool_depth: int = Field(default=3, ge=1, le=25)
    max_prompt_chars: int = Field(default=8000, ge=100, le=2_000_000)
    request_timeout_s: float = Field(default=120.0, gt=0)

    @property
    def principal_arn(self) -> str:
        return f"arn:aws:sts::{self.account_id}:assumed-role/{self.role_name}/aircap-session"

    @property
    def vuln_flags(self) -> dict[str, bool]:
        return {name: getattr(self, name) for name in VULN_FLAGS}

    @property
    def active_guardrail(self) -> str | None:
        return None if self.drop_guardrail else self.guardrail_id

    def log_posture(self) -> None:
        enabled = [k for k, v in self.vuln_flags.items() if v]
        if enabled:
            logger.warning("LAB RUNNING VULNERABLE: %s", ", ".join(enabled))
        else:
            logger.info("lab posture: hardened baseline (no vuln flags set)")


_BASE = Settings()
_ACTIVE: ContextVar[Settings | None] = ContextVar("aircap_posture", default=None)


def current() -> Settings:
    """The Settings governing the current context."""
    return _ACTIVE.get() or _BASE


def base() -> Settings:
    """The process-wide baseline, ignoring any active override."""
    return _BASE


@contextmanager
def posture(**overrides: Any) -> Iterator[Settings]:
    """Temporarily apply configuration overrides to the current context.

    Unknown keys are rejected rather than silently ignored - a typo in an attack
    manifest must fail loudly, otherwise an attack appears to run hardened and the
    detection matrix quietly fills with false negatives.
    """
    unknown = set(overrides) - set(Settings.model_fields)
    if unknown:
        raise ValueError(f"unknown setting(s): {', '.join(sorted(unknown))}")

    merged = _BASE.model_copy(update=overrides)
    token = _ACTIVE.set(merged)
    enabled = [k for k, v in merged.vuln_flags.items() if v]
    logger.info("posture entered: %s", ", ".join(enabled) if enabled else "hardened")
    try:
        yield merged
    finally:
        _ACTIVE.reset(token)


class _SettingsProxy:
    """Attribute access resolves against the active posture at call time."""

    def __getattr__(self, name: str) -> Any:
        return getattr(current(), name)

    def __repr__(self) -> str:
        return f"<SettingsProxy active={current().vuln_flags}>"


settings = _SettingsProxy()
