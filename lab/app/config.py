"""Lab configuration. Every vulnerability is an explicit, logged opt-in."""

from __future__ import annotations

import logging

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("aircap.config")


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
        return {
            "trust_retrieved_content": self.trust_retrieved_content,
            "no_tool_allowlist": self.no_tool_allowlist,
            "allow_unscoped_fetch": self.allow_unscoped_fetch,
            "no_output_filter": self.no_output_filter,
            "drop_guardrail": self.drop_guardrail,
        }

    @property
    def active_guardrail(self) -> str | None:
        return None if self.drop_guardrail else self.guardrail_id

    def log_posture(self) -> None:
        enabled = [k for k, v in self.vuln_flags.items() if v]
        if enabled:
            logger.warning("LAB RUNNING VULNERABLE: %s", ", ".join(enabled))
        else:
            logger.info("lab posture: hardened baseline (no vuln flags set)")


settings = Settings()
