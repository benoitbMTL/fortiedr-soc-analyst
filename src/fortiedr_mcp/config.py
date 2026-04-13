from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from fortiedr_mcp.errors import FortiEDRConfigurationError


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    raise FortiEDRConfigurationError(
        "FORTIEDR_VERIFY_SSL must be one of true/false, yes/no, on/off, or 1/0."
    )


def _normalize_host(host: str) -> str:
    raw = host.strip()
    if not raw:
        raise FortiEDRConfigurationError("FORTIEDR_HOST is required.")

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.hostname:
        raise FortiEDRConfigurationError("FORTIEDR_HOST must be a hostname or HTTPS URL.")

    return parsed.hostname


@dataclass(frozen=True)
class FortiEDRConfig:
    host: str
    user: str
    password: str
    organization: str | None
    verify_ssl: bool
    timeout_seconds: float

    @property
    def base_url(self) -> str:
        return f"https://{self.host}"

    @classmethod
    def from_values(
        cls,
        *,
        host: str,
        user: str,
        password: str,
        organization: str | None,
        verify_ssl: bool = True,
        timeout_seconds: float = 30,
    ) -> "FortiEDRConfig":
        if not user or not user.strip():
            raise FortiEDRConfigurationError("FORTIEDR_USER is required.")
        if not password:
            raise FortiEDRConfigurationError("FORTIEDR_PASS is required.")
        if timeout_seconds <= 0:
            raise FortiEDRConfigurationError(
                "FORTIEDR_TIMEOUT_SECONDS must be greater than zero."
            )

        return cls(
            host=_normalize_host(host),
            user=user.strip(),
            password=password,
            organization=organization.strip() if organization else None,
            verify_ssl=verify_ssl,
            timeout_seconds=timeout_seconds,
        )

    @classmethod
    def from_env(cls) -> "FortiEDRConfig":
        project_root = Path(__file__).resolve().parents[2]
        dotenv_path = project_root / ".env"
        if dotenv_path.exists():
            load_dotenv(dotenv_path, override=False)

        user = os.getenv("FORTIEDR_USER") or os.getenv("FORTIEDR_API_USER")
        password = os.getenv("FORTIEDR_PASS") or os.getenv("FORTIEDR_API_PASSWORD")
        host = os.getenv("FORTIEDR_HOST")
        organization = os.getenv("FORTIEDR_ORG")

        missing = []
        if not user:
            missing.append("FORTIEDR_USER or FORTIEDR_API_USER")
        if not password:
            missing.append("FORTIEDR_PASS or FORTIEDR_API_PASSWORD")
        if not host:
            missing.append("FORTIEDR_HOST")

        if missing:
            raise FortiEDRConfigurationError(
                "Missing required environment variables: " + ", ".join(missing)
            )

        timeout_raw = os.getenv("FORTIEDR_TIMEOUT_SECONDS", "30").strip()
        try:
            timeout_seconds = float(timeout_raw)
        except ValueError as exc:
            raise FortiEDRConfigurationError(
                "FORTIEDR_TIMEOUT_SECONDS must be a number."
            ) from exc

        if timeout_seconds <= 0:
            raise FortiEDRConfigurationError(
                "FORTIEDR_TIMEOUT_SECONDS must be greater than zero."
            )

        return cls.from_values(
            host=host,
            user=user,
            password=password,
            organization=organization,
            verify_ssl=_parse_bool(os.getenv("FORTIEDR_VERIFY_SSL"), default=True),
            timeout_seconds=timeout_seconds,
        )
