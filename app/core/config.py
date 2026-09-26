"""CertWatch server-side configuration.

Every value here corresponds directly to a row in the CertWatch MVP Technical
Specification v1, Section 24 ("Environment/secrets configuration"). Nothing in
this module is client-controlled: scan requests, host lists, and API calls
read these limits but never set them.

Defaults match the specification's stated initial design targets (Section 19,
Section 24, Section 28 open decision #4) and are not yet empirically load-tested —
they are deliberately easy to override via environment variables so they can be
tuned after real usage (M9) without a code change.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Server-side configuration, loaded from environment variables / .env.

    Field names intentionally mirror the specification's Section 24 table so a
    reviewer can check this module against that section directly.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application identity ---
    app_name: str = "CertWatch"
    environment: str = Field(default="development")  # "development" | "production"

    # --- Scan submission limits (Section 18, Section 24) ---
    max_hosts_per_scan: int = Field(default=250, alias="MAX_HOSTS_PER_SCAN")
    submit_rate_limit_per_ip_per_hour: int = Field(
        default=5, alias="SUBMIT_RATE_LIMIT_PER_IP_PER_HOUR"
    )

    # --- Network/scanning timeouts and concurrency (Section 19, Section 24) ---
    # NOTE: these values are consumed by app.scanning, which is not implemented
    # until M2. They are declared here now so M2 has no config-layer work to do.
    scan_connect_timeout_seconds: float = Field(default=3.0, alias="SCAN_CONNECT_TIMEOUT_SECONDS")
    scan_handshake_timeout_seconds: float = Field(
        default=2.0, alias="SCAN_HANDSHAKE_TIMEOUT_SECONDS"
    )
    scan_concurrency_per_scan: int = Field(default=15, alias="SCAN_CONCURRENCY_PER_SCAN")
    scan_concurrency_global: int = Field(default=100, alias="SCAN_CONCURRENCY_GLOBAL")
    scan_total_timeout_seconds: int = Field(default=180, alias="SCAN_TOTAL_TIMEOUT_SECONDS")

    # --- Allowed scan ports (Section 5: fixed allowlist, never arbitrary) ---
    allowed_scan_ports_raw: str = Field(default="443,8443,993,995", alias="ALLOWED_SCAN_PORTS")

    @property
    def allowed_scan_ports(self) -> frozenset[int]:
        return frozenset(
            int(p.strip()) for p in self.allowed_scan_ports_raw.split(",") if p.strip()
        )

    # --- AI / /ask rate limits and cost controls (Section 17, Section 18) ---
    ask_rate_limit_per_scan: int = Field(default=20, alias="ASK_RATE_LIMIT_PER_SCAN")
    ask_rate_limit_per_ip_per_hour: int = Field(default=60, alias="ASK_RATE_LIMIT_PER_IP_PER_HOUR")
    llm_api_key: str | None = Field(default=None, alias="LLM_API_KEY")
    ai_enabled_by_default: bool = Field(default=True, alias="AI_ENABLED_BY_DEFAULT")

    # --- Data retention (Section 21, Section 28 open decision #5) ---
    default_retention_days: int = Field(default=90, alias="DEFAULT_RETENTION_DAYS")

    # --- Object storage (Section 11) ---
    # "local" is the only backend implemented at M0/M3 for development; cloud backends
    # (s3 / azure_blob / r2) are selected at the M2 gate per the Decision Log and are
    # not implemented yet — selecting one here before then is a config-only placeholder.
    object_storage_backend: str = Field(default="local", alias="OBJECT_STORAGE_BACKEND")
    object_storage_local_path: str = Field(
        default="./.data/scans", alias="OBJECT_STORAGE_LOCAL_PATH"
    )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide Settings singleton.

    Cached so environment variables are read once per process; tests override
    this via dependency injection rather than mutating the cache.
    """
    return Settings()
