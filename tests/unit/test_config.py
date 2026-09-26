"""Verify Settings defaults match technical specification Section 24 exactly.

If any of these assertions ever needs to change, Section 24 and the Decision
Log must change first — this test is a guard against the numbers silently
drifting apart from the spec, not the other way around.
"""

from __future__ import annotations

from app.core.config import Settings


def test_settings_defaults_match_section_24() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]

    assert settings.max_hosts_per_scan == 250
    assert settings.scan_connect_timeout_seconds == 3.0
    assert settings.scan_handshake_timeout_seconds == 2.0
    assert settings.scan_concurrency_per_scan == 15
    assert settings.scan_concurrency_global == 100
    assert settings.scan_total_timeout_seconds == 180
    assert settings.submit_rate_limit_per_ip_per_hour == 5
    assert settings.ask_rate_limit_per_scan == 20
    assert settings.ask_rate_limit_per_ip_per_hour == 60
    assert settings.allowed_scan_ports == frozenset({443, 8443, 993, 995})
    assert settings.default_retention_days == 90
    assert settings.object_storage_backend == "local"


def test_allowed_scan_ports_parses_csv_env_value() -> None:
    settings = Settings(_env_file=None, ALLOWED_SCAN_PORTS="443,9443")  # type: ignore[call-arg]
    assert settings.allowed_scan_ports == frozenset({443, 9443})
