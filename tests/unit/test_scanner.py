"""End-to-end pipeline wiring tests for `scan_host`/`scan_hosts`.

Exercises every `HostScanStatus` branch. The OK-path test uses a real local
mock TLS server (reusing the same pattern as test_tls_client.py) with
`resolve_and_validate` monkeypatched to point at it directly — real loopback
resolution is legitimately rejected by network_guard, so this substitution
is what lets an otherwise-real pipeline (real handshake, real chain
retrieval, real M1 parsing) run end-to-end in a test. Every other branch is
reached by monkeypatching whichever stage should fail, so each status is
tested in isolation without needing a real broken/unreachable network peer.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import socket
import ssl
import tempfile
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.core.config import Settings
from app.scanning import scanner as scanner_module
from app.scanning.network_guard import (
    DisallowedAddressError,
    ResolutionError,
    ValidatedTarget,
)
from app.scanning.scanner import HostScanStatus, scan_host, scan_hosts
from app.scanning.tls_client import HandshakeError


def _settings(**overrides) -> Settings:
    return Settings(**overrides)


# --- DISALLOWED_PORT / DISALLOWED_ADDRESS / RESOLUTION_FAILED: no real I/O ---


@pytest.mark.asyncio
async def test_disallowed_port_short_circuits_before_resolution(monkeypatch):
    called = False

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("resolve_and_validate must not run for a disallowed port")

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _fail_if_called)
    outcome = await scan_host("example.com", 22, _settings())
    assert outcome.status == HostScanStatus.DISALLOWED_PORT
    assert called is False


@pytest.mark.asyncio
async def test_disallowed_address_outcome(monkeypatch):
    async def _raise(*args, **kwargs):
        raise DisallowedAddressError("blocked")

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _raise)
    outcome = await scan_host("example.com", 443, _settings())
    assert outcome.status == HostScanStatus.DISALLOWED_ADDRESS


@pytest.mark.asyncio
async def test_resolution_failed_outcome(monkeypatch):
    async def _raise(*args, **kwargs):
        raise ResolutionError("nxdomain")

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _raise)
    outcome = await scan_host("example.com", 443, _settings())
    assert outcome.status == HostScanStatus.RESOLUTION_FAILED


@pytest.mark.asyncio
async def test_handshake_failed_outcome(monkeypatch):
    async def _fake_resolve(hostname, port):
        return ValidatedTarget(
            hostname=hostname, port=port, addresses=(ipaddress.ip_address("8.8.8.8"),)
        )

    async def _raise(*args, **kwargs):
        raise HandshakeError("no route")

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _fake_resolve)
    monkeypatch.setattr(scanner_module, "perform_tls_handshake", _raise)
    outcome = await scan_host("example.com", 443, _settings())
    assert outcome.status == HostScanStatus.HANDSHAKE_FAILED


@pytest.mark.asyncio
async def test_parse_failed_outcome(monkeypatch):
    from app.scanning.tls_client import TlsHandshakeResult

    async def _fake_resolve(hostname, port):
        return ValidatedTarget(
            hostname=hostname, port=port, addresses=(ipaddress.ip_address("8.8.8.8"),)
        )

    async def _fake_handshake(*args, **kwargs):
        return TlsHandshakeResult(
            hostname="example.com",
            port=443,
            connected_ip="8.8.8.8",
            pem_chain=[b"not a real certificate"],
            tls_version="TLSv1.3",
            handshake_duration_seconds=0.01,
        )

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _fake_resolve)
    monkeypatch.setattr(scanner_module, "perform_tls_handshake", _fake_handshake)
    outcome = await scan_host("example.com", 443, _settings())
    assert outcome.status == HostScanStatus.PARSE_FAILED


# --- OK path: real handshake + real parsing against a local mock server ---


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(subject_cn, issuer_cn, subject_key, issuer_key, *, is_ca, sans=None):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture
def mock_tls_server():
    hostname = "scanner-mock.example.com"
    intermediate_key = _make_key()
    leaf_key = _make_key()
    intermediate_cert = _make_cert(
        "Mock Intermediate CA", "Mock Root CA", intermediate_key, intermediate_key, is_ca=True
    )
    leaf_cert = _make_cert(
        hostname, "Mock Intermediate CA", leaf_key, intermediate_key, is_ca=False, sans=[hostname]
    )
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    intermediate_cert_pem = intermediate_cert.public_bytes(serialization.Encoding.PEM)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    stop = False

    def _serve():
        with (
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_file,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as chain_file,
        ):
            key_file.write(leaf_key_pem)
            key_file.flush()
            chain_file.write(leaf_cert_pem + intermediate_cert_pem)
            chain_file.flush()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=chain_file.name, keyfile=key_file.name)
        sock.settimeout(0.5)
        while not stop:
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
                tls_conn.close()
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    yield hostname, port
    stop = True
    thread.join(timeout=2)
    sock.close()


@pytest.mark.asyncio
async def test_ok_path_end_to_end(monkeypatch, mock_tls_server):
    hostname, port = mock_tls_server

    async def _fake_resolve(hostname_arg, port_arg):
        return ValidatedTarget(
            hostname=hostname_arg, port=port_arg, addresses=(ipaddress.ip_address("127.0.0.1"),)
        )

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _fake_resolve)
    # The mock server binds an ephemeral port, so it must be added to the
    # allowlist for this test alone — the allowlist mechanism itself is
    # network_guard's job and is covered by test_network_guard.py.
    settings = _settings(ALLOWED_SCAN_PORTS=str(port))
    outcome = await scan_host(hostname, port, settings)
    assert outcome.status == HostScanStatus.OK
    assert outcome.certificate is not None
    assert outcome.certificate.hostname_mismatch is False


# --- Concurrency / timeout behavior (Section 19) ---


@pytest.mark.asyncio
async def test_global_semaphore_is_a_process_wide_singleton():
    from app.scanning.scanner import _global_semaphore

    first = _global_semaphore(7)
    second = _global_semaphore(7)
    assert first is second


@pytest.mark.asyncio
async def test_scan_hosts_safety_net_timeout_marks_pending_as_handshake_failed(monkeypatch):
    async def _hang_forever(*args, **kwargs):
        await asyncio.sleep(10)

    async def _fake_resolve(hostname_arg, port_arg):
        return ValidatedTarget(
            hostname=hostname_arg, port=port_arg, addresses=(ipaddress.ip_address("8.8.8.8"),)
        )

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _fake_resolve)
    monkeypatch.setattr(scanner_module, "perform_tls_handshake", _hang_forever)

    settings = _settings(SCAN_TOTAL_TIMEOUT_SECONDS=0)
    outcomes = await scan_hosts([("slow.example.com", 443)], settings)
    assert len(outcomes) == 1
    assert outcomes[0].status == HostScanStatus.HANDSHAKE_FAILED
    assert "safety-net" in (outcomes[0].detail or "")


@pytest.mark.asyncio
async def test_scan_hosts_bounds_concurrency_per_scan(monkeypatch):
    """A per-scan cap of 1 forces every host through one at a time —
    verified by tracking the maximum number of simultaneously in-flight
    calls to the (stubbed) resolve step."""
    in_flight = 0
    max_in_flight = 0
    lock = asyncio.Lock()

    async def _tracked_resolve(hostname_arg, port_arg):
        nonlocal in_flight, max_in_flight
        async with lock:
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)
        async with lock:
            in_flight -= 1
        return ValidatedTarget(
            hostname=hostname_arg, port=port_arg, addresses=(ipaddress.ip_address("8.8.8.8"),)
        )

    async def _fail_handshake(*args, **kwargs):
        raise HandshakeError("stub: no real handshake in this test")

    monkeypatch.setattr(scanner_module, "resolve_and_validate", _tracked_resolve)
    monkeypatch.setattr(scanner_module, "perform_tls_handshake", _fail_handshake)

    settings = _settings(
        SCAN_CONCURRENCY_PER_SCAN=1, SCAN_CONCURRENCY_GLOBAL=100, SCAN_TOTAL_TIMEOUT_SECONDS=30
    )
    hosts = [(f"host{i}.example.com", 443) for i in range(4)]
    outcomes = await scan_hosts(hosts, settings)
    assert len(outcomes) == 4
    assert all(o.status == HostScanStatus.HANDSHAKE_FAILED for o in outcomes)
    assert max_in_flight == 1
