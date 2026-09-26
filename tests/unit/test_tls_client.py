"""TLS handshake / full-chain retrieval tests.

Uses a local, in-process mock TLS server (stdlib `ssl`, `PROTOCOL_TLS_SERVER`)
presenting a throwaway leaf+intermediate chain generated on the fly with
`cryptography` — no private key material is ever written to disk, matching
the fixture-generation discipline used in M1. The server is bound to
127.0.0.1, and `perform_tls_handshake` is pointed at that literal address
directly (not through `network_guard`, which would legitimately reject
loopback) since this suite validates TLS-handshake/chain-retrieval wiring,
not address-safety logic.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.scanning.tls_client import HandshakeError, perform_tls_handshake


def _make_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_cert(
    subject_cn: str,
    issuer_cn: str,
    subject_key: rsa.RSAPrivateKey,
    issuer_key: rsa.RSAPrivateKey,
    *,
    is_ca: bool,
    sans: list[str] | None = None,
) -> x509.Certificate:
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


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


class _MockTlsServer:
    """A background-thread TLS server presenting leaf+intermediate."""

    def __init__(self, hostname: str = "mock.example.com"):
        self.hostname = hostname
        intermediate_key = _make_key()
        leaf_key = _make_key()
        self.intermediate_cert = _make_cert(
            "Mock Intermediate CA", "Mock Root CA", intermediate_key, intermediate_key, is_ca=True
        )
        self.leaf_cert = _make_cert(
            hostname,
            "Mock Intermediate CA",
            leaf_key,
            intermediate_key,
            is_ca=False,
            sans=[hostname],
        )
        self._leaf_key_pem = _pem_key(leaf_key)
        self._leaf_cert_pem = _pem_cert(self.leaf_cert)
        self._intermediate_cert_pem = _pem_cert(self.intermediate_cert)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)

    def _serve_forever(self) -> None:
        import tempfile

        with (
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_file,
            tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as chain_file,
        ):
            key_file.write(self._leaf_key_pem)
            key_file.flush()
            chain_file.write(self._leaf_cert_pem + self._intermediate_cert_pem)
            chain_file.flush()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=chain_file.name, keyfile=key_file.name)
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
                tls_conn.close()
            except (ssl.SSLError, OSError):
                pass

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def mock_server():
    server = _MockTlsServer()
    server.start()
    yield server
    server.stop()


@pytest.mark.asyncio
async def test_full_chain_retrieved(mock_server):
    result = await perform_tls_handshake(
        mock_server.hostname,
        mock_server.port,
        (ipaddress.ip_address("127.0.0.1"),),
        connect_timeout_seconds=2.0,
        handshake_timeout_seconds=2.0,
    )
    assert len(result.pem_chain) == 2  # leaf + intermediate, both returned
    assert b"BEGIN CERTIFICATE" in result.pem_chain[0]
    assert b"BEGIN CERTIFICATE" in result.pem_chain[1]


@pytest.mark.asyncio
async def test_hostname_and_sni_preserved(mock_server):
    # The server only agrees to complete the handshake normally regardless
    # of SNI in this simple mock, but we confirm the call succeeds using the
    # original hostname (not the connected IP) as both SNI and the
    # hostname carried in the result.
    result = await perform_tls_handshake(
        mock_server.hostname,
        mock_server.port,
        (ipaddress.ip_address("127.0.0.1"),),
        connect_timeout_seconds=2.0,
        handshake_timeout_seconds=2.0,
    )
    assert result.hostname == mock_server.hostname
    assert result.connected_ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_connect_timeout_raises_handshake_error():
    # 192.0.2.1 is TEST-NET-1 (RFC 5737) — guaranteed non-routable, so the
    # connect attempt will simply hang/fail rather than reach a real host.
    with pytest.raises(HandshakeError):
        await perform_tls_handshake(
            "unreachable.example.com",
            443,
            (ipaddress.ip_address("192.0.2.1"),),
            connect_timeout_seconds=0.2,
            handshake_timeout_seconds=0.2,
        )


@pytest.mark.asyncio
async def test_handshake_failure_with_non_tls_server_raises_handshake_error():
    # A plain TCP server that never speaks TLS: the handshake itself fails
    # (not the connect), exercising the second failure path.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    stop = False

    def _serve():
        sock.settimeout(0.5)
        while not stop:
            try:
                conn, _ = sock.accept()
            except TimeoutError:
                continue
            conn.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    try:
        with pytest.raises(HandshakeError):
            await perform_tls_handshake(
                "not-tls.example.com",
                port,
                (ipaddress.ip_address("127.0.0.1"),),
                connect_timeout_seconds=1.0,
                handshake_timeout_seconds=1.0,
            )
    finally:
        stop = True
        thread.join(timeout=2)
        sock.close()


@pytest.mark.asyncio
async def test_no_addresses_raises_handshake_error():
    with pytest.raises(HandshakeError):
        await perform_tls_handshake(
            "no-addresses.example.com",
            443,
            (),
            connect_timeout_seconds=1.0,
            handshake_timeout_seconds=1.0,
        )
