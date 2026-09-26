"""TLS handshake and certificate-chain retrieval — owned by M2.

Implements Section 7 (TLS/certificate discovery) and Section 6's
"SNI/hostname preserved" control. Connects ONLY to an address already
validated by `app.scanning.network_guard.resolve_and_validate` — this
module never resolves or validates addresses itself; address-safety logic
lives in exactly one place (network_guard), never duplicated here.

Certificate verification is intentionally NOT enforced at the TLS layer
(`SSL.VERIFY_NONE`): CertWatch's own two-pass validator
(`app.parsing.certificate_parser`) is the sole source of truth for chain
trust, including the private/internal-CA case that a strict OpenSSL
verify would simply refuse to complete a handshake for at all. This
module's only job is retrieving the certificate chain exactly as the
server presented it — undecided about trust.

Implementation note (recorded in the Decision Log): Python's stdlib `ssl`
module has no public API in this Python version to retrieve the FULL
peer certificate chain (leaf + intermediates) — `SSLSocket.getpeercert()`
returns the leaf only. `pyOpenSSL` is used here specifically because it
exposes OpenSSL's `SSL_get_peer_cert_chain()` via
`SSL.Connection.get_peer_cert_chain()`, which does return the complete
presented chain. pyOpenSSL's OpenSSL bindings are synchronous; the
blocking handshake runs in a thread executor so it doesn't block the
event loop, while `asyncio.wait_for` still enforces the overall per-host
time budget (Section 19).
"""

from __future__ import annotations

import asyncio
import select
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from OpenSSL import SSL, crypto

from app.scanning.network_guard import IPAddress

_T = TypeVar("_T")


class HandshakeError(Exception):
    """A TCP connection or TLS handshake failed or timed out on every
    validated address.

    An ordinary scan-result finding ("could not talk to this host at
    all"), not a bug — callers should record this as a finding, never let
    it crash a batch scan.
    """


def _run_ssl_op(raw_sock: socket.socket, deadline: float, op: Callable[[], _T]) -> _T:
    """Run a pyOpenSSL operation, retrying through WantReadError/WantWriteError
    until it completes or `deadline` (a `time.monotonic()` timestamp) passes.

    Discovered empirically while writing this module's tests (recorded in
    the Decision Log): a Python socket with `settimeout(x)` set (x not
    None/0) is "blocking with a timeout" at the Python socket-module level,
    which Python implements internally via a non-blocking fd plus its own
    retry-on-EAGAIN loop — but pyOpenSSL's `SSL.Connection` talks to the fd
    directly through OpenSSL's BIO layer, bypassing that retry entirely. The
    raw socket must be non-blocking (`setblocking(False)`) for the duration
    of the handshake, and this helper supplies the retry loop Python's
    socket module would otherwise have done, using `select.select` bounded
    by the same per-host time budget (Section 19) so a stalled peer still
    times out promptly instead of hanging the executor thread.
    """
    while True:
        try:
            return op()
        except SSL.WantReadError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for socket to become readable") from None
            ready, _, _ = select.select([raw_sock], [], [], remaining)
            if not ready:
                raise TimeoutError("timed out waiting for socket to become readable") from None
        except SSL.WantWriteError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for socket to become writable") from None
            _, ready, _ = select.select([], [raw_sock], [], remaining)
            if not ready:
                raise TimeoutError("timed out waiting for socket to become writable") from None


@dataclass(frozen=True)
class TlsHandshakeResult:
    """What Section 3/7 needs from a completed TLS handshake."""

    hostname: str
    port: int
    connected_ip: str
    pem_chain: list[bytes]
    tls_version: str
    handshake_duration_seconds: float


def _do_handshake_sync(
    ip: IPAddress,
    port: int,
    hostname: str,
    connect_timeout_seconds: float,
    handshake_timeout_seconds: float,
) -> TlsHandshakeResult:
    """Blocking implementation; always run via `loop.run_in_executor`.

    pyOpenSSL/OpenSSL bindings have no asyncio-native API, so the
    handshake itself is synchronous — the enclosing coroutine
    (`perform_tls_handshake`) is what makes this non-blocking for the
    rest of the application and enforces the overall time budget.
    """
    started = time.monotonic()
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    raw_sock = socket.socket(family, socket.SOCK_STREAM)
    raw_sock.settimeout(connect_timeout_seconds)
    try:
        # Connect to the validated IP LITERAL, never to `hostname` — this
        # is what makes resolve-once-connect-to-pinned-IP (Section 6)
        # actually hold: nothing here can trigger a second DNS lookup.
        raw_sock.connect((str(ip), port))
    except OSError as exc:
        raw_sock.close()
        raise HandshakeError(f"TCP connect to {ip}:{port} failed: {exc}") from exc

    # Non-blocking for the handshake itself — see _run_ssl_op's docstring
    # for why: pyOpenSSL needs to observe WantReadError/WantWriteError and
    # retry them itself, which only happens on a genuinely non-blocking fd.
    raw_sock.setblocking(False)
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE)
    conn = SSL.Connection(context, raw_sock)
    # SNI and the certificate-hostname-verification target are both the
    # ORIGINAL submitted hostname, even though the socket connected to an
    # IP literal (Section 6: "SNI/hostname preserved"). Hostname/SAN
    # matching itself happens later, in app.parsing (M1) — not here.
    conn.set_tlsext_host_name(hostname.encode("idna", errors="strict"))
    conn.set_connect_state()
    deadline = time.monotonic() + handshake_timeout_seconds
    try:
        _run_ssl_op(raw_sock, deadline, conn.do_handshake)
    except (SSL.Error, OSError, TimeoutError) as exc:
        raw_sock.close()
        raise HandshakeError(
            f"TLS handshake with {hostname!r} ({ip}:{port}) failed: {exc}"
        ) from exc

    chain = conn.get_peer_cert_chain()
    if not chain:
        conn.close()
        raise HandshakeError(f"{hostname!r} ({ip}:{port}) presented no certificate chain")

    pem_chain = [crypto.dump_certificate(crypto.FILETYPE_PEM, cert) for cert in chain]
    tls_version = conn.get_protocol_version_name()
    conn.close()

    return TlsHandshakeResult(
        hostname=hostname,
        port=port,
        connected_ip=str(ip),
        pem_chain=pem_chain,
        tls_version=tls_version,
        handshake_duration_seconds=time.monotonic() - started,
    )


async def perform_tls_handshake(
    hostname: str,
    port: int,
    addresses: tuple[IPAddress, ...],
    *,
    connect_timeout_seconds: float,
    handshake_timeout_seconds: float,
) -> TlsHandshakeResult:
    """Complete a TLS handshake against one of `addresses`, never re-resolving.

    `addresses` must come from `network_guard.resolve_and_validate` — every
    entry has already been validated safe. Tries each address in order
    (for hosts with multiple A/AAAA records) until one succeeds; raises
    `HandshakeError` only if none do.
    """
    if not addresses:
        raise HandshakeError(f"no validated addresses to connect to for {hostname!r}")

    loop = asyncio.get_running_loop()
    total_timeout = connect_timeout_seconds + handshake_timeout_seconds
    last_error: Exception | None = None
    for ip in addresses:
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    _do_handshake_sync,
                    ip,
                    port,
                    hostname,
                    connect_timeout_seconds,
                    handshake_timeout_seconds,
                ),
                timeout=total_timeout,
            )
        except (HandshakeError, TimeoutError) as exc:
            last_error = exc
            continue

    raise HandshakeError(
        f"could not complete a TLS handshake with {hostname!r} on any resolved address"
    ) from last_error
