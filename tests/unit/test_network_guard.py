"""SSRF / DNS-rebinding tests — Section 22 test list.

`resolve_and_validate` is tested two ways:
  - Against real `socket.getaddrinfo` for IP-literal "hostnames" (decimal,
    octal, hex, shorthand forms) — this needs no network access at all;
    the OS resolver canonicalizes these locally via libc, which is exactly
    the mechanism this module's defense depends on (see the module
    docstring).
  - Against a fake event-loop `getaddrinfo` for every disallowed-range case
    and the simulated-DNS-rebinding case, so these tests are hermetic and
    don't depend on any real DNS record existing.
"""

from __future__ import annotations

import ipaddress

import pytest

from app.scanning.network_guard import (
    DisallowedAddressError,
    DisallowedPortError,
    ResolutionError,
    resolve_and_validate,
    validate_port,
)

ALLOWED_PORTS = frozenset({443, 8443, 993, 995})


class _FakeLoop:
    """A stand-in event loop whose `getaddrinfo` is fully controlled by
    the test, and that fails loudly if called more than once per attempt
    (the DNS-rebinding-defeating behavior under test)."""

    def __init__(
        self, sockaddrs: list[tuple[str, int]] | None = None, raise_: Exception | None = None
    ):
        self._sockaddrs = sockaddrs or []
        self._raise = raise_
        self.call_count = 0

    async def getaddrinfo(self, host, port, type=None, proto=None):  # noqa: A002
        self.call_count += 1
        if self.call_count > 1:
            raise AssertionError("getaddrinfo called more than once for a single attempt")
        if self._raise is not None:
            raise self._raise
        return [(0, 0, 0, "", sockaddr) for sockaddr in self._sockaddrs]


def _patch_loop(monkeypatch, fake_loop: _FakeLoop) -> None:
    monkeypatch.setattr("app.scanning.network_guard.asyncio.get_running_loop", lambda: fake_loop)


# --- Port allowlist (Section 5) ---


def test_allowed_port_passes():
    validate_port(443, ALLOWED_PORTS)  # must not raise


def test_disallowed_port_rejected_before_any_resolution():
    with pytest.raises(DisallowedPortError):
        validate_port(22, ALLOWED_PORTS)


# --- Full-address validation: every disallowed range (Section 5/22) ---


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # RFC1918
        "172.16.0.5",  # RFC1918
        "192.168.1.1",  # RFC1918
        "127.0.0.1",  # loopback v4
        "::1",  # loopback v6
        "169.254.169.254",  # cloud metadata address (v4 link-local)
        "169.254.1.1",  # link-local v4, general
        "fe80::1",  # link-local v6
        "fd00:ec2::254",  # AWS-style IPv6 metadata (unique-local)
        "fc00::1",  # IPv6 unique-local (ULA)
        "0.0.0.0",  # unspecified v4
        "::",  # unspecified v6
        "224.0.0.1",  # multicast v4
        "ff02::1",  # multicast v6
        "::ffff:10.0.0.5",  # IPv4-mapped IPv6, wrapping RFC1918
        "::ffff:127.0.0.1",  # IPv4-mapped IPv6, wrapping loopback
    ],
)
async def test_disallowed_address_rejected(monkeypatch, ip):
    fake_loop = _FakeLoop(sockaddrs=[(ip, 443)])
    _patch_loop(monkeypatch, fake_loop)
    with pytest.raises(DisallowedAddressError):
        await resolve_and_validate("target.example.com", 443)
    assert fake_loop.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
async def test_allowed_public_address_passes(monkeypatch, ip):
    fake_loop = _FakeLoop(sockaddrs=[(ip, 443)])
    _patch_loop(monkeypatch, fake_loop)
    target = await resolve_and_validate("target.example.com", 443)
    assert ipaddress.ip_address(ip) in target.addresses


@pytest.mark.asyncio
async def test_one_disallowed_address_among_many_rejects_the_whole_host(monkeypatch):
    """Multiple A/AAAA records where any one is disallowed rejects the
    whole host (Section 22) — a public-looking first record must not
    let a private second record slip through."""
    fake_loop = _FakeLoop(sockaddrs=[("8.8.8.8", 443), ("10.0.0.1", 443)])
    _patch_loop(monkeypatch, fake_loop)
    with pytest.raises(DisallowedAddressError):
        await resolve_and_validate("target.example.com", 443)


@pytest.mark.asyncio
async def test_resolution_failure_raises_resolution_error(monkeypatch):
    import socket

    fake_loop = _FakeLoop(raise_=socket.gaierror("Name or service not known"))
    _patch_loop(monkeypatch, fake_loop)
    with pytest.raises(ResolutionError):
        await resolve_and_validate("does-not-exist.invalid", 443)


# --- Decimal/octal/hex-encoded private IPs (Section 5/6/22) ---
# These go through the REAL resolver, unmocked: the OS canonicalizes these
# forms to a dotted-quad before our code ever sees them, which is exactly
# the mechanism being tested (see the module docstring).


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "encoded_host",
    [
        "2130706433",  # decimal for 127.0.0.1
        "017700000001",  # octal for 127.0.0.1
        "0x7f.0.0.1",  # hex-prefixed for 127.0.0.1
        "127.1",  # shorthand for 127.0.0.1
    ],
)
async def test_encoded_private_ip_forms_are_rejected(encoded_host):
    with pytest.raises(DisallowedAddressError):
        await resolve_and_validate(encoded_host, 443)


@pytest.mark.asyncio
async def test_encoded_public_ip_form_is_not_rejected():
    # 134744072 == 8.8.8.8 in decimal — a public address, just written oddly.
    target = await resolve_and_validate("134744072", 443)
    assert ipaddress.ip_address("8.8.8.8") in target.addresses


# --- Simulated DNS rebinding (Section 6/22, T2) ---


@pytest.mark.asyncio
async def test_resolves_exactly_once_per_attempt(monkeypatch):
    """The core rebinding defense: resolve_and_validate must never call the
    resolver a second time for one attempt, however the test formulates
    the attack (a public address at check time, private moments later) —
    this is enforced structurally by _FakeLoop raising if called twice."""
    fake_loop = _FakeLoop(sockaddrs=[("8.8.8.8", 443)])
    _patch_loop(monkeypatch, fake_loop)
    target = await resolve_and_validate("rebinding.example.com", 443)
    assert fake_loop.call_count == 1
    assert target.addresses == (ipaddress.ip_address("8.8.8.8"),)
    # A hypothetical second resolution (simulating the rebind) is never
    # triggered by anything in resolve_and_validate's own return value —
    # the caller must reuse target.addresses, never re-resolve.
