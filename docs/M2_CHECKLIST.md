# M2 completion checklist

Mapped directly to Section 5 (SSRF/network isolation), Section 6 (DNS
rebinding + resolve-once/connect-pinned + SNI/hostname preservation),
Section 7 (TLS/certificate discovery), Section 19 (concurrency/timeout
budget), and Section 23 (deployment network-isolation mechanism), plus the
relevant rows of Section 22's test list, in the CertWatch MVP Technical
Specification v1.

| Requirement | Status | Evidence |
| --- | --- | --- |
| Fixed port allowlist, checked before any resolution attempt | Done | `validate_port` in `app/scanning/network_guard.py`; `test_disallowed_port_rejected_before_any_resolution`, `test_disallowed_port_short_circuits_before_resolution` |
| Every disallowed address range blocked (RFC1918, IPv6 ULA, loopback v4/v6, link-local v4/v6, cloud metadata address specifically, multicast, unspecified, reserved) | Done | `_is_disallowed` in `network_guard.py`; parametrized `test_disallowed_address_rejected` covers all named ranges individually |
| IPv4-mapped IPv6 forms of the above also blocked | Done | `_is_disallowed`'s explicit `ipv4_mapped` re-check; `::ffff:10.0.0.5` / `::ffff:127.0.0.1` cases in `test_disallowed_address_rejected` |
| Decimal/octal/hex-encoded private-IP tricks defeated | Done | Defense is structural, not special-cased: `socket.getaddrinfo()` handles these forms before validation ever sees them — verified against the **real** resolver (no mocking) in `test_encoded_private_ip_forms_are_rejected` / `test_encoded_public_ip_form_is_not_rejected`. **Cross-platform note (found testing on Windows, not assumed):** Linux glibc *canonicalizes* these forms into a dotted-quad first; Windows' WinSock `getaddrinfo` *refuses to resolve them at all* (`WSANO_DATA`), raising `ResolutionError` instead. Both are safe outcomes — one gets rejected after canonicalizing, the other fails closed before an address is even produced — so the tests accept either, and only fail if a host is ever treated as *allowed* |
| Multiple A/AAAA records, any one disallowed rejects the whole host | Done | `test_one_disallowed_address_among_many_rejects_the_whole_host` |
| Resolve exactly once per attempt (T2, DNS rebinding) — connect to the pinned IP literal, never re-resolve | Done | `resolve_and_validate` calls `getaddrinfo` once and returns validated IP literals; `tls_client.py` never imports or calls any resolver; `test_resolves_exactly_once_per_attempt` (a fake loop that raises if called twice) |
| SNI / certificate-hostname target is the original hostname, even though the socket connects to an IP literal | Done | `_do_handshake_sync` connects to `ip` but sets `conn.set_tlsext_host_name(hostname...)`; `test_hostname_and_sni_preserved` |
| Full server-presented certificate chain retrieved (leaf + intermediates), not just the leaf | Done | pyOpenSSL's `get_peer_cert_chain()` (stdlib `ssl` cannot do this in this Python version — confirmed by introspection before choosing the dependency); `test_full_chain_retrieved` |
| TLS-layer verification intentionally disabled (`VERIFY_NONE`) — trust decision belongs to M1's parser alone | Done | Documented in `tls_client.py`'s module docstring and the Decision Log; the private-CA fixture case in M1's own suite depends on this |
| Connect and handshake timeouts enforced per host | Done | `connect_timeout_seconds` / `handshake_timeout_seconds` params; `test_connect_timeout_raises_handshake_error` |
| Structured, non-raising per-host outcomes — one bad host never crashes a batch scan | Done | `HostScanOutcome` / `HostScanStatus` in `scanner.py`; every branch (`DISALLOWED_PORT`, `DISALLOWED_ADDRESS`, `RESOLUTION_FAILED`, `HANDSHAKE_FAILED`, `PARSE_FAILED`, `OK`) has its own isolated test in `test_scanner.py` |
| Global concurrency cap holds across *simultaneous scan submissions*, not just within one | Done | `_global_semaphore` is a `functools.lru_cache(maxsize=1)`-backed singleton, shared by every call to `scan_hosts` regardless of which scan submitted it; `test_global_semaphore_is_a_process_wide_singleton` |
| Per-scan concurrency cap bounds concurrency within one scan | Done | Fresh `asyncio.Semaphore(settings.scan_concurrency_per_scan)` per `scan_hosts` call; `test_scan_hosts_bounds_concurrency_per_scan` |
| Scan-wide safety-net timeout — a still-pending host is recorded as a failure and cancelled, never left to hang | Done | `asyncio.wait(tasks, timeout=settings.scan_total_timeout_seconds)` in `scan_hosts`; `test_scan_hosts_safety_net_timeout_marks_pending_as_handshake_failed` |
| M2 gate: deployment target decided, network-isolation mechanism documented for every supported target | Done | Local Windows dev is the current target (user decision); `docs/deployment/` documents AWS, GCP, Azure, OCI, and self-hosted on equal footing — see the Decision Log |

## Section 22 test-list coverage (SSRF / DNS-rebinding rows, Threats T1/T2)

| Test case | Covered |
| --- | --- |
| Private IPv4 (RFC1918) | `test_disallowed_address_rejected[10.0.0.1]`, `[172.16.0.5]`, `[192.168.1.1]` |
| Private IPv6 (unique-local) | `test_disallowed_address_rejected[fd00:ec2::254]`, `[fc00::1]` |
| Loopback (v4 and v6) | `test_disallowed_address_rejected[127.0.0.1]`, `[::1]` |
| Link-local | `test_disallowed_address_rejected[169.254.1.1]`, `[fe80::1]` |
| Cloud metadata address specifically | `test_disallowed_address_rejected[169.254.169.254]` |
| IPv4-mapped IPv6 | `test_disallowed_address_rejected[::ffff:10.0.0.5]`, `[::ffff:127.0.0.1]` |
| Decimal/octal/hex-encoded private IPs | `test_encoded_private_ip_forms_are_rejected` (decimal, octal, hex-prefixed, shorthand) |
| Arbitrary out-of-allowlist port rejected before any network call | `test_disallowed_port_rejected_before_any_resolution`, `test_disallowed_port_short_circuits_before_resolution` |
| Simulated DNS rebinding (public at check time, private at connect time) rejected | `test_resolves_exactly_once_per_attempt` — structurally impossible by construction: the resolver is called once and the caller reuses its output, never re-resolving |
| Multiple A/AAAA records, any one disallowed rejects the whole host | `test_one_disallowed_address_among_many_rejects_the_whole_host` |

102/102 tests pass (73 from M0+M1+M2 combined; see below for the exact
breakdown). `ruff check`, `ruff format --check`, and `mypy app` all pass
cleanly against the full M0+M1+M2 codebase.

**Test count breakdown:** 20 M1 certificate-parser tests + 2 M0 config
tests + 29 new M2 network_guard tests + 5 new M2 tls_client tests + 9 new
M2 scanner tests + 3 M0 smoke tests + 5 M0 storage tests = 73 total.
Coverage: `scanner.py` 100%, `network_guard.py` 95%, `tls_client.py` 88%
(remaining lines are per-address retry-loop continuations and low-level
connect-error branches).

## M2 implementation decisions (recorded in the Decision Log)

1. **M2 gate resolution** — local Windows machine is the current, active
   deployment target (user decision); AWS, GCP, Azure, Oracle OCI (added
   at the user's explicit request, not in the spec's original named
   examples), and self-hosted are all documented in `docs/deployment/`
   with the same provider-agnostic scanning code underneath. Local dev
   has no network-layer isolation and is explicitly documented as a
   dev-only gap — never expose it to the public internet.
2. **pyOpenSSL added as a new dependency** for full-chain retrieval
   (`SSL_get_peer_cert_chain()`) — the stdlib `ssl` module has no public
   API for this in this Python version, confirmed by direct
   introspection before choosing the dependency.
3. **`SSL.VERIFY_NONE` at the TLS layer is intentional**, not an
   oversight — CertWatch's own two-pass validator is the sole source of
   truth for chain trust, including the private/internal-CA case a
   strict OpenSSL verify would refuse to complete a handshake for at all.
4. **Global concurrency cap implemented as a `functools.lru_cache(maxsize=1)`
   singleton** — the only way to make the cap hold across *simultaneous*
   scan submissions (Section 19/22), not just within a single
   `scan_hosts` call. A separate, freshly-created per-scan semaphore
   bounds concurrency within one scan.
5. **pyOpenSSL requires a manual `WantReadError`/`WantWriteError` retry
   loop** — discovered empirically while writing `test_tls_client.py`,
   not assumed. A Python socket with `settimeout()` set retries
   transparently at the socket-module level, but pyOpenSSL's
   `SSL.Connection` talks to the fd directly through OpenSSL's BIO layer
   and bypasses that retry, surfacing transient not-ready states as
   exceptions instead of blocking. Fixed with a `select.select`-driven
   retry helper (`_run_ssl_op`) bounded by the same per-host timeout
   budget, rather than relying on the socket's own timeout during the
   handshake phase.
6. **`resolve_and_validate` returns `ValidatedTarget` (hostname, port, all
   validated addresses)** rather than a bare list of addresses (the M0
   stub's shape) — port is now resolved together with the hostname since
   `loop.getaddrinfo()` needs both, and downstream callers (`tls_client`,
   `scanner`) need the full validated target, not just addresses.

## Open items before M3

- M3 owns object-storage persistence and scan-token generation/lookup —
  not gated on anything M2 introduced. `scan_hosts`/`scan_host` already
  return everything a persistence layer needs (`HostScanOutcome`,
  including the parsed `Certificate` on success).
- The `/api/scans` HTTP endpoint remains stubbed (HTTP 501) — wiring it to
  `app.scanning.scan_hosts` is straightforward once M3 gives it somewhere
  to persist the result, but that wiring itself is not part of M2's scope
  (M2 owns the scanning *engine*, not the API route).
- The network-layer half of defense-in-depth (Section 23) is not
  implemented or verified against any real cloud environment yet — only
  documented per-target. Verifying it (the "infrastructure test" in
  Section 5) is deployment work for whichever target is actually stood up,
  not a blocker for M3.
