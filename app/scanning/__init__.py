"""Network discovery and SSRF/DNS-rebinding defense — owned by M2.

NOT IMPLEMENTED YET. This package exists to fix the module boundary so that
M2 has a clear place to land, without any later milestone needing to restructure
the project.

M2 is explicitly gated (technical specification, Section 25 / this milestone plan):
the cloud provider and the Section 23 network-isolation mechanism (subnet routing
isolation, metadata-address block, provider-specific metadata hardening) must be
selected and verified BEFORE any scanner code is written here. Do not add live
TLS-connect or DNS-resolution logic to this package until that gate has been
satisfied and recorded in the Decision Log.

When implemented, this package must provide (Sections 5-7):
    - resolve_and_validate(hostname) -> list[ipaddress.IPv4Address | IPv6Address]
        Resolves once, validates every returned address against the disallowed
        ranges (RFC1918, loopback, link-local incl. cloud metadata, multicast,
        IPv6 ULA, IPv4-mapped IPv6), rejects the whole host if any address is
        disallowed. Uses Python's `ipaddress` module — never string/regex matching.
    - connect_to_pinned_ip(ip, port, sni_hostname) -> ssl.SSLSocket
        Connects to the already-validated IP literal directly (never re-resolves),
        while setting SNI/hostname verification to the original submitted hostname.
    - Port validation against Settings.allowed_scan_ports before any network call.
"""
