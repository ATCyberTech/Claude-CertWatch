"""Network discovery and SSRF/DNS-rebinding defense — owned by M2.

Implemented as of M2. The M2 gate (cloud provider + Section 23
network-isolation mechanism selected and verified before scanner code
runs live) is resolved per the Decision Log: local Windows-machine
development is the current deployment target, with the application-layer
defense (this package) as the only active protection layer — the
network-layer half of the defense-in-depth design (Section 23) is a
deployment-time control with no equivalent on an unconfigured local
machine, so it is documented, not code, and lands per target in
`docs/deployment/`. All five deployment targets named in that decision
(local dev, AWS, GCP, Azure, OCI, self-hosted) are supported by the same
provider-agnostic application code in this package; only the deployment
docs differ.

- `network_guard.py` (Sections 5, 6): resolve-once, validate-every-address,
  reject-the-whole-host-on-any-disallowed-range, connect-to-pinned-IP.
  The single highest-risk component in the product — see its own
  docstring. Never re-resolves after validation (defeats DNS rebinding).
- `tls_client.py` (Section 7): completes the TLS handshake against an
  already-validated address only, retrieves the full presented
  certificate chain (leaf + intermediates) via pyOpenSSL (the stdlib
  `ssl` module cannot retrieve more than the leaf — Decision Log), and
  hands the chain to `app.parsing` (M1) for classification.
- `scanner.py` (Section 3, 19): wires the two together into a per-host
  pipeline that never raises on an ordinary scan failure, and enforces
  the per-scan and global concurrency caps plus the scan-wide safety-net
  timeout.
"""
