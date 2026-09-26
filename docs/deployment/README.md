# Deployment / network-isolation mechanisms

The M2 gate (technical specification Section 25, and the Decision Log)
required a cloud provider and a concrete network-isolation mechanism to be
selected before scanner code was written, because the SSRF defense-in-depth
design (Section 23) has an application layer (in code, `app/scanning/`) and
a network layer (deployment configuration, not code) — and the network
layer only means something once you know the actual target.

**Current decision:** local development on a Windows machine is the active
target for now. The application-layer defense (`app/scanning/network_guard.py`)
runs unconditionally regardless of deployment target — it is the same Python
code everywhere. The network layer has no equivalent on an unconfigured local
machine (there's no VPC, no subnet routing, no security groups to configure),
so for local development that second layer is simply absent; this is an
accepted, documented gap for a dev-only environment, the same way M0/M1 use a
local-filesystem storage backend that is explicitly dev-only.

The application itself stays provider-agnostic: nothing in `app/` hardcodes a
cloud provider. Moving to any of the targets below is a deployment-configuration
change, not a code change — see the matching doc:

| Target | Doc |
| --- | --- |
| Local development (current) | [`local-dev.md`](local-dev.md) |
| AWS | [`aws.md`](aws.md) |
| GCP | [`gcp.md`](gcp.md) |
| Azure | [`azure.md`](azure.md) |
| Oracle Cloud Infrastructure (OCI) | [`oci.md`](oci.md) |
| Self-hosted (bare Linux VM, any host) | [`self-hosted.md`](self-hosted.md) |

## The mechanism, in general (Section 23)

Every target below implements the same three-part design:

1. **Routing isolation**: the scan-worker process runs in its own
   dedicated subnet/network whose route table has no route to the rest of
   the private address space, so RFC1918 (or provider-equivalent private)
   destinations are undeliverable at the routing layer itself — not merely
   filtered by a rule that application-layer code could be tricked around.
2. **Explicit metadata-address block**: the cloud metadata address
   (`169.254.169.254` and its IPv6 equivalent where applicable) is reachable
   via link-local addressing independent of normal routing, so it needs its
   own explicit deny rule at the network ACL / firewall level.
3. **Provider-specific metadata hardening**: e.g. AWS IMDSv2 with
   `HttpTokens: required` and `HttpPutResponseHopLimit: 1` — a raw
   TLS-connect attempt (which is all CertWatch's scanner ever does) cannot
   satisfy a token-request handshake, so this blocks metadata SSRF
   specifically, as a well-documented, zero-extra-infrastructure control.

Loopback traffic never leaves the host, so it is inherently out of
network-layer reach regardless of routing on any target — it is defended
only by the application-layer check in `network_guard.py` (which already
does this — see its tests).
