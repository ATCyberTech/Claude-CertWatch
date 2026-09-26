# Local development (current default)

This is the active deployment target right now: running `uvicorn` directly
on a developer's machine (the README's "How to run locally" section) — no
cloud account, no VPC, no security groups.

## What protection actually exists here

Only the application layer: `app/scanning/network_guard.py`'s
`resolve_and_validate` and `validate_port`, which run unconditionally on
every scan regardless of deployment target. They correctly reject RFC1918,
loopback, link-local (including the cloud metadata address
`169.254.169.254`), multicast, IPv6 ULA, and IPv4-mapped IPv6 addresses —
see `tests/unit/test_network_guard.py` for the full test list.

## What does NOT exist here

The network-layer half of Section 23's design (routing isolation, an
explicit metadata-address block, provider-specific metadata hardening) has
no equivalent on an unconfigured local machine: there's no VPC, no subnet
route table, and (on a home/office network) no way to block the local
machine's own loopback or LAN reachability without breaking the machine
for everything else.

This is an accepted, explicit gap for local development only — the same
pattern as the local-filesystem `ObjectStorage` backend, which is
documented as dev-only and never used in front of a real customer. **Do
not expose this local instance to the public internet or to untrusted
users.** It is for the developer's own testing against their own targets.

## When this changes

Moving to a real deployment (any of `aws.md`, `gcp.md`, `azure.md`,
`oci.md`, `self-hosted.md`) adds the network layer described in each of
those docs — no code in `app/` needs to change to do so.
