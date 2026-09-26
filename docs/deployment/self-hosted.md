# Self-hosted deployment (bare Linux VM, any host)

One small Linux VM (any provider or on-prem host that isn't one of the
named clouds) running the FastAPI app directly, plus local-disk or an
S3-compatible object-storage endpoint (e.g. MinIO) for storage.

## Network-layer isolation

There is no VPC/VCN or managed routing layer to lean on here, so the
routing-isolation principle is implemented directly with `iptables` /
`nftables` egress rules on the host itself:

```bash
# Deny outbound to RFC1918 ranges
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
# Deny outbound to the link-local range (covers the cloud-metadata address
# pattern even though a bare host normally has no metadata service)
iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
# Loopback is inherently local — no iptables rule reaches it; defended
# only by network_guard.py's application-layer check, as everywhere else.
```

If this host actually runs on a cloud provider's infrastructure without
using that provider's managed networking (e.g. a bare VM with no VPC
configuration touched), also add the explicit metadata-address rule above
even though it duplicates the link-local rule — auditability over
minimalism for the single highest-risk component in the product.

Run these rules for the specific user/process the scanner runs as wherever
the platform allows it, and verify with an actual connection attempt from
that process to a private test target as part of deployment verification
(the "infrastructure test" implementation requirement in Section 5).

## Object storage

Local disk (same `LocalFilesystemStorage` backend used in dev — acceptable
here only if this host has durable, backed-up storage) or an
S3-compatible endpoint via a new `ObjectStorage` backend, deferred to M3.

## Not yet decided here

Which self-hosted provider/host, and its backup/retention story for
Section 21, are M3+ deployment details, not blockers for M2.
