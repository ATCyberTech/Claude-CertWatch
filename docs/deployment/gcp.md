# GCP deployment

One small Compute Engine instance (or a Cloud Run/container-per-request
service) running the FastAPI app, plus a Cloud Storage bucket.

## Network-layer isolation

1. **Dedicated subnet, no private route**: place the scan-worker instance
   in its own subnet with no route to the rest of the VPC's private
   address space.
2. **VPC firewall rules**: deny egress to RFC1918 ranges at the VPC
   firewall level (GCP firewall rules are stateful and apply per-VPC —
   configure an explicit deny rule for the private ranges, since GCP's
   default network otherwise permits broad internal reachability).
3. **Metadata hardening**: GCP's metadata server (also at
   `169.254.169.254`) requires the `Metadata-Flavor: Google` header on any
   request — a raw TLS-connect attempt cannot supply this, so the metadata
   endpoint is not reachable via this scanner's connection path by
   construction. Still add an explicit firewall deny rule for
   `169.254.169.254` as defense in depth, matching the routing-isolation
   principle applied to every other private destination.

## Object storage

A Cloud Storage bucket, keyed by the CSPRNG-generated scan token — a new
`ObjectStorage` backend implementing the same interface as
`app/storage/local_filesystem.py`, deferred to M3.

## Not yet decided here

Compute Engine vs. Cloud Run, and the bucket's lifecycle policy for the
retention default (Section 21), are M3+ deployment details, not blockers
for M2.
