# Oracle Cloud Infrastructure (OCI) deployment

One small Compute instance (or an OCI Container Instance) running the
FastAPI app, plus an Object Storage bucket. Not named explicitly in the
technical specification's Section 23 examples (which cover AWS/Azure/GCP),
but the same design principle applies directly — recorded here so OCI is
supported on equal footing, per the Decision Log.

## Network-layer isolation

1. **Dedicated subnet, no private route**: place the scan-worker instance
   in its own subnet within its VCN (Virtual Cloud Network), with a route
   table that has no route to the rest of the VCN's private address space.
2. **Security Lists / Network Security Groups (NSGs)**: deny egress to
   RFC1918 destinations at the security-list or NSG level, applied to the
   subnet or the instance's VNIC.
3. **Metadata hardening**: OCI's Instance Metadata Service is reachable at
   `169.254.169.254` (v1) and supports a v2 API that, like AWS IMDSv2,
   requires an `Authorization: Bearer Oracle` header on requests — enforce
   metadata v2-only where the instance configuration allows it. A raw
   TLS-connect attempt cannot supply this header, so metadata SSRF is not
   reachable via this scanner's connection path by construction; add an
   explicit security-list deny rule for that address anyway, as defense in
   depth matching the routing-isolation principle.

## Object storage

An OCI Object Storage bucket, keyed by the CSPRNG-generated scan token — a
new `ObjectStorage` backend implementing the same interface as
`app/storage/local_filesystem.py`, deferred to M3.

## Not yet decided here

Instance shape, and the bucket's lifecycle policy for the retention
default (Section 21), are M3+ deployment details, not blockers for M2.
