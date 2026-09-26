# Azure deployment

One small Azure VM (or a Container Instance/App Service
container-per-request deployment) running the FastAPI app, plus a Blob
Storage container.

## Network-layer isolation

1. **Dedicated subnet, no private route**: place the scan-worker VM in its
   own subnet whose route table (via a Route Table resource / UDRs) has no
   route to the rest of the VNet's private address space.
2. **Network Security Group (NSG) rules**: deny outbound traffic to
   RFC1918 destinations at the NSG level, applied to the subnet or NIC.
3. **Explicit metadata block**: Azure's Instance Metadata Service (IMDS) is
   only reachable at the fixed link-local address `169.254.169.254` and
   requires the `Metadata: true` header — a raw TLS-connect attempt cannot
   supply this, so it isn't reachable via this scanner's connection path by
   construction. Add an explicit NSG deny rule for that address anyway, as
   defense in depth matching the routing-isolation principle.

## Object storage

An Azure Blob Storage container, keyed by the CSPRNG-generated scan
token — a new `ObjectStorage` backend implementing the same interface as
`app/storage/local_filesystem.py`, deferred to M3.

## Not yet decided here

VM size vs. Container Instances, and the container's lifecycle/retention
policy (Section 21), are M3+ deployment details, not blockers for M2.
