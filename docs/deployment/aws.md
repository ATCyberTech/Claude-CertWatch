# AWS deployment

Per Section 23: one small EC2 instance (or a container-per-request/Fargate
task) running the FastAPI app, plus an S3 bucket for object storage. No
Kubernetes, no microservices, no message bus.

## Network-layer isolation

1. **Dedicated subnet, no private route**: run the scan-worker instance in
   its own subnet whose route table has no route to the rest of the VPC's
   private (RFC1918) address space — the routing layer itself makes those
   destinations undeliverable, not a security-group rule alone.
2. **Explicit metadata block**: the instance metadata address
   (`169.254.169.254`) is reachable via link-local addressing independent of
   VPC routing. Add an explicit network ACL deny rule for that address in
   addition to routing isolation.
3. **IMDSv2 enforced**: on the instance's metadata options, set
   `HttpTokens: required` and `HttpPutResponseHopLimit: 1`. A raw
   TLS-connect attempt (all this scanner ever does) cannot satisfy IMDSv2's
   token-request handshake, so this blocks metadata SSRF specifically —
   zero extra infrastructure, just an instance-launch setting.

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <instance-id> \
  --http-tokens required \
  --http-put-response-hop-limit 1
```

Loopback is out of network-layer reach regardless — defended only by
`network_guard.py`'s application-layer check.

## Object storage

An S3 bucket, keyed by the CSPRNG-generated scan token (Section 11/12) — a
new `ObjectStorage` backend implementing the same interface as
`app/storage/local_filesystem.py`, deferred to M3.

## Not yet decided here

Exact instance size/type, Fargate vs. EC2, and the S3 bucket's lifecycle
policy for the retention default (Section 21) are all M3+ deployment
details, not blockers for M2.
