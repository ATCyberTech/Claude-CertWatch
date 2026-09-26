# Certificate fixtures

Empty at M0 by design — M1 populates this directory with the fixture set
required by technical specification Section 22: valid, expired, genuinely
self-signed, private-CA-chained, public-CA-chained, broken chain (missing/
expired intermediate, wrong order), cross-signed (valid alternate path),
wrong-host SAN, wildcard edge cases, weak key (RSA-1024), SHA1-signed, and
malformed/truncated DER.
