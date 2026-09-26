# Integration tests

Empty at M0 by design. This directory holds tests that need more than one
component wired together (e.g. M2's SSRF/rebinding suite against a local test
TLS server, or M9's end-to-end upload→report flow). Nothing qualifies yet —
M0 has no scanning, parsing, or storage logic to integrate.
