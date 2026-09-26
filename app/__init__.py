"""CertWatch — MVP v0 application package.

Module boundaries (each owned by a build milestone — see docs/M0_CHECKLIST.md
and the CertWatch MVP Technical Specification v1, Section 25):

    app.core      — configuration, shared types. Owned by M0, extended throughout.
    app.scanning  — DNS resolution, SSRF/rebinding guard, TLS discovery. Owned by M2.
    app.parsing   — X.509 parsing, chain classification. Owned by M1.
    app.risk      — deterministic risk engine (Section 9). Owned by M4.
    app.storage   — object-storage abstraction + token model (Sections 11-12). Owned by M3.
    app.ai        — LLM tool-calling layer, AI on/off toggle (Sections 16-17). Owned by M7.
    app.reports   — PDF/CSV report generation (Section 15). Owned by M5.
    app.api       — HTTP API routes (Section 13). Wired incrementally, M2 through M8.
    app.web       — server-rendered UI (Section 14). Owned by M6.

No module above imports live network, certificate-parsing, or storage logic that its
owning milestone has not yet implemented — see each module's stub docstring.
"""
