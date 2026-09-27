"""Log redaction for scan tokens (Section 12, Section 21) — owned by M8.

Section 12 (BUILD NOW): "tokens redacted in server access logs and
application logs." CertWatch has no log-shipping pipeline of its own at
v0 (Section 21's "hosting platform's secret manager" framing is likewise
deferred until a concrete cloud target is stood up — see the M2 gate
precedent), so this configures Python's own `logging` module with a
filter that redacts anything shaped like a scan token before a record is
formatted or written anywhere.

Scope note (M8 implementation decision, recorded in the Decision Log):
this reliably covers every logger CertWatch's own code writes through
(anything under the root logger, plus `certwatch.ai`'s dedicated logger
from M7). It does NOT reliably intercept uvicorn's own built-in access
log (`uvicorn.access`), which by default prints the request path —
containing the token — before this module ever runs, and whose handler
wiring is controlled by uvicorn's own `dictConfig` at a point in the
startup sequence this application factory cannot reliably order itself
around across uvicorn versions. The documented, honest mitigation
(recorded here and in the README) is to run uvicorn with `--no-access-log`
in any environment where access-log token exposure matters, or to route
access logs through a reverse proxy/log pipeline that applies its own
redaction — not to claim a guarantee this module cannot actually keep.
"""

from __future__ import annotations

import logging
import re

# `secrets.token_urlsafe(32)` (app.storage.scan_store.generate_scan_token)
# produces ~43 URL-safe base64 characters (A-Za-z0-9-_, no padding). This
# threshold is comfortably below that and above any short id/path segment
# CertWatch's own code ever logs, so it redacts scan tokens specifically
# without also redacting harmless short strings.
_TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{32,}")
_REDACTED = "<redacted-token>"


class RedactTokensFilter(logging.Filter):
    """Redacts token-shaped substrings from a log record's message and args
    before formatting, so a token never reaches a log handler intact."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _TOKEN_LIKE.sub(_REDACTED, record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: (_TOKEN_LIKE.sub(_REDACTED, value) if isinstance(value, str) else value)
                    for key, value in record.args.items()
                }
            else:
                record.args = tuple(
                    _TOKEN_LIKE.sub(_REDACTED, arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )
        return True


# Every logger name this redaction is attached to — the root logger (every
# logger CertWatch's own modules create with `logging.getLogger(__name__)`
# propagates through it) plus `certwatch.ai` (M7's dedicated tool-call
# logger, which sets `propagate` per its own default but is listed
# explicitly here for defense-in-depth against that ever changing).
_REDACTED_LOGGER_NAMES = ("", "certwatch.ai")


def configure_log_redaction() -> None:
    """Attach one `RedactTokensFilter` instance to every logger named in
    `_REDACTED_LOGGER_NAMES`. Idempotent — safe to call once per process
    or many times (each `create_app()` call in a test suite): a logger
    that already carries a `RedactTokensFilter` instance is left alone
    rather than accumulating duplicates.
    """
    redactor = RedactTokensFilter()
    for name in _REDACTED_LOGGER_NAMES:
        logger = logging.getLogger(name)
        if not any(isinstance(f, RedactTokensFilter) for f in logger.filters):
            logger.addFilter(redactor)
