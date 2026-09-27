"""Unit tests for `app.core.logging_config` (M8, Section 12/21's "tokens
redacted in server access logs and application logs"). See that module's
docstring for the documented scope limit (uvicorn's own access log is not
reliably covered) — these tests prove the filter logic and wiring it does
own, not a real uvicorn process end-to-end.
"""

from __future__ import annotations

import logging

from app.core.logging_config import (
    _REDACTED_LOGGER_NAMES,
    RedactTokensFilter,
    configure_log_redaction,
)


def _make_record(msg: str, args: tuple[object, ...] = ()) -> logging.LogRecord:
    return logging.LogRecord(
        name="certwatch.ai",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


def test_filter_redacts_a_token_shaped_string_in_the_message():
    token = "a" * 43  # shaped like secrets.token_urlsafe(32)'s output
    record = _make_record(f"scan {token} was viewed")

    assert RedactTokensFilter().filter(record) is True
    assert token not in record.msg
    assert "<redacted-token>" in record.msg


def test_filter_leaves_short_strings_alone():
    record = _make_record("scan abc123 status=complete")
    RedactTokensFilter().filter(record)
    assert record.msg == "scan abc123 status=complete"


def test_filter_redacts_within_positional_args():
    token = "b" * 50
    record = _make_record("scan %s viewed", args=(token,))
    RedactTokensFilter().filter(record)
    assert record.args[0] == "<redacted-token>"


def test_filter_redacts_within_dict_style_args():
    token = "c" * 60
    # `logging.LogRecord` only stores `.args` as a bare dict (rather than a
    # one-element tuple) when it's passed this way — `%(token)s`-style
    # formatting, as `logging.getLogger(...).info(msg, {"token": token})`
    # would produce.
    record = logging.LogRecord(
        name="certwatch.ai",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="scan %(token)s viewed",
        args=({"token": token},),
        exc_info=None,
    )
    RedactTokensFilter().filter(record)
    assert record.args["token"] == "<redacted-token>"


def test_configure_log_redaction_attaches_filter_to_named_loggers():
    configure_log_redaction()
    for name in _REDACTED_LOGGER_NAMES:
        logger = logging.getLogger(name)
        assert any(isinstance(f, RedactTokensFilter) for f in logger.filters)


def test_configure_log_redaction_is_idempotent():
    configure_log_redaction()
    configure_log_redaction()
    root_filters = [f for f in logging.getLogger("").filters if isinstance(f, RedactTokensFilter)]
    assert len(root_filters) == 1
