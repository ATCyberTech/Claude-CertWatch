"""Unit tests for `app.ai.analyst.answer_question` — AI-disabled
enforcement, the grounding/citation check, and the fallback path (M7,
Section 16). Uses a `FakeProvider` implementing `LLMProvider` directly;
no network call, no `anthropic` import.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.ai.analyst import _FALLBACK_MESSAGE, answer_question
from app.ai.llm_client import GroundedAnswer, LLMUnavailableError, ToolCallResult
from app.parsing.models import Certificate, ChainCategory
from app.storage.scan_store import HostResultRecord, ScanRecord, certificate_to_record


def _certificate(**overrides) -> Certificate:
    defaults = dict(
        fingerprint_sha256="a" * 64,
        subject_cn="example.com",
        san_list=["example.com"],
        issuer="Example CA",
        serial_number="1",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        key_algorithm="RSA-2048",
        signature_algorithm="sha256WithRSAEncryption",
        pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        chain_category=ChainCategory.PUBLIC_CA,
        is_expired=False,
        days_to_expiry=30,
        is_wildcard=False,
        hostname_mismatch=False,
        risk_severity=None,
        duplicate_of=None,
    )
    defaults.update(overrides)
    return Certificate(**defaults)


def _record(ai_enabled: bool = True) -> ScanRecord:
    return ScanRecord(
        token="test-token",
        submitted_at=datetime(2026, 1, 1, tzinfo=UTC),
        host_count=1,
        status="complete",
        source_ip=None,
        ai_enabled=ai_enabled,
        host_results=[
            HostResultRecord(
                hostname="example.com",
                port=443,
                status="ok",
                certificate=certificate_to_record(_certificate()),
            )
        ],
    )


class _FakeProvider:
    def __init__(self, answers) -> None:
        self._answers = list(answers)
        self.call_count = 0

    def ask(self, question, scan_token, tools):
        self.call_count += 1
        answer = self._answers[min(self.call_count, len(self._answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer


_GROUNDED_TOOL_CALL = ToolCallResult(
    tool_name="get_findings",
    arguments={},
    result={"findings": [{"subject_cn": "example.com", "san_list": [], "endpoints": []}]},
)


def test_ai_disabled_never_calls_provider() -> None:
    record = _record(ai_enabled=False)
    provider = _FakeProvider(answers=[GroundedAnswer(text="should never be seen")])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == _FALLBACK_MESSAGE
    assert citations == []
    assert provider.call_count == 0


def test_no_provider_configured_returns_fallback() -> None:
    record = _record(ai_enabled=True)
    text, citations = answer_question(record, [_certificate()], "anything?", None)
    assert text == _FALLBACK_MESSAGE
    assert citations == []


def test_provider_unavailable_returns_fallback() -> None:
    record = _record()
    provider = _FakeProvider(answers=[LLMUnavailableError("boom")])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == _FALLBACK_MESSAGE
    assert citations == []
    assert provider.call_count == 1


def test_ungrounded_answer_is_rejected_and_falls_back() -> None:
    """Names a host that never appeared in any tool result — must not be
    surfaced, even after retrying."""
    record = _record()
    ungrounded = GroundedAnswer(text="totally-invented-host.example.net is fine.")
    provider = _FakeProvider(answers=[ungrounded, ungrounded])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == _FALLBACK_MESSAGE
    assert citations == []
    assert provider.call_count == 2


def test_grounded_answer_via_get_endpoints_result_shape() -> None:
    """`_known_names` must also recognize the `get_endpoints_for_certificate`
    and `get_certificate` tool result shapes, not just `get_findings`'s."""
    record = _record()
    endpoints_call = ToolCallResult(
        tool_name="get_endpoints_for_certificate",
        arguments={"certificate_id": "a" * 64},
        result={"endpoints": [{"host": "example.com", "port": 443}]},
    )
    grounded = GroundedAnswer(text="example.com is healthy.", tool_calls=[endpoints_call])
    provider = _FakeProvider(answers=[grounded])

    text, citations = answer_question(record, [_certificate()], "How's example.com?", provider)

    assert text == "example.com is healthy."
    assert citations == ["example.com"]


def test_grounded_answer_via_get_certificate_result_shape() -> None:
    record = _record()
    certificate_call = ToolCallResult(
        tool_name="get_certificate",
        arguments={"certificate_id": "a" * 64},
        result={"certificate_id": "a" * 64, "subject_cn": "example.com", "san_list": []},
    )
    grounded = GroundedAnswer(text="example.com is healthy.", tool_calls=[certificate_call])
    provider = _FakeProvider(answers=[grounded])

    text, citations = answer_question(record, [_certificate()], "How's example.com?", provider)

    assert text == "example.com is healthy."
    assert citations == ["example.com"]


def test_grounded_answer_is_returned_with_citations() -> None:
    record = _record()
    grounded = GroundedAnswer(text="example.com is healthy.", tool_calls=[_GROUNDED_TOOL_CALL])
    provider = _FakeProvider(answers=[grounded])

    text, citations = answer_question(record, [_certificate()], "How's example.com?", provider)

    assert text == "example.com is healthy."
    assert citations == ["example.com"]
    assert provider.call_count == 1


def test_answer_with_no_name_like_text_and_no_tool_calls_passes_grounding() -> None:
    """An answer that makes no factual claim about any specific host (e.g.
    "I don't have enough information") shouldn't be rejected just because
    no tool was called."""
    record = _record()
    generic = GroundedAnswer(text="I don't have enough information to answer that.")
    provider = _FakeProvider(answers=[generic])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == "I don't have enough information to answer that."
    assert citations == []


def test_retry_recovers_if_a_later_attempt_is_grounded() -> None:
    """First attempt ungrounded, second attempt grounded: the retry within
    the attempt budget should recover a real answer rather than falling
    back on the first failure."""
    record = _record()
    ungrounded = GroundedAnswer(text="fake-host.invalid is fine.")
    grounded = GroundedAnswer(text="example.com is healthy.", tool_calls=[_GROUNDED_TOOL_CALL])
    provider = _FakeProvider(answers=[ungrounded, grounded])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == "example.com is healthy."
    assert citations == ["example.com"]
    assert provider.call_count == 2


def test_exhausting_attempt_budget_falls_back() -> None:
    """Every attempt within the budget comes back ungrounded — this must
    fall back rather than loop indefinitely or surface a bad answer."""
    record = _record()
    ungrounded = GroundedAnswer(text="fake-host.invalid is fine.")
    provider = _FakeProvider(answers=[ungrounded, ungrounded, ungrounded])

    text, citations = answer_question(record, [_certificate()], "anything?", provider)

    assert text == _FALLBACK_MESSAGE
    assert citations == []
