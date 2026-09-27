"""Orchestrates one "Ask CertWatch" question end to end (Section 16).

`answer_question` is the single entry point `app.api.routes_scans` and
`app.web.routes` both call — mirroring `execute_scan`'s pattern (M6) so the
JSON API and the web UI can never answer a question differently. It owns:

- AI-disabled enforcement: if `record.ai_enabled` is False, the LLM is never
  called at all (Section 16's central guarantee).
- The fallback path: any provider failure, or an answer that fails the
  grounding check after retrying, produces the same plain, non-alarming
  message rather than surfacing an error or a possibly-hallucinated answer.
- The grounding/citation check (Section 16): every certificate/host name the
  model's answer mentions must appear in a tool result it actually received
  in that same call.
"""

from __future__ import annotations

import re

from app.ai.llm_client import GroundedAnswer, LLMProvider, LLMUnavailableError, ToolCallResult
from app.ai.tools import ScanToolExecutor
from app.parsing.models import Certificate
from app.storage.scan_store import ScanRecord

_FALLBACK_MESSAGE = (
    "Ask CertWatch isn't available for this answer right now. Your scan's "
    "risk summary, certificate inventory, and PDF/CSV reports are already "
    "complete and don't depend on this feature."
)

_MAX_ANSWER_ATTEMPTS = 2

# A conservative hostname/identifier shape: labels of letters, digits, and
# hyphens joined by dots, optionally with a trailing :port — good enough to
# spot a certificate_id, subject_cn, SAN entry, or "host:port" endpoint
# string mentioned in prose, without trying to be a full hostname grammar.
_NAME_LIKE = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]+)+\b")


def _known_names(tool_calls: list[ToolCallResult]) -> set[str]:
    """Every certificate_id / subject_cn / SAN / endpoint host the model
    actually saw, across every tool result in this answer's conversation."""
    known: set[str] = set()

    def _collect(finding: dict[str, object]) -> None:
        for key in ("certificate_id", "subject_cn", "issuer"):
            value = finding.get(key)
            if isinstance(value, str):
                known.add(value.lower())
        sans = finding.get("san_list")
        if isinstance(sans, list):
            known.update(str(s).lower() for s in sans)
        endpoints = finding.get("endpoints")
        if isinstance(endpoints, list):
            for endpoint in endpoints:
                if isinstance(endpoint, dict) and isinstance(endpoint.get("host"), str):
                    known.add(str(endpoint["host"]).lower())

    for call in tool_calls:
        result = call.result
        if "findings" in result and isinstance(result["findings"], list):
            for finding in result["findings"]:
                if isinstance(finding, dict):
                    _collect(finding)
        elif "endpoints" in result and isinstance(result["endpoints"], list):
            for endpoint in result["endpoints"]:
                if isinstance(endpoint, dict) and isinstance(endpoint.get("host"), str):
                    known.add(str(endpoint["host"]).lower())
        elif "certificate_id" in result:
            _collect(result)

    return known


def _passes_grounding_check(answer: GroundedAnswer) -> bool:
    """Reject any answer that names a hostname-shaped string not present in
    the tool results the model actually received (Section 16)."""
    known = _known_names(answer.tool_calls)
    if not known:
        # No tool was ever called: nothing to ground a factual claim in,
        # unless the answer also mentions no name-like string.
        return not _NAME_LIKE.search(answer.text)
    return all(match.group(0).lower() in known for match in _NAME_LIKE.finditer(answer.text))


def _citations_in(answer: GroundedAnswer) -> list[str]:
    """The known certificate/host names the answer actually cites, in the
    order they first appear — used for the response's `citations` list."""
    known = _known_names(answer.tool_calls)
    seen: list[str] = []
    for match in _NAME_LIKE.finditer(answer.text):
        name = match.group(0)
        if name.lower() in known and name not in seen:
            seen.append(name)
    return seen


def answer_question(
    record: ScanRecord,
    certificates: list[Certificate],
    question: str,
    provider: LLMProvider | None,
) -> tuple[str, list[str]]:
    """Answer `question` about this scan. Returns `(answer_text, citations)`.

    Never raises: AI-disabled, a missing provider, a provider failure, or a
    repeatedly ungrounded answer all fall back to the same plain message
    (Section 16's fallback-behavior bullet) — the caller can always render
    the result directly.
    """
    if not record.ai_enabled or provider is None:
        return _FALLBACK_MESSAGE, []

    tools = ScanToolExecutor(record=record, certificates=certificates)
    for _ in range(_MAX_ANSWER_ATTEMPTS):
        try:
            answer = provider.ask(question, record.token, tools)
        except LLMUnavailableError:
            return _FALLBACK_MESSAGE, []
        if _passes_grounding_check(answer):
            return answer.text, _citations_in(answer)

    return _FALLBACK_MESSAGE, []
