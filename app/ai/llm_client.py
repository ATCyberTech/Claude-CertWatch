"""LLM provider abstraction — module boundary only, owned by M7.

Declaring this interface now (rather than at M7) lets app.api's /ask route
signature (owned by M7 too, but wired into the router at M0 as a placeholder —
see app/api/routes_scans.py) depend on a stable type without M7 needing to
touch the router.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ToolCallResult:
    """One tool call's result, as returned to the model (Section 16)."""

    tool_name: str
    arguments: dict[str, object]
    result: dict[str, object]


@dataclass
class GroundedAnswer:
    """An LLM answer with its supporting tool calls, for citation rendering."""

    text: str
    citations: list[str]  # finding_ids / endpoints the answer traces to
    tool_calls: list[ToolCallResult]


class LLMProvider(ABC):
    """Abstraction over a single hosted LLM provider (Section 17, Section 28)."""

    @abstractmethod
    def ask(self, question: str, scan_token: str) -> GroundedAnswer:
        """NOT IMPLEMENTED — owned by M7. See app/ai/__init__.py."""
        raise NotImplementedError("app.ai.llm_client.LLMProvider.ask is owned by M7.")
