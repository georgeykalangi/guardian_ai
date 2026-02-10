"""LLM-based risk scoring interface with a stub implementation for v1.

The stub returns safe defaults. Swap in a real LLM provider for fuzzy detection:
- prompt injection in tool output
- ambiguous user intent
- PII detection when regex fails
- semantic domain checks
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal


@dataclass
class RiskAssessment:
    """Output from the risk scorer."""

    final_score: int  # 0-100
    explanation: str
    flags: list[str]  # e.g. ["pii_detected", "prompt_injection_suspected"]


class BaseRiskScorer(ABC):
    @abstractmethod
    async def score(
        self, proposal: ToolCallProposal, context: ToolCallContext
    ) -> RiskAssessment:
        ...


# ---------------------------------------------------------------------------
# Heuristic patterns used by both stub and real scorers
# ---------------------------------------------------------------------------

_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # email
    re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),  # credit card
    re.compile(r"(?i)\b(password|passwd|pwd)\s*[=:]\s*\S+"),
]

_INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(previous|all|prior)\s+(instructions?|prompts?)"),
    re.compile(r"(?i)you\s+are\s+now\s+"),
    re.compile(r"(?i)system\s*:\s*"),
    re.compile(r"(?i)override\s+(instructions?|policy|rules?)"),
    re.compile(r"(?i)forget\s+(everything|all|your\s+instructions?)"),
]


def _heuristic_score(proposal: ToolCallProposal) -> tuple[int, list[str]]:
    """Quick regex-based risk assessment. Returns (score_delta, flags)."""
    score = 0
    flags: list[str] = []
    serialized = str(proposal.tool_args)

    for pattern in _PII_PATTERNS:
        if pattern.search(serialized):
            score += 20
            flags.append("pii_detected")
            break

    for pattern in _INJECTION_PATTERNS:
        if pattern.search(serialized):
            score += 40
            flags.append("prompt_injection_suspected")
            break

    # High-impact categories get a base bump
    if proposal.tool_category.value in ("payment", "auth"):
        score += 15
        flags.append("high_impact_category")

    return min(score, 100), flags


class StubRiskScorer(BaseRiskScorer):
    """Deterministic heuristic scorer — no LLM calls. Good for v1 and testing."""

    async def score(
        self, proposal: ToolCallProposal, context: ToolCallContext
    ) -> RiskAssessment:
        heuristic_score, flags = _heuristic_score(proposal)

        if heuristic_score == 0:
            return RiskAssessment(
                final_score=10,
                explanation="No risk indicators detected by heuristics.",
                flags=flags,
            )

        explanations = []
        if "pii_detected" in flags:
            explanations.append("Possible PII found in tool arguments.")
        if "prompt_injection_suspected" in flags:
            explanations.append("Potential prompt injection pattern detected.")
        if "high_impact_category" in flags:
            explanations.append(f"Tool category '{proposal.tool_category}' is high-impact.")

        return RiskAssessment(
            final_score=heuristic_score,
            explanation=" ".join(explanations),
            flags=flags,
        )
