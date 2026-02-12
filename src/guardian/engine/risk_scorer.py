"""LLM-based risk scoring interface with a stub implementation for v1.

The stub returns safe defaults. Swap in a real LLM provider for fuzzy detection:
- prompt injection in tool output
- ambiguous user intent
- PII detection when regex fails
- semantic domain checks
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from guardian.engine.detectors import (
    collect_all_text_fields,
    scan_for_injection,
    scan_for_pii,
)
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
# Heuristic scoring using shared detectors
# ---------------------------------------------------------------------------


def _heuristic_score(
    proposal: ToolCallProposal,
    context: ToolCallContext | None = None,
) -> tuple[int, list[str]]:
    """Quick regex-based risk assessment. Returns (score_delta, flags)."""
    score = 0
    flags: list[str] = []

    all_text = collect_all_text_fields(
        proposal.tool_args,
        conversation_summary=context.conversation_summary if context else "",
        intended_outcome=proposal.intended_outcome,
    )

    # PII detection
    pii_result = scan_for_pii(all_text)
    if pii_result.found:
        unique_types = len(pii_result.pattern_ids)
        score += 25  # base for any PII
        if unique_types >= 2:
            score += 5 * (unique_types - 1)  # extra per additional type
        flags.append("pii_detected")

    # Injection detection
    injection_result = scan_for_injection(all_text)
    if injection_result.found:
        score += 65
        flags.append("prompt_injection_suspected")

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
        heuristic_score, flags = _heuristic_score(proposal, context)

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
