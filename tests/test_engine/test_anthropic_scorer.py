"""Tests for the Anthropic LLM risk scorer with mocked API."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardian.engine.anthropic_scorer import AnthropicRiskScorer
from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal


def _make_proposal(tool_name="bash", tool_args=None, tool_category="unknown"):
    return ToolCallProposal(
        tool_name=tool_name,
        tool_args=tool_args or {"command": "ls"},
        tool_category=tool_category,
    )


def _make_context():
    return ToolCallContext(agent_id="test-agent", tenant_id="test-tenant")


def _mock_anthropic_response(score: int, explanation: str, flags: list[str]):
    """Create a mock Anthropic messages.create response."""
    response_json = json.dumps({"score": score, "explanation": explanation, "flags": flags})
    content_block = MagicMock()
    content_block.text = response_json
    response = MagicMock()
    response.content = [content_block]
    return response


class TestAnthropicRiskScorer:
    async def test_high_risk_response(self):
        """LLM returns a high-risk score."""
        scorer = AnthropicRiskScorer(api_key="test-key", model="test-model")

        mock_response = _mock_anthropic_response(
            score=85,
            explanation="Destructive file deletion detected",
            flags=["destructive_operation"],
        )

        with patch.object(scorer, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            result = await scorer.score(
                _make_proposal(tool_args={"command": "rm -rf /tmp"}),
                _make_context(),
            )

        assert result.final_score >= 85
        assert "destructive_operation" in result.flags

    async def test_low_risk_response(self):
        """LLM returns a low-risk score."""
        scorer = AnthropicRiskScorer(api_key="test-key")

        mock_response = _mock_anthropic_response(
            score=5,
            explanation="Safe read-only operation",
            flags=[],
        )

        with patch.object(scorer, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            result = await scorer.score(_make_proposal(), _make_context())

        assert result.final_score <= 10
        assert result.explanation == "Safe read-only operation"

    async def test_fallback_on_api_failure(self):
        """When LLM call fails, falls back to heuristic-only result."""
        scorer = AnthropicRiskScorer(api_key="test-key")

        with patch.object(scorer, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(side_effect=Exception("API down"))

            result = await scorer.score(_make_proposal(), _make_context())

        assert result.final_score >= 10
        assert "Heuristic-only" in result.explanation

    async def test_score_combination_takes_max(self):
        """Combined score should be max(heuristic, LLM)."""
        scorer = AnthropicRiskScorer(api_key="test-key")

        # Proposal with PII (heuristic score ~20) but low LLM score
        proposal = _make_proposal(
            tool_args={"data": "SSN: 123-45-6789"}
        )

        mock_response = _mock_anthropic_response(
            score=10,
            explanation="Low risk per LLM",
            flags=[],
        )

        with patch.object(scorer, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            result = await scorer.score(proposal, _make_context())

        # Heuristic detects PII (score=20), LLM says 10, max=20
        assert result.final_score >= 20
        assert "pii_detected" in result.flags

    async def test_llm_score_capped_at_100(self):
        """Even if LLM returns >100, final score is capped."""
        scorer = AnthropicRiskScorer(api_key="test-key")

        mock_response = _mock_anthropic_response(
            score=150,  # Invalid but we handle it
            explanation="Extremely dangerous",
            flags=["critical"],
        )

        with patch.object(scorer, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)

            result = await scorer.score(_make_proposal(), _make_context())

        assert result.final_score <= 100
