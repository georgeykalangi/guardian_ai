"""Guardian decision output models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class DecisionVerdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REWRITE = "rewrite"
    REQUIRE_APPROVAL = "require_approval"


class RiskScore(BaseModel):
    """Composite risk score from deterministic + LLM evaluation."""

    deterministic_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Score from rule matching. None if no rule matched.",
    )
    llm_score: int | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Score from LLM risk assessment. None if skipped.",
    )
    final_score: int = Field(..., ge=0, le=100)
    explanation: str = ""


class RewrittenCall(BaseModel):
    """If verdict=rewrite, the safe alternative."""

    original_tool_name: str
    original_tool_args: dict
    rewritten_tool_name: str
    rewritten_tool_args: dict
    rewrite_rule_id: str
    description: str = ""


class GuardianDecision(BaseModel):
    """The Guardian's output for a single tool call proposal."""

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    proposal_id: str = Field(..., description="Links back to the ToolCallProposal.")
    verdict: DecisionVerdict
    risk_score: RiskScore
    matched_rule_id: str | None = Field(
        default=None,
        description="Which policy rule fired, if any.",
    )
    reason: str = Field(default="", description="Human-readable explanation.")
    rewritten_call: RewrittenCall | None = Field(
        default=None,
        description="Present only if verdict is 'rewrite'.",
    )
    requires_human: bool = Field(
        default=False,
        description="True if decision needs human approval.",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
