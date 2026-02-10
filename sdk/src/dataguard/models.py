"""Lightweight Pydantic models mirroring the DataGuard server schemas.

These are standalone — no dependency on the guardian server package.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ToolCategory(StrEnum):
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    HTTP_REQUEST = "http_request"
    CODE_EXECUTION = "code_execution"
    MESSAGE_SEND = "message_send"
    PAYMENT = "payment"
    AUTH = "auth"
    UNKNOWN = "unknown"


class ToolCallProposal(BaseModel):
    """A proposed tool call to evaluate."""

    proposal_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_category: ToolCategory = ToolCategory.UNKNOWN
    intended_outcome: str = ""


class ToolCallContext(BaseModel):
    """Ambient context sent alongside a proposal."""

    agent_id: str
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = "default"
    user_id: str | None = None
    conversation_summary: str = ""
    prior_decisions: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DecisionVerdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REWRITE = "rewrite"
    REQUIRE_APPROVAL = "require_approval"


class RiskScore(BaseModel):
    deterministic_score: int | None = None
    llm_score: int | None = None
    final_score: int
    explanation: str = ""


class RewrittenCall(BaseModel):
    original_tool_name: str
    original_tool_args: dict[str, Any]
    rewritten_tool_name: str
    rewritten_tool_args: dict[str, Any]
    rewrite_rule_id: str
    description: str = ""


class GuardianDecision(BaseModel):
    """The Guardian's verdict for a tool call proposal."""

    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    proposal_id: str
    verdict: DecisionVerdict
    risk_score: RiskScore
    matched_rule_id: str | None = None
    reason: str = ""
    rewritten_call: RewrittenCall | None = None
    requires_human: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvaluateRequest(BaseModel):
    """Request body for POST /v1/guardian/evaluate."""

    proposal: ToolCallProposal
    context: ToolCallContext
    policy_id: str | None = None


class OutcomeReport(BaseModel):
    """Request body for POST /v1/guardian/report-outcome."""

    proposal_id: str
    tool_name: str
    success: bool
    response_data: dict[str, Any] | None = None
    error_message: str | None = None
    execution_duration_ms: int | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
