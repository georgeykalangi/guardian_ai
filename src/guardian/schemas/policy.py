"""Pydantic models for the JSON policy specification."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REWRITE = "rewrite"


class MatchCondition(BaseModel):
    """A set of match clauses within a rule. All present conditions must match (AND logic)."""

    tool_name: dict[str, Any] | None = None
    tool_category: dict[str, Any] | None = None
    tool_args_contains: dict[str, str] | None = None
    tool_args_field_check: dict[str, Any] | None = None


class PolicyRule(BaseModel):
    """One deterministic rule in the policy ruleset."""

    rule_id: str = Field(..., min_length=1)
    description: str = ""
    match: MatchCondition
    action: PolicyAction
    reason: str = ""
    rewrite_rule_id: str | None = Field(
        default=None,
        description="If action=rewrite, which rewrite transform to apply.",
    )


class RiskThresholds(BaseModel):
    """Thresholds for converting LLM risk scores to verdicts."""

    allow_max: int = Field(default=30, ge=0, le=100)
    rewrite_confirm_min: int = Field(default=31, ge=0, le=100)
    rewrite_confirm_max: int = Field(default=60, ge=0, le=100)
    block_approval_min: int = Field(default=61, ge=0, le=100)


class PolicySpec(BaseModel):
    """Complete policy document. Rules are evaluated top-to-bottom; first match wins."""

    policy_id: str
    version: int = 1
    description: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scope: list[str] = Field(
        default=["tool_call", "message_send"],
        description="Which interaction types this policy governs.",
    )
    parent_policy_id: str | None = Field(
        default=None,
        description="Inherit rules from a parent policy (org-level).",
    )
    rules: list[PolicyRule] = Field(default_factory=list)
    risk_thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
