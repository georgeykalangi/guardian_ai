"""Pydantic models for audit log queries and responses."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """Read-only view of an audit log row."""

    id: int
    decision_id: str
    proposal_id: str
    agent_id: str
    session_id: str
    tenant_id: str
    user_id: str | None
    tool_name: str
    tool_category: str
    verdict: str
    risk_score_final: int
    matched_rule_id: str | None
    reason: str
    requires_human: bool
    approved_by: str | None
    outcome_success: bool | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditQuery(BaseModel):
    """Filters for querying audit logs."""

    tenant_id: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    verdict: str | None = None
    tool_name: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    limit: int = Field(default=50, le=500)
    offset: int = Field(default=0, ge=0)
