"""Canonical schemas for tool call proposals flowing through the Guardian."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


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
    """The proposed tool call an agent wants to execute."""

    proposal_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique ID for this proposal.",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Canonical name of the tool, e.g. 'bash', 'http_fetch', 'send_email'.",
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments the agent wants to pass to the tool.",
    )
    tool_category: ToolCategory = Field(
        default=ToolCategory.UNKNOWN,
        description="Coarse category for policy matching.",
    )
    intended_outcome: str = Field(
        default="",
        max_length=1024,
        description="Agent's stated purpose for this call.",
    )

    @field_validator("tool_name")
    @classmethod
    def normalize_tool_name(cls, v: str) -> str:
        return v.strip().lower()


class ToolCallContext(BaseModel):
    """Ambient context around the tool call."""

    agent_id: str = Field(..., description="ID of the calling agent.")
    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Conversation / session ID.",
    )
    tenant_id: str = Field(
        default="default",
        description="Tenant / project identifier for multi-tenancy.",
    )
    user_id: str | None = Field(
        default=None,
        description="End-user on whose behalf the agent acts.",
    )
    conversation_summary: str = Field(
        default="",
        max_length=4096,
        description="Short summary of the conversation so far.",
    )
    prior_decisions: list[str] = Field(
        default_factory=list,
        description="IDs of previous GuardianDecisions in this session.",
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ToolResponse(BaseModel):
    """Post-execution: the tool's response flows back for audit."""

    proposal_id: str = Field(..., description="Links back to the original proposal.")
    tool_name: str
    success: bool
    response_data: dict[str, Any] | None = None
    error_message: str | None = None
    execution_duration_ms: int | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GuardianEvaluateRequest(BaseModel):
    """Top-level request body for POST /v1/guardian/evaluate."""

    proposal: ToolCallProposal
    context: ToolCallContext
    policy_id: str | None = Field(
        default=None,
        description="Override: use a specific policy version. None = active default.",
    )
