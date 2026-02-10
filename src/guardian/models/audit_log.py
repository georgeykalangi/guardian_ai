"""Audit log ORM model — every Guardian decision is persisted here."""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from guardian.models.base import Base


class AuditLog(Base):
    __tablename__ = "guardian_audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    proposal_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_id: Mapped[str] = mapped_column(String(256), index=True)
    session_id: Mapped[str] = mapped_column(String(36), index=True)
    tenant_id: Mapped[str] = mapped_column(String(256), index=True, default="default")
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # What was proposed
    tool_name: Mapped[str] = mapped_column(String(256))
    tool_category: Mapped[str] = mapped_column(String(64))
    tool_args_hash: Mapped[str] = mapped_column(String(64))
    tool_args_snapshot: Mapped[dict] = mapped_column(JSON)
    intended_outcome: Mapped[str] = mapped_column(Text, default="")

    # What was decided
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    risk_score_final: Mapped[int] = mapped_column(Integer)
    risk_score_deterministic: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_score_llm: Mapped[int | None] = mapped_column(Integer, nullable=True)
    matched_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")

    # Rewrite info
    rewrite_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rewritten_args_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Approval tracking
    requires_human: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Outcome (filled by report-outcome)
    outcome_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    outcome_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
