"""Initial audit log table.

Revision ID: 001
Revises: None
Create Date: 2026-02-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "guardian_audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        sa.Column("decision_id", sa.String(36), unique=True, index=True, nullable=False),
        sa.Column("proposal_id", sa.String(36), index=True, nullable=False),
        sa.Column("agent_id", sa.String(256), index=True, nullable=False),
        sa.Column("session_id", sa.String(36), index=True, nullable=False),
        sa.Column("tenant_id", sa.String(256), index=True, nullable=False, server_default="default"),
        sa.Column("user_id", sa.String(256), nullable=True),
        # What was proposed
        sa.Column("tool_name", sa.String(256), nullable=False),
        sa.Column("tool_category", sa.String(64), nullable=False),
        sa.Column("tool_args_hash", sa.String(64), nullable=False),
        sa.Column("tool_args_snapshot", sa.JSON(), nullable=False),
        sa.Column("intended_outcome", sa.Text(), server_default="", nullable=False),
        # What was decided
        sa.Column("verdict", sa.String(32), index=True, nullable=False),
        sa.Column("risk_score_final", sa.Integer(), nullable=False),
        sa.Column("risk_score_deterministic", sa.Integer(), nullable=True),
        sa.Column("risk_score_llm", sa.Integer(), nullable=True),
        sa.Column("matched_rule_id", sa.String(128), nullable=True),
        sa.Column("reason", sa.Text(), server_default="", nullable=False),
        # Rewrite info
        sa.Column("rewrite_rule_id", sa.String(128), nullable=True),
        sa.Column("rewritten_args_snapshot", sa.JSON(), nullable=True),
        # Approval tracking
        sa.Column("requires_human", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("approved_by", sa.String(256), nullable=True),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        # Outcome
        sa.Column("outcome_success", sa.Boolean(), nullable=True),
        sa.Column("outcome_error", sa.Text(), nullable=True),
        sa.Column("execution_duration_ms", sa.Integer(), nullable=True),
        # Timestamps
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("guardian_audit_log")
