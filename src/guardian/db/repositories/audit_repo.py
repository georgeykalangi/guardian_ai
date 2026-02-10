"""Repository for audit log persistence and queries."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.models.audit_log import AuditLog
from guardian.schemas.audit import AuditLogEntry, AuditQuery
from guardian.schemas.decision import GuardianDecision
from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal, ToolResponse


class AuditRepository:
    def __init__(self, session: AsyncSession):
        self._session = session

    async def log_decision(
        self,
        decision: GuardianDecision,
        proposal: ToolCallProposal,
        context: ToolCallContext,
    ) -> None:
        """Persist a Guardian decision to the audit log."""
        args_json = json.dumps(proposal.tool_args, sort_keys=True)
        args_hash = hashlib.sha256(args_json.encode()).hexdigest()

        rewritten_snapshot = None
        rewrite_rule_id = None
        if decision.rewritten_call:
            rewritten_snapshot = decision.rewritten_call.rewritten_tool_args
            rewrite_rule_id = decision.rewritten_call.rewrite_rule_id

        row = AuditLog(
            decision_id=decision.decision_id,
            proposal_id=proposal.proposal_id,
            agent_id=context.agent_id,
            session_id=context.session_id,
            tenant_id=context.tenant_id,
            user_id=context.user_id,
            tool_name=proposal.tool_name,
            tool_category=proposal.tool_category.value,
            tool_args_hash=args_hash,
            tool_args_snapshot=proposal.tool_args,
            intended_outcome=proposal.intended_outcome,
            verdict=decision.verdict.value,
            risk_score_final=decision.risk_score.final_score,
            risk_score_deterministic=decision.risk_score.deterministic_score,
            risk_score_llm=decision.risk_score.llm_score,
            matched_rule_id=decision.matched_rule_id,
            reason=decision.reason,
            rewrite_rule_id=rewrite_rule_id,
            rewritten_args_snapshot=rewritten_snapshot,
            requires_human=decision.requires_human,
        )
        self._session.add(row)
        await self._session.commit()

    async def record_outcome(self, outcome: ToolResponse) -> None:
        """Update an audit log entry with the tool's execution result."""
        stmt = select(AuditLog).where(AuditLog.proposal_id == outcome.proposal_id)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row:
            row.outcome_success = outcome.success
            row.outcome_error = outcome.error_message
            row.execution_duration_ms = outcome.execution_duration_ms
            await self._session.commit()

    async def query(self, filters: AuditQuery) -> list[AuditLogEntry]:
        """Query audit logs with filters."""
        stmt = select(AuditLog).order_by(AuditLog.created_at.desc())

        if filters.tenant_id:
            stmt = stmt.where(AuditLog.tenant_id == filters.tenant_id)
        if filters.agent_id:
            stmt = stmt.where(AuditLog.agent_id == filters.agent_id)
        if filters.session_id:
            stmt = stmt.where(AuditLog.session_id == filters.session_id)
        if filters.verdict:
            stmt = stmt.where(AuditLog.verdict == filters.verdict)
        if filters.tool_name:
            stmt = stmt.where(AuditLog.tool_name == filters.tool_name)
        if filters.since:
            stmt = stmt.where(AuditLog.created_at >= filters.since)
        if filters.until:
            stmt = stmt.where(AuditLog.created_at <= filters.until)

        stmt = stmt.offset(filters.offset).limit(filters.limit)
        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [AuditLogEntry.model_validate(row) for row in rows]

    async def get_by_decision_id(self, decision_id: str) -> AuditLogEntry | None:
        stmt = select(AuditLog).where(AuditLog.decision_id == decision_id)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return AuditLogEntry.model_validate(row) if row else None
