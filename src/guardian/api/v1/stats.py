"""Stats / summary endpoint for dashboard and monitoring."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.db.session import get_db
from guardian.dependencies import verify_api_key
from guardian.models.audit_log import AuditLog

router = APIRouter(
    prefix="/v1/stats",
    tags=["stats"],
    dependencies=[Depends(verify_api_key)],
)


@router.get("/summary", summary="Get decision summary stats")
async def stats_summary(
    hours: int = Query(default=24, ge=1, le=720),
    session: AsyncSession = Depends(get_db),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Total decisions
    total_q = select(func.count()).select_from(AuditLog).where(AuditLog.created_at >= since)
    total = (await session.execute(total_q)).scalar() or 0

    # Count by verdict
    verdict_q = (
        select(AuditLog.verdict, func.count())
        .where(AuditLog.created_at >= since)
        .group_by(AuditLog.verdict)
    )
    verdict_rows = (await session.execute(verdict_q)).all()
    by_verdict = {row[0]: row[1] for row in verdict_rows}

    # Pending approvals (requires_human=True and approved_by is NULL)
    pending_q = (
        select(func.count())
        .select_from(AuditLog)
        .where(
            AuditLog.requires_human.is_(True),
            AuditLog.approved_by.is_(None),
        )
    )
    pending_approvals = (await session.execute(pending_q)).scalar() or 0

    # Average risk score
    avg_q = (
        select(func.avg(AuditLog.risk_score_final))
        .where(AuditLog.created_at >= since)
    )
    avg_risk = (await session.execute(avg_q)).scalar()
    avg_risk_score = round(float(avg_risk), 1) if avg_risk is not None else 0.0

    return {
        "hours": hours,
        "total_decisions": total,
        "by_verdict": by_verdict,
        "pending_approvals": pending_approvals,
        "avg_risk_score": avg_risk_score,
    }
