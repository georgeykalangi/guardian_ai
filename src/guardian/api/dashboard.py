"""Admin dashboard — Jinja2 HTML pages for audit trail and approvals."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.db.session import get_db
from guardian.dependencies import require_admin
from guardian.models.audit_log import AuditLog

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))


@router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request, session: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    # Stats
    total_q = select(func.count()).select_from(AuditLog).where(AuditLog.created_at >= since)
    total = (await session.execute(total_q)).scalar() or 0

    pending_q = (
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.requires_human.is_(True), AuditLog.approved_by.is_(None))
    )
    pending = (await session.execute(pending_q)).scalar() or 0

    avg_q = select(func.avg(AuditLog.risk_score_final)).where(AuditLog.created_at >= since)
    avg_risk = (await session.execute(avg_q)).scalar()
    avg_risk_score = round(float(avg_risk), 1) if avg_risk is not None else 0.0

    stats = {
        "total_decisions": total,
        "pending_approvals": pending,
        "avg_risk_score": avg_risk_score,
    }

    # Recent decisions (last 50)
    decisions_q = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(50)
    result = await session.execute(decisions_q)
    decisions = result.scalars().all()

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "stats": stats, "decisions": decisions},
    )


@router.get("/approvals", response_class=HTMLResponse)
async def approvals_page(request: Request, session: AsyncSession = Depends(get_db)):
    pending_q = (
        select(AuditLog)
        .where(AuditLog.requires_human.is_(True), AuditLog.approved_by.is_(None))
        .order_by(AuditLog.created_at.desc())
    )
    result = await session.execute(pending_q)
    pending = result.scalars().all()

    return templates.TemplateResponse(
        "approvals.html",
        {"request": request, "pending": pending},
    )


@router.post("/approvals/{decision_id}/resolve", dependencies=[Depends(require_admin)])
async def resolve_approval(
    decision_id: str,
    approved: str = Form(...),
    session: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog).where(AuditLog.decision_id == decision_id)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()

    if row:
        row.approved_by = "dashboard-admin"
        row.approved_at = datetime.now(timezone.utc)
        if approved.lower() != "true":
            row.verdict = "deny"
        else:
            row.verdict = "allow"
        await session.commit()

    return RedirectResponse(url="/dashboard/approvals", status_code=303)
