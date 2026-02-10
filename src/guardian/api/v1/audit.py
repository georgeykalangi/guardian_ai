"""Audit log query endpoints."""

from fastapi import APIRouter

from guardian.schemas.audit import AuditLogEntry, AuditQuery

router = APIRouter(prefix="/v1/audit", tags=["audit"])


@router.post(
    "/query",
    response_model=list[AuditLogEntry],
    summary="Query audit logs with filters",
)
async def query_audit_logs(query: AuditQuery) -> list[AuditLogEntry]:
    # In v1 without full DB wiring, return empty
    # Will be connected to AuditRepository when DB is available
    return []
