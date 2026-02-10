"""Audit log query endpoints."""

from fastapi import APIRouter, Depends

from guardian.db.repositories.audit_repo import AuditRepository
from guardian.dependencies import get_audit_repo, verify_api_key
from guardian.schemas.audit import AuditLogEntry, AuditQuery

router = APIRouter(
    prefix="/v1/audit",
    tags=["audit"],
    dependencies=[Depends(verify_api_key)],
)


@router.post(
    "/query",
    response_model=list[AuditLogEntry],
    summary="Query audit logs with filters",
)
async def query_audit_logs(
    query: AuditQuery,
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> list[AuditLogEntry]:
    return await audit_repo.query(query)
