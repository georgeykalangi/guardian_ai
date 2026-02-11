"""Guardian evaluation API router — the core of DataGuard."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from guardian.db.repositories.audit_repo import AuditRepository
from guardian.dependencies import get_audit_repo, get_orchestrator, require_admin, verify_api_key
from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.schemas.auth import ApiKeyInfo
from guardian.schemas.decision import GuardianDecision
from guardian.schemas.tool_call import GuardianEvaluateRequest, ToolResponse

logger = logging.getLogger("guardian")

router = APIRouter(
    prefix="/v1/guardian",
    tags=["guardian"],
    dependencies=[Depends(verify_api_key)],
)


@router.post(
    "/evaluate",
    response_model=GuardianDecision,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a proposed tool call",
    description=(
        "Receives a ToolCallProposal + context, runs the decision pipeline: "
        "deterministic policy rules -> LLM risk scoring -> verdict."
    ),
)
async def evaluate_tool_call(
    request: GuardianEvaluateRequest,
    orchestrator: DecisionOrchestrator = Depends(get_orchestrator),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    key_info: ApiKeyInfo | None = Depends(verify_api_key),
) -> GuardianDecision:
    # Override tenant_id from API key if the key has a non-default tenant
    if key_info and key_info.tenant_id != "default":
        request.context.tenant_id = key_info.tenant_id
    decision = await orchestrator.evaluate(
        request.proposal, request.context, request.policy_id
    )
    try:
        await audit_repo.log_decision(decision, request.proposal, request.context)
    except Exception:
        logger.exception("Failed to persist audit log for decision %s", decision.decision_id)
    return decision


@router.post(
    "/evaluate-batch",
    response_model=list[GuardianDecision],
    status_code=status.HTTP_200_OK,
    summary="Evaluate multiple proposals",
)
async def evaluate_batch(
    requests: list[GuardianEvaluateRequest],
    orchestrator: DecisionOrchestrator = Depends(get_orchestrator),
    audit_repo: AuditRepository = Depends(get_audit_repo),
) -> list[GuardianDecision]:
    decisions = []
    for req in requests:
        decision = await orchestrator.evaluate(req.proposal, req.context, req.policy_id)
        try:
            await audit_repo.log_decision(decision, req.proposal, req.context)
        except Exception:
            logger.exception("Failed to persist audit log for decision %s", decision.decision_id)
        decisions.append(decision)
    return decisions


@router.post(
    "/report-outcome",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Report tool execution outcome for audit",
)
async def report_outcome(
    outcome: ToolResponse,
    audit_repo: AuditRepository = Depends(get_audit_repo),
):
    try:
        await audit_repo.record_outcome(outcome)
    except Exception:
        logger.exception("Failed to record outcome for proposal %s", outcome.proposal_id)
    return {"status": "recorded", "proposal_id": outcome.proposal_id}


@router.post(
    "/approve/{decision_id}",
    response_model=GuardianDecision,
    summary="Approve or reject a pending decision",
    dependencies=[Depends(require_admin)],
)
async def approve_decision(
    decision_id: str,
    approved: bool,
    reviewer: str = "unknown",
    orchestrator: DecisionOrchestrator = Depends(get_orchestrator),
) -> GuardianDecision:
    decision = await orchestrator.resolve_approval(decision_id, approved, reviewer)
    if decision is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Decision not found or not pending approval.",
        )
    return decision
