"""Guardian evaluation API router — the core of DataGuard."""

from fastapi import APIRouter, Depends, HTTPException, status

from guardian.dependencies import get_orchestrator
from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.schemas.decision import GuardianDecision
from guardian.schemas.tool_call import GuardianEvaluateRequest, ToolResponse

router = APIRouter(prefix="/v1/guardian", tags=["guardian"])


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
) -> GuardianDecision:
    decision = await orchestrator.evaluate(
        request.proposal, request.context, request.policy_id
    )
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
) -> list[GuardianDecision]:
    decisions = []
    for req in requests:
        decision = await orchestrator.evaluate(req.proposal, req.context, req.policy_id)
        decisions.append(decision)
    return decisions


@router.post(
    "/report-outcome",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Report tool execution outcome for audit",
)
async def report_outcome(outcome: ToolResponse):
    # In v1 without DB wiring, just acknowledge
    return {"status": "recorded", "proposal_id": outcome.proposal_id}


@router.post(
    "/approve/{decision_id}",
    response_model=GuardianDecision,
    summary="Approve or reject a pending decision",
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
