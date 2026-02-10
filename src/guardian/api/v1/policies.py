"""Policy management endpoints."""

from fastapi import APIRouter, Depends

from guardian.dependencies import get_orchestrator
from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.schemas.policy import PolicySpec

router = APIRouter(prefix="/v1/policies", tags=["policies"])


@router.get(
    "/active",
    response_model=PolicySpec,
    summary="Get the currently active policy",
)
async def get_active_policy(
    orchestrator: DecisionOrchestrator = Depends(get_orchestrator),
) -> PolicySpec:
    return orchestrator._policy


@router.put(
    "/active",
    response_model=PolicySpec,
    summary="Replace the active policy",
)
async def update_active_policy(
    policy: PolicySpec,
    orchestrator: DecisionOrchestrator = Depends(get_orchestrator),
) -> PolicySpec:
    orchestrator.update_policy(policy)
    return policy
