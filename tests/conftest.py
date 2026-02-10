"""Shared test fixtures."""

import json
from pathlib import Path

import pytest

from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.engine.rewriter import REWRITE_REGISTRY, init_default_rules
from guardian.engine.risk_scorer import StubRiskScorer
from guardian.schemas.policy import PolicySpec
from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal


@pytest.fixture(autouse=True)
def _setup_rewrite_rules():
    """Ensure rewrite rules are registered for all tests."""
    REWRITE_REGISTRY.clear()
    init_default_rules()


@pytest.fixture
def default_policy() -> PolicySpec:
    path = Path(__file__).parent.parent / "policies" / "default_policy.json"
    with path.open() as f:
        data = json.load(f)
    return PolicySpec(**data)


@pytest.fixture
def orchestrator(default_policy: PolicySpec) -> DecisionOrchestrator:
    scorer = StubRiskScorer()
    return DecisionOrchestrator(policy=default_policy, risk_scorer=scorer)


@pytest.fixture
def context() -> ToolCallContext:
    return ToolCallContext(agent_id="test-agent", tenant_id="test-tenant")


def make_proposal(
    tool_name: str = "bash",
    tool_args: dict | None = None,
    tool_category: str = "unknown",
    intended_outcome: str = "",
) -> ToolCallProposal:
    """Helper to create test proposals."""
    return ToolCallProposal(
        tool_name=tool_name,
        tool_args=tool_args or {},
        tool_category=tool_category,
        intended_outcome=intended_outcome,
    )
