"""FastAPI dependency injection."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from guardian.config import settings
from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.engine.rewriter import init_default_rules
from guardian.engine.risk_scorer import BaseRiskScorer, StubRiskScorer
from guardian.schemas.policy import PolicySpec


@lru_cache
def _load_default_policy() -> PolicySpec:
    """Load the default policy from disk."""
    path = Path(settings.default_policy_path)
    with path.open() as f:
        data = json.load(f)
    return PolicySpec(**data)


@lru_cache
def _get_risk_scorer() -> BaseRiskScorer:
    """Instantiate the risk scorer based on config."""
    # v1: always use the stub scorer
    return StubRiskScorer()


def _ensure_rewrite_rules() -> None:
    """Ensure default rewrite rules are registered."""
    from guardian.engine.rewriter import REWRITE_REGISTRY

    if not REWRITE_REGISTRY:
        init_default_rules()


@lru_cache
def get_orchestrator() -> DecisionOrchestrator:
    """Build and return the singleton DecisionOrchestrator."""
    _ensure_rewrite_rules()
    policy = _load_default_policy()
    scorer = _get_risk_scorer()
    return DecisionOrchestrator(policy=policy, risk_scorer=scorer)
