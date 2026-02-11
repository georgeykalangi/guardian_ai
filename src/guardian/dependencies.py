"""FastAPI dependency injection."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from guardian.config import settings
from guardian.db.repositories.audit_repo import AuditRepository
from guardian.db.session import get_db
from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.engine.rewriter import init_default_rules
from guardian.engine.risk_scorer import BaseRiskScorer, StubRiskScorer
from guardian.schemas.auth import ApiKeyInfo, Role
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
    if settings.llm_provider == "anthropic" and settings.llm_api_key:
        from guardian.engine.anthropic_scorer import AnthropicRiskScorer

        return AnthropicRiskScorer(api_key=settings.llm_api_key, model=settings.llm_model)
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


async def get_audit_repo(session: AsyncSession = Depends(get_db)) -> AuditRepository:
    """Provide an AuditRepository bound to the current DB session."""
    return AuditRepository(session)


async def verify_api_key(x_api_key: str | None = Header(default=None)) -> ApiKeyInfo | None:
    """Validate the X-API-Key header and return parsed key info.

    If no API keys are configured (empty string), auth is disabled (dev mode).
    """
    configured = settings.parse_api_keys()
    if not configured:
        return None  # Dev mode: no auth required

    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
        )

    key_info = configured.get(x_api_key)
    if key_info is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )
    return key_info


async def require_admin(key_info: ApiKeyInfo | None = Depends(verify_api_key)) -> ApiKeyInfo | None:
    """Require admin role. Raises 403 if the key is agent-only."""
    if key_info is None:
        return None  # Dev mode
    if key_info.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )
    return key_info
