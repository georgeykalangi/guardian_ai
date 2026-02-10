"""Shared test fixtures."""

import json
import os
from pathlib import Path

# Set env vars before any guardian imports so Settings picks them up
os.environ.setdefault("GUARDIAN_API_KEYS", "test-key-123")
os.environ.setdefault("GUARDIAN_DATABASE_URL", "sqlite+aiosqlite://")

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from guardian.engine.orchestrator import DecisionOrchestrator
from guardian.engine.rewriter import REWRITE_REGISTRY, init_default_rules
from guardian.engine.risk_scorer import StubRiskScorer
from guardian.models.base import Base
from guardian.models.audit_log import AuditLog  # noqa: F401 — register model
from guardian.schemas.policy import PolicySpec
from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal

API_KEY_HEADER = {"X-API-Key": "test-key-123"}

# In-memory async SQLite engine for tests
_test_engine = create_async_engine("sqlite+aiosqlite://", echo=False)
_test_session_factory = async_sessionmaker(
    _test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(autouse=True)
async def _setup_db():
    """Create tables before each test, drop after."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def _override_get_db():
    async with _test_session_factory() as session:
        yield session


@pytest.fixture(autouse=True)
def _override_db_dependency():
    """Override the get_db dependency to use the test database."""
    from guardian.db.session import get_db
    from guardian.main import app

    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)


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
