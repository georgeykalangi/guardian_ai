"""Shared fixtures for SDK tests."""

from __future__ import annotations

from typing import Any

import pytest

from dataguard.client import GuardianClient


ALLOW_DECISION = {
    "decision_id": "dec-001",
    "proposal_id": "prop-001",
    "verdict": "allow",
    "risk_score": {"final_score": 10, "explanation": "Low risk"},
    "reason": "Tool is allowed",
    "requires_human": False,
}

DENY_DECISION = {
    "decision_id": "dec-002",
    "proposal_id": "prop-002",
    "verdict": "deny",
    "risk_score": {"final_score": 95, "explanation": "Destructive command"},
    "reason": "Dangerous operation blocked",
    "requires_human": False,
}

REWRITE_DECISION = {
    "decision_id": "dec-003",
    "proposal_id": "prop-003",
    "verdict": "rewrite",
    "risk_score": {"final_score": 60, "explanation": "Needs sandboxing"},
    "reason": "Command rewritten for safety",
    "rewritten_call": {
        "original_tool_name": "bash",
        "original_tool_args": {"command": "rm -rf /tmp/data"},
        "rewritten_tool_name": "bash",
        "rewritten_tool_args": {"command": "rm -rf /tmp/data --interactive"},
        "rewrite_rule_id": "rule-sandbox-01",
        "description": "Added interactive flag",
    },
    "requires_human": False,
}

APPROVAL_DECISION = {
    "decision_id": "dec-004",
    "proposal_id": "prop-004",
    "verdict": "require_approval",
    "risk_score": {"final_score": 75, "explanation": "Payment action"},
    "reason": "Needs human approval",
    "requires_human": True,
}


@pytest.fixture
def client() -> GuardianClient:
    return GuardianClient(
        base_url="http://testserver",
        agent_id="test-agent",
        tenant_id="test-tenant",
        session_id="test-session",
    )


@pytest.fixture
def client_no_raise() -> GuardianClient:
    return GuardianClient(
        base_url="http://testserver",
        agent_id="test-agent",
        tenant_id="test-tenant",
        session_id="test-session",
        raise_on_deny=False,
    )
