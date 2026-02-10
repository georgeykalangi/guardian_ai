"""Tests for the stats summary endpoint."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


class TestStatsSummary:
    def test_empty_stats(self, client):
        """Stats endpoint returns zeroes when no decisions exist."""
        resp = client.get("/v1/stats/summary", headers=API_KEY_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_decisions"] == 0
        assert data["pending_approvals"] == 0
        assert data["avg_risk_score"] == 0.0
        assert data["by_verdict"] == {}

    def test_stats_after_evaluations(self, client):
        """Stats reflect decisions made via evaluate endpoint."""
        # Create an allow decision
        client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {"tool_name": "bash", "tool_args": {"command": "echo hi"}},
                "context": {"agent_id": "a1", "tenant_id": "t1"},
            },
        )
        # Create a deny decision
        client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "rm -rf /"},
                    "tool_category": "code_execution",
                },
                "context": {"agent_id": "a1", "tenant_id": "t1"},
            },
        )

        resp = client.get("/v1/stats/summary", headers=API_KEY_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_decisions"] == 2
        assert "allow" in data["by_verdict"]
        assert "deny" in data["by_verdict"]
        assert data["avg_risk_score"] > 0

    def test_stats_requires_auth(self, client):
        resp = client.get("/v1/stats/summary")
        assert resp.status_code == 401

    def test_stats_custom_hours(self, client):
        resp = client.get("/v1/stats/summary?hours=1", headers=API_KEY_HEADER)
        assert resp.status_code == 200
        assert resp.json()["hours"] == 1
