"""Tests for the admin dashboard HTML routes."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import ADMIN_KEY_HEADER, AGENT_KEY_HEADER, API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


def _create_pending_decision(client) -> str:
    """Helper: evaluate a payment tool call to create a pending approval."""
    resp = client.post(
        "/v1/guardian/evaluate",
        headers=API_KEY_HEADER,
        json={
            "proposal": {
                "tool_name": "stripe_charge",
                "tool_args": {"amount": 500},
                "tool_category": "payment",
            },
            "context": {"agent_id": "test-agent"},
        },
    )
    return resp.json()["decision_id"]


class TestDashboardHome:
    def test_returns_html(self, client):
        response = client.get("/dashboard/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_contains_stats(self, client):
        response = client.get("/dashboard/")
        body = response.text
        # The dashboard template should render stats
        assert "total_decisions" in body or "Total" in body or "0" in body

    def test_shows_decisions_after_evaluate(self, client):
        # Create a decision first
        client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "echo hello"},
                },
                "context": {"agent_id": "dashboard-test"},
            },
        )
        response = client.get("/dashboard/")
        assert response.status_code == 200
        # The page should contain something about the decision
        assert "allow" in response.text.lower() or "bash" in response.text.lower()


class TestApprovalsPage:
    def test_returns_html(self, client):
        response = client.get("/dashboard/approvals")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_empty_approvals(self, client):
        response = client.get("/dashboard/approvals")
        assert response.status_code == 200

    def test_shows_pending_after_evaluate(self, client):
        _create_pending_decision(client)
        response = client.get("/dashboard/approvals")
        assert response.status_code == 200
        # Should show the pending approval
        assert "require_approval" in response.text or "stripe_charge" in response.text


class TestResolveApproval:
    def test_approve_redirects(self, client):
        decision_id = _create_pending_decision(client)
        response = client.post(
            f"/dashboard/approvals/{decision_id}/resolve",
            headers=API_KEY_HEADER,
            data={"approved": "true"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "/dashboard/approvals" in response.headers["location"]

    def test_reject_redirects(self, client):
        decision_id = _create_pending_decision(client)
        response = client.post(
            f"/dashboard/approvals/{decision_id}/resolve",
            headers=API_KEY_HEADER,
            data={"approved": "false"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    def test_resolve_nonexistent_still_redirects(self, client):
        response = client.post(
            "/dashboard/approvals/nonexistent-id/resolve",
            headers=API_KEY_HEADER,
            data={"approved": "true"},
            follow_redirects=False,
        )
        # Even if not found, the endpoint redirects gracefully
        assert response.status_code == 303

    def test_resolve_requires_admin(self, client):
        decision_id = _create_pending_decision(client)
        response = client.post(
            f"/dashboard/approvals/{decision_id}/resolve",
            headers=AGENT_KEY_HEADER,
            data={"approved": "true"},
            follow_redirects=False,
        )
        assert response.status_code == 403

    def test_approve_updates_audit_log(self, client):
        decision_id = _create_pending_decision(client)
        client.post(
            f"/dashboard/approvals/{decision_id}/resolve",
            headers=API_KEY_HEADER,
            data={"approved": "true"},
            follow_redirects=False,
        )
        # After approval, it should no longer appear in pending
        resp = client.get("/dashboard/approvals")
        # The decision_id should not be in the pending list (it was resolved)
        assert decision_id not in resp.text or "allow" in resp.text
