"""End-to-end API tests for the Guardian evaluate endpoint."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import ADMIN_KEY_HEADER, AGENT_KEY_HEADER, API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


class TestEvaluateEndpoint:
    def test_deny_rm_rf(self, client):
        response = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "rm -rf /var/data"},
                    "tool_category": "code_execution",
                },
                "context": {
                    "agent_id": "test-agent",
                    "tenant_id": "acme-corp",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "deny"
        assert data["risk_score"]["final_score"] == 100

    def test_allow_safe_command(self, client):
        response = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "echo hello"},
                },
                "context": {
                    "agent_id": "test-agent",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "allow"

    def test_rewrite_sudo(self, client):
        response = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "sudo apt-get update"},
                },
                "context": {
                    "agent_id": "test-agent",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "rewrite"
        assert "sudo" not in data["rewritten_call"]["rewritten_tool_args"]["command"]

    def test_require_approval_payment(self, client):
        response = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "stripe_charge",
                    "tool_args": {"amount": 1000},
                    "tool_category": "payment",
                },
                "context": {
                    "agent_id": "test-agent",
                },
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "require_approval"
        assert data["requires_human"] is True

    def test_batch_evaluate(self, client):
        response = client.post(
            "/v1/guardian/evaluate-batch",
            headers=API_KEY_HEADER,
            json=[
                {
                    "proposal": {
                        "tool_name": "bash",
                        "tool_args": {"command": "echo safe"},
                    },
                    "context": {"agent_id": "test-agent"},
                },
                {
                    "proposal": {
                        "tool_name": "bash",
                        "tool_args": {"command": "rm -rf /"},
                    },
                    "context": {"agent_id": "test-agent"},
                },
            ],
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["verdict"] == "allow"
        assert data[1]["verdict"] == "deny"

    def test_report_outcome(self, client):
        response = client.post(
            "/v1/guardian/report-outcome",
            headers=API_KEY_HEADER,
            json={
                "proposal_id": "test-123",
                "tool_name": "bash",
                "success": True,
                "response_data": {"output": "hello"},
            },
        )
        assert response.status_code == 202

    def test_approve_nonexistent(self, client):
        response = client.post(
            "/v1/guardian/approve/nonexistent?approved=true&reviewer=admin",
            headers=API_KEY_HEADER,
        )
        assert response.status_code == 404


class TestHealthEndpoints:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_ready(self, client):
        response = client.get("/ready")
        assert response.status_code == 200


class TestPoliciesEndpoint:
    def test_get_active_policy(self, client):
        response = client.get("/v1/policies/active", headers=API_KEY_HEADER)
        assert response.status_code == 200
        data = response.json()
        assert data["policy_id"] == "default-v1"
        assert len(data["rules"]) > 0

    def test_update_active_policy(self, client):
        new_policy = {
            "policy_id": "custom-v1",
            "version": 2,
            "description": "Custom test policy",
            "rules": [],
            "risk_thresholds": {
                "allow_max": 30,
                "rewrite_confirm_min": 31,
                "rewrite_confirm_max": 60,
                "block_approval_min": 61,
            },
        }
        response = client.put(
            "/v1/policies/active", headers=API_KEY_HEADER, json=new_policy
        )
        assert response.status_code == 200
        data = response.json()
        assert data["policy_id"] == "custom-v1"
        assert data["version"] == 2

        # Verify the update took effect
        get_resp = client.get("/v1/policies/active", headers=API_KEY_HEADER)
        assert get_resp.json()["policy_id"] == "custom-v1"

    def test_update_policy_agent_forbidden(self, client):
        new_policy = {
            "policy_id": "hacked-v1",
            "version": 1,
            "rules": [],
        }
        response = client.put(
            "/v1/policies/active", headers=AGENT_KEY_HEADER, json=new_policy
        )
        assert response.status_code == 403

    def test_update_policy_affects_evaluation(self, client):
        """After replacing policy with no rules, previously denied commands are allowed."""
        # Baseline: rm -rf is denied by default policy
        resp1 = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "rm -rf /tmp/data"},
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp1.json()["verdict"] == "deny"

        # Replace with empty policy (no deny rules)
        client.put(
            "/v1/policies/active",
            headers=API_KEY_HEADER,
            json={
                "policy_id": "permissive-v1",
                "version": 1,
                "rules": [],
                "risk_thresholds": {
                    "allow_max": 30,
                    "rewrite_confirm_min": 31,
                    "rewrite_confirm_max": 60,
                    "block_approval_min": 61,
                },
            },
        )

        # Now the same command falls through to heuristic scoring (no rule match)
        resp2 = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "rm -rf /tmp/data"},
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp2.json()["verdict"] != "deny"

    def test_update_policy_validates_body(self, client):
        response = client.put(
            "/v1/policies/active",
            headers=API_KEY_HEADER,
            json={"not_a_policy": True},
        )
        assert response.status_code == 422


class TestApprovalFlowE2E:
    """Full cycle: evaluate → require_approval → approve → resolved."""

    def test_approve_flow(self, client):
        # Step 1: Submit a payment tool call → require_approval
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "stripe_charge",
                    "tool_args": {"amount": 5000},
                    "tool_category": "payment",
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "require_approval"
        assert data["requires_human"] is True
        decision_id = data["decision_id"]

        # Step 2: Approve with admin key
        approve_resp = client.post(
            f"/v1/guardian/approve/{decision_id}?approved=true&reviewer=admin-user",
            headers=API_KEY_HEADER,
        )
        assert approve_resp.status_code == 200
        approved_data = approve_resp.json()
        assert approved_data["verdict"] == "allow"
        assert "admin-user" in approved_data["reason"]

    def test_reject_flow(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "stripe_charge",
                    "tool_args": {"amount": 9999},
                    "tool_category": "payment",
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        decision_id = resp.json()["decision_id"]

        reject_resp = client.post(
            f"/v1/guardian/approve/{decision_id}?approved=false&reviewer=sec-team",
            headers=API_KEY_HEADER,
        )
        assert reject_resp.status_code == 200
        assert reject_resp.json()["verdict"] == "deny"

    def test_approve_requires_admin(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=AGENT_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "stripe_charge",
                    "tool_args": {"amount": 100},
                    "tool_category": "payment",
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        decision_id = resp.json()["decision_id"]

        # Agent role can't approve
        approve_resp = client.post(
            f"/v1/guardian/approve/{decision_id}?approved=true&reviewer=hacker",
            headers=AGENT_KEY_HEADER,
        )
        assert approve_resp.status_code == 403

    def test_double_approve_returns_404(self, client):
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
        decision_id = resp.json()["decision_id"]

        # First approval succeeds
        client.post(
            f"/v1/guardian/approve/{decision_id}?approved=true&reviewer=admin",
            headers=API_KEY_HEADER,
        )

        # Second approval fails (already resolved, removed from pending)
        second = client.post(
            f"/v1/guardian/approve/{decision_id}?approved=true&reviewer=admin",
            headers=API_KEY_HEADER,
        )
        assert second.status_code == 404
