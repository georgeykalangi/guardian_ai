"""End-to-end API tests for the Guardian evaluate endpoint."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app


@pytest.fixture
def client():
    return TestClient(app)


class TestEvaluateEndpoint:
    def test_deny_rm_rf(self, client):
        response = client.post(
            "/v1/guardian/evaluate",
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
        response = client.get("/v1/policies/active")
        assert response.status_code == 200
        data = response.json()
        assert data["policy_id"] == "default-v1"
        assert len(data["rules"]) > 0
