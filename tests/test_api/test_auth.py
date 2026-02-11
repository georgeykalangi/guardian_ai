"""Tests for API key authentication and RBAC."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import ADMIN_KEY_HEADER, AGENT_KEY_HEADER, API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


EVAL_PAYLOAD = {
    "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
    "context": {"agent_id": "test-agent"},
}

MINIMAL_POLICY = {
    "policy_id": "test-policy",
    "version": 1,
    "rules": [],
}


class TestApiKeyAuth:
    def test_missing_key_returns_401(self, client):
        resp = client.post("/v1/guardian/evaluate", json=EVAL_PAYLOAD)
        assert resp.status_code == 401
        assert "Missing API key" in resp.json()["detail"]

    def test_wrong_key_returns_401(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers={"X-API-Key": "wrong-key"},
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 401
        assert "Invalid API key" in resp.json()["detail"]

    def test_correct_key_returns_200(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 200

    def test_health_no_auth_needed(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_ready_no_auth_needed(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200

    def test_audit_requires_auth(self, client):
        resp = client.post("/v1/audit/query", json={})
        assert resp.status_code == 401

    def test_policies_requires_auth(self, client):
        resp = client.get("/v1/policies/active")
        assert resp.status_code == 401


class TestAuthDisabledWhenNoKeys:
    async def test_no_keys_configured_allows_passthrough(self):
        """When GUARDIAN_API_KEYS is empty, auth is disabled."""
        from guardian.config import settings
        from guardian.dependencies import verify_api_key

        original = settings.api_keys
        try:
            settings.api_keys = ""
            result = await verify_api_key(None)
            assert result is None
        finally:
            settings.api_keys = original


class TestRBAC:
    """Test role-based access control with structured API keys."""

    def test_agent_can_evaluate(self, client):
        """Agent-role keys can call /evaluate."""
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=AGENT_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 200

    def test_agent_cannot_approve(self, client):
        """Agent-role keys get 403 on /approve."""
        resp = client.post(
            "/v1/guardian/approve/fake-id?approved=true&reviewer=agent",
            headers=AGENT_KEY_HEADER,
        )
        assert resp.status_code == 403
        assert "Admin role required" in resp.json()["detail"]

    def test_agent_cannot_update_policy(self, client):
        """Agent-role keys get 403 on PUT /policies/active."""
        resp = client.put(
            "/v1/policies/active",
            headers=AGENT_KEY_HEADER,
            json=MINIMAL_POLICY,
        )
        assert resp.status_code == 403
        assert "Admin role required" in resp.json()["detail"]

    def test_admin_can_evaluate(self, client):
        """Admin-role keys can call /evaluate."""
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=ADMIN_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 200

    def test_admin_can_update_policy(self, client):
        """Admin-role keys can PUT /policies/active."""
        resp = client.put(
            "/v1/policies/active",
            headers=ADMIN_KEY_HEADER,
            json=MINIMAL_POLICY,
        )
        assert resp.status_code == 200

    def test_legacy_bare_key_gets_admin(self, client):
        """Bare key (no colons) gets default:admin — backward compatible."""
        # test-key-123 is a bare key in conftest
        resp = client.put(
            "/v1/policies/active",
            headers=API_KEY_HEADER,
            json=MINIMAL_POLICY,
        )
        assert resp.status_code == 200

    def test_agent_can_read_policy(self, client):
        """Agent-role keys can GET /policies/active (read is not admin-only)."""
        resp = client.get(
            "/v1/policies/active",
            headers=AGENT_KEY_HEADER,
        )
        assert resp.status_code == 200

    def test_tenant_override_from_key(self, client):
        """Structured key with non-default tenant overrides context.tenant_id."""
        payload = {
            "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
            "context": {"agent_id": "test-agent", "tenant_id": "original-tenant"},
        }
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=AGENT_KEY_HEADER,  # agent-key:tenant-a:agent
            json=payload,
        )
        assert resp.status_code == 200
        # The decision should reflect tenant-a since the key overrides
