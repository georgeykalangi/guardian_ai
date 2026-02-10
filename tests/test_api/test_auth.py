"""Tests for API key authentication."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


class TestApiKeyAuth:
    def test_missing_key_returns_401(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            json={
                "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp.status_code == 401
        assert "Missing API key" in resp.json()["detail"]

    def test_wrong_key_returns_401(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers={"X-API-Key": "wrong-key"},
            json={
                "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp.status_code == 401
        assert "Invalid API key" in resp.json()["detail"]

    def test_correct_key_returns_200(self, client):
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp.status_code == 200

    def test_health_no_auth_needed(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_ready_no_auth_needed(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200

    def test_audit_requires_auth(self, client):
        resp = client.post(
            "/v1/audit/query",
            json={},
        )
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
