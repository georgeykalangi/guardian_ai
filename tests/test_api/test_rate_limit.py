"""Tests for rate limiting middleware."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app, create_app
from guardian.middleware.rate_limiter import RateLimitMiddleware
from tests.conftest import ADMIN_KEY_HEADER, API_KEY_HEADER


@pytest.fixture
def rate_limited_client():
    """Create a test client with a low rate limit (3 RPM)."""
    # Find and replace the rate limit middleware with a low-limit version
    test_app = create_app()

    # Override the DB dependency for test app
    from guardian.db.session import get_db
    from tests.conftest import _override_get_db

    test_app.dependency_overrides[get_db] = _override_get_db

    # Replace the rate limiter middleware with a low-limit one
    # Starlette stores middleware in app.middleware_stack, but we can
    # reconstruct by creating an app with the desired settings.
    # Simpler: directly test the middleware by manipulating the existing app's middleware.

    # Instead, we'll use a fresh app with known settings
    from guardian.config import settings

    original_rpm = settings.rate_limit_rpm
    settings.rate_limit_rpm = 3
    fresh_app = create_app()
    fresh_app.dependency_overrides[get_db] = _override_get_db
    client = TestClient(fresh_app)
    yield client
    settings.rate_limit_rpm = original_rpm


EVAL_PAYLOAD = {
    "proposal": {"tool_name": "bash", "tool_args": {"command": "ls"}},
    "context": {"agent_id": "test-agent"},
}


class TestRateLimiting:
    def test_under_limit_succeeds(self, rate_limited_client):
        """Requests under the RPM limit succeed."""
        for _ in range(3):
            resp = rate_limited_client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json=EVAL_PAYLOAD,
            )
            assert resp.status_code == 200

    def test_over_limit_returns_429(self, rate_limited_client):
        """Exceeding the RPM limit returns 429."""
        for _ in range(3):
            rate_limited_client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json=EVAL_PAYLOAD,
            )

        resp = rate_limited_client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 429
        assert "Rate limit exceeded" in resp.json()["detail"]

    def test_retry_after_header_present(self, rate_limited_client):
        """429 response includes Retry-After header."""
        for _ in range(3):
            rate_limited_client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json=EVAL_PAYLOAD,
            )

        resp = rate_limited_client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers
        assert int(resp.headers["Retry-After"]) > 0

    def test_health_exempt_from_rate_limit(self, rate_limited_client):
        """Health endpoint is exempt from rate limiting."""
        for _ in range(5):
            resp = rate_limited_client.get("/health")
            assert resp.status_code == 200

    def test_ready_exempt_from_rate_limit(self, rate_limited_client):
        """Ready endpoint is exempt from rate limiting."""
        for _ in range(5):
            resp = rate_limited_client.get("/ready")
            assert resp.status_code == 200

    def test_different_keys_independent_limits(self, rate_limited_client):
        """Different API keys have independent rate limits."""
        # Exhaust limit for one key
        for _ in range(3):
            rate_limited_client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json=EVAL_PAYLOAD,
            )

        # Different key should still work
        resp = rate_limited_client.post(
            "/v1/guardian/evaluate",
            headers=ADMIN_KEY_HEADER,
            json=EVAL_PAYLOAD,
        )
        assert resp.status_code == 200

    def test_disabled_when_rpm_zero(self):
        """When RPM=0, rate limiting is disabled (default in tests)."""
        client = TestClient(app)
        for _ in range(10):
            resp = client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json=EVAL_PAYLOAD,
            )
            assert resp.status_code == 200
