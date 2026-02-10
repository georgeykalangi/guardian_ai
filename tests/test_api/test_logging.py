"""Tests for request logging middleware and CORS headers."""

from fastapi.testclient import TestClient

from guardian.main import app


class TestRequestLogging:
    def test_response_includes_request_id(self):
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "x-request-id" in resp.headers

    def test_custom_request_id_echoed(self):
        client = TestClient(app)
        resp = client.get("/health", headers={"X-Request-ID": "my-req-123"})
        assert resp.headers["x-request-id"] == "my-req-123"


class TestCORS:
    def test_cors_headers_on_preflight(self):
        client = TestClient(app)
        resp = client.options(
            "/v1/guardian/evaluate",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        # Starlette echoes origin when allow_credentials=True
        assert "access-control-allow-origin" in resp.headers

    def test_cors_headers_on_regular_request(self):
        client = TestClient(app)
        resp = client.get("/health", headers={"Origin": "http://localhost:3000"})
        assert resp.headers.get("access-control-allow-origin") == "*"
