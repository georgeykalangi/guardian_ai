"""Tests for audit persistence wiring — evaluate creates entries, query returns them."""

import pytest
from fastapi.testclient import TestClient

from guardian.main import app
from tests.conftest import API_KEY_HEADER


@pytest.fixture
def client():
    return TestClient(app)


class TestAuditWiring:
    def test_evaluate_creates_audit_entry(self, client):
        """Evaluating a proposal should persist an audit log entry."""
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "echo hello"},
                },
                "context": {"agent_id": "test-agent", "tenant_id": "acme"},
            },
        )
        assert resp.status_code == 200
        decision = resp.json()

        # Query audit logs
        query_resp = client.post(
            "/v1/audit/query",
            headers=API_KEY_HEADER,
            json={"tenant_id": "acme"},
        )
        assert query_resp.status_code == 200
        entries = query_resp.json()
        assert len(entries) >= 1
        assert entries[0]["decision_id"] == decision["decision_id"]
        assert entries[0]["tool_name"] == "bash"
        assert entries[0]["verdict"] == "allow"

    def test_report_outcome_updates_entry(self, client):
        """report-outcome should update the existing audit log entry."""
        # First create an entry via evaluate
        resp = client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "echo hello"},
                    "proposal_id": "prop-outcome-test",
                },
                "context": {"agent_id": "test-agent"},
            },
        )
        assert resp.status_code == 200

        # Report outcome
        outcome_resp = client.post(
            "/v1/guardian/report-outcome",
            headers=API_KEY_HEADER,
            json={
                "proposal_id": "prop-outcome-test",
                "tool_name": "bash",
                "success": True,
                "execution_duration_ms": 42,
            },
        )
        assert outcome_resp.status_code == 202

        # Verify the audit entry was updated
        query_resp = client.post(
            "/v1/audit/query",
            headers=API_KEY_HEADER,
            json={"agent_id": "test-agent"},
        )
        entries = query_resp.json()
        matching = [e for e in entries if e.get("outcome_success") is True]
        assert len(matching) >= 1

    def test_audit_query_returns_results(self, client):
        """Audit query should return persisted entries."""
        # Create two entries
        for cmd in ["echo a", "echo b"]:
            client.post(
                "/v1/guardian/evaluate",
                headers=API_KEY_HEADER,
                json={
                    "proposal": {"tool_name": "bash", "tool_args": {"command": cmd}},
                    "context": {"agent_id": "test-agent", "tenant_id": "acme"},
                },
            )

        resp = client.post(
            "/v1/audit/query",
            headers=API_KEY_HEADER,
            json={"tenant_id": "acme"},
        )
        assert resp.status_code == 200
        entries = resp.json()
        assert len(entries) == 2

    def test_audit_query_filter_by_verdict(self, client):
        """Audit query filtering by verdict should work."""
        # Create an allow entry
        client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {"tool_name": "bash", "tool_args": {"command": "echo safe"}},
                "context": {"agent_id": "test-agent", "tenant_id": "filter-test"},
            },
        )
        # Create a deny entry
        client.post(
            "/v1/guardian/evaluate",
            headers=API_KEY_HEADER,
            json={
                "proposal": {
                    "tool_name": "bash",
                    "tool_args": {"command": "rm -rf /var/data"},
                    "tool_category": "code_execution",
                },
                "context": {"agent_id": "test-agent", "tenant_id": "filter-test"},
            },
        )

        # Query only deny
        resp = client.post(
            "/v1/audit/query",
            headers=API_KEY_HEADER,
            json={"tenant_id": "filter-test", "verdict": "deny"},
        )
        entries = resp.json()
        assert len(entries) == 1
        assert entries[0]["verdict"] == "deny"

    def test_batch_evaluate_creates_multiple_entries(self, client):
        """Batch evaluate should create audit entries for each decision."""
        resp = client.post(
            "/v1/guardian/evaluate-batch",
            headers=API_KEY_HEADER,
            json=[
                {
                    "proposal": {"tool_name": "bash", "tool_args": {"command": "echo a"}},
                    "context": {"agent_id": "batch-agent", "tenant_id": "batch-test"},
                },
                {
                    "proposal": {"tool_name": "bash", "tool_args": {"command": "echo b"}},
                    "context": {"agent_id": "batch-agent", "tenant_id": "batch-test"},
                },
            ],
        )
        assert resp.status_code == 200

        query_resp = client.post(
            "/v1/audit/query",
            headers=API_KEY_HEADER,
            json={"tenant_id": "batch-test"},
        )
        entries = query_resp.json()
        assert len(entries) == 2
