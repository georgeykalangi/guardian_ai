"""Tests for GuardianClient (async + sync)."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from dataguard.client import GuardianClient
from dataguard.exceptions import ApprovalRequired, ToolBlocked
from dataguard.models import DecisionVerdict

from .conftest import (
    ALLOW_DECISION,
    APPROVAL_DECISION,
    DENY_DECISION,
    REWRITE_DECISION,
)


class TestGuardianClientInit:
    def test_defaults(self):
        c = GuardianClient("http://localhost:8000", agent_id="a1")
        assert c.base_url == "http://localhost:8000"
        assert c.agent_id == "a1"
        assert c.tenant_id == "default"
        assert c.timeout == 5.0
        assert c.raise_on_deny is True

    def test_trailing_slash_stripped(self):
        c = GuardianClient("http://localhost:8000/", agent_id="a1")
        assert c.base_url == "http://localhost:8000"

    def test_custom_session_id(self):
        c = GuardianClient("http://x", agent_id="a", session_id="my-sess")
        assert c.session_id == "my-sess"


class TestAsyncEvaluate:
    async def test_allow(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        decision = await client.evaluate("bash", {"command": "ls"})
        assert decision.verdict == DecisionVerdict.ALLOW
        assert decision.risk_score.final_score == 10

    async def test_deny_raises(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=DENY_DECISION,
        )
        with pytest.raises(ToolBlocked) as exc_info:
            await client.evaluate("bash", {"command": "rm -rf /"})
        assert exc_info.value.decision.verdict == DecisionVerdict.DENY
        assert exc_info.value.decision.risk_score.final_score == 95

    async def test_deny_no_raise(
        self, client_no_raise: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=DENY_DECISION,
        )
        decision = await client_no_raise.evaluate("bash", {"command": "rm -rf /"})
        assert decision.verdict == DecisionVerdict.DENY

    async def test_rewrite(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=REWRITE_DECISION,
        )
        decision = await client.evaluate("bash", {"command": "rm -rf /tmp/data"})
        assert decision.verdict == DecisionVerdict.REWRITE
        assert decision.rewritten_call is not None
        assert "interactive" in decision.rewritten_call.rewritten_tool_args["command"]

    async def test_require_approval_raises(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=APPROVAL_DECISION,
        )
        with pytest.raises(ApprovalRequired) as exc_info:
            await client.evaluate("payment", {"amount": 1000})
        assert exc_info.value.decision.requires_human is True

    async def test_sends_correct_payload(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        await client.evaluate("bash", {"command": "ls"})
        request = httpx_mock.get_request()
        body = request.read()
        import json

        payload = json.loads(body)
        assert payload["proposal"]["tool_name"] == "bash"
        assert payload["proposal"]["tool_args"] == {"command": "ls"}
        assert payload["context"]["agent_id"] == "test-agent"
        assert payload["context"]["tenant_id"] == "test-tenant"
        assert payload["context"]["session_id"] == "test-session"


class TestSyncEvaluate:
    def test_allow(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        decision = client.evaluate_sync("bash", {"command": "ls"})
        assert decision.verdict == DecisionVerdict.ALLOW

    def test_deny_raises(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=DENY_DECISION,
        )
        with pytest.raises(ToolBlocked):
            client.evaluate_sync("bash", {"command": "rm -rf /"})


class TestEvaluateBatch:
    async def test_batch(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate-batch",
            json=[ALLOW_DECISION, ALLOW_DECISION],
        )
        decisions = await client.evaluate_batch(
            [
                {"tool_name": "bash", "tool_args": {"command": "ls"}},
                {"tool_name": "bash", "tool_args": {"command": "pwd"}},
            ]
        )
        assert len(decisions) == 2
        assert all(d.verdict == DecisionVerdict.ALLOW for d in decisions)


class TestReportOutcome:
    async def test_report(self, client: GuardianClient, httpx_mock: HTTPXMock):
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/report-outcome",
            json={"status": "recorded", "proposal_id": "prop-001"},
        )
        result = await client.report_outcome(
            "prop-001", "bash", True, response_data={"output": "ok"}
        )
        assert result["status"] == "recorded"


class TestApprove:
    async def test_approve(self, client: GuardianClient, httpx_mock: HTTPXMock):
        approved = {**ALLOW_DECISION, "decision_id": "dec-004"}
        httpx_mock.add_response(
            url=httpx.URL(
                "http://testserver/v1/guardian/approve/dec-004",
                params={"approved": "true", "reviewer": "admin"},
            ),
            json=approved,
        )
        decision = await client.approve("dec-004", approved=True, reviewer="admin")
        assert decision.verdict == DecisionVerdict.ALLOW


class TestContextManager:
    async def test_async_context_manager(self, httpx_mock: HTTPXMock):
        async with GuardianClient(
            "http://testserver", agent_id="a", session_id="s"
        ) as c:
            httpx_mock.add_response(
                url="http://testserver/v1/guardian/evaluate",
                json=ALLOW_DECISION,
            )
            decision = await c.evaluate("bash", {"command": "ls"})
            assert decision.verdict == DecisionVerdict.ALLOW
