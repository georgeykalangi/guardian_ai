"""Tests for GuardianClient (async + sync)."""

import time

import httpx
import pytest
from pytest_httpx import HTTPXMock

from dataguard.client import GuardianClient
from dataguard.exceptions import ApprovalRequired, CircuitBreakerOpen, ConnectionError, ToolBlocked
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
        assert c.api_key is None
        assert c.max_retries == 3
        assert c.circuit_breaker_threshold == 5

    def test_trailing_slash_stripped(self):
        c = GuardianClient("http://localhost:8000/", agent_id="a1")
        assert c.base_url == "http://localhost:8000"

    def test_custom_session_id(self):
        c = GuardianClient("http://x", agent_id="a", session_id="my-sess")
        assert c.session_id == "my-sess"

    def test_api_key_stored(self):
        c = GuardianClient("http://x", agent_id="a", api_key="my-key")
        assert c.api_key == "my-key"


class TestApiKeyHeader:
    async def test_api_key_header_sent(self, client: GuardianClient, httpx_mock: HTTPXMock):
        """API key should be sent as X-API-Key header."""
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        await client.evaluate("bash", {"command": "ls"})
        request = httpx_mock.get_request()
        assert request.headers.get("x-api-key") == "test-key-123"

    async def test_no_api_key_header_when_none(self, httpx_mock: HTTPXMock):
        """No X-API-Key header when api_key is None."""
        c = GuardianClient("http://testserver", agent_id="a", session_id="s")
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        await c.evaluate("bash", {"command": "ls"})
        request = httpx_mock.get_request()
        assert "x-api-key" not in request.headers


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


class TestRetry:
    async def test_retry_on_transient_failure(self, httpx_mock: HTTPXMock):
        """Client retries on ConnectError and succeeds."""
        c = GuardianClient(
            "http://testserver",
            agent_id="a",
            session_id="s",
            max_retries=3,
        )
        # First call fails, second succeeds
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        decision = await c.evaluate("bash", {"command": "ls"})
        assert decision.verdict == DecisionVerdict.ALLOW

    async def test_all_retries_exhausted(self, httpx_mock: HTTPXMock):
        """After max_retries failures, raises ConnectionError."""
        c = GuardianClient(
            "http://testserver",
            agent_id="a",
            session_id="s",
            max_retries=2,
        )
        httpx_mock.add_exception(httpx.ConnectError("fail"))
        httpx_mock.add_exception(httpx.ConnectError("fail"))
        with pytest.raises(ConnectionError):
            await c.evaluate("bash", {"command": "ls"})


class TestCircuitBreaker:
    async def test_circuit_opens_after_threshold(self, httpx_mock: HTTPXMock):
        """Circuit breaker opens after N consecutive failures."""
        c = GuardianClient(
            "http://testserver",
            agent_id="a",
            session_id="s",
            max_retries=1,
            circuit_breaker_threshold=3,
            circuit_breaker_timeout=30.0,
        )

        # Cause 3 failures (each call with max_retries=1 = 1 failure)
        for _ in range(3):
            httpx_mock.add_exception(httpx.ConnectError("fail"))
            with pytest.raises(ConnectionError):
                await c.evaluate("bash", {"command": "ls"})

        # Circuit should now be open
        with pytest.raises(CircuitBreakerOpen):
            await c.evaluate("bash", {"command": "ls"})

    async def test_circuit_resets_after_timeout(self, httpx_mock: HTTPXMock):
        """Circuit breaker resets after timeout elapses."""
        c = GuardianClient(
            "http://testserver",
            agent_id="a",
            session_id="s",
            max_retries=1,
            circuit_breaker_threshold=2,
            circuit_breaker_timeout=0.1,  # 100ms for fast test
        )

        # Open the circuit
        for _ in range(2):
            httpx_mock.add_exception(httpx.ConnectError("fail"))
            with pytest.raises(ConnectionError):
                await c.evaluate("bash", {"command": "ls"})

        # Wait for timeout
        time.sleep(0.15)

        # Should be half-open now — allow a request through
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        decision = await c.evaluate("bash", {"command": "ls"})
        assert decision.verdict == DecisionVerdict.ALLOW
        assert c._consecutive_failures == 0  # Reset on success

    async def test_circuit_success_resets_failures(self, httpx_mock: HTTPXMock):
        """A successful request resets the failure counter."""
        c = GuardianClient(
            "http://testserver",
            agent_id="a",
            session_id="s",
            max_retries=2,
            circuit_breaker_threshold=5,
        )

        # One failure then success
        httpx_mock.add_exception(httpx.ConnectError("fail"))
        httpx_mock.add_response(
            url="http://testserver/v1/guardian/evaluate",
            json=ALLOW_DECISION,
        )
        decision = await c.evaluate("bash", {"command": "ls"})
        assert decision.verdict == DecisionVerdict.ALLOW
        assert c._consecutive_failures == 0
