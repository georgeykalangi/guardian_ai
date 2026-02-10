"""Tests for GuardianMiddleware."""

import pytest
from pytest_httpx import HTTPXMock

from dataguard.client import GuardianClient
from dataguard.exceptions import ApprovalRequired, ToolBlocked
from dataguard.middleware import GuardianMiddleware

from .conftest import (
    ALLOW_DECISION,
    APPROVAL_DECISION,
    DENY_DECISION,
    REWRITE_DECISION,
)


class TestBeforeToolCall:
    async def test_allow_returns_originals(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)
        mw = GuardianMiddleware(client)

        name, args = await mw.before_tool_call("bash", {"command": "ls"})
        assert name == "bash"
        assert args == {"command": "ls"}

    async def test_rewrite_returns_rewritten(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=REWRITE_DECISION)
        mw = GuardianMiddleware(client)

        name, args = await mw.before_tool_call("bash", {"command": "rm -rf /tmp/data"})
        assert name == "bash"
        assert "interactive" in args["command"]

    async def test_deny_raises(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=DENY_DECISION)
        mw = GuardianMiddleware(client)

        with pytest.raises(ToolBlocked):
            await mw.before_tool_call("bash", {"command": "rm -rf /"})

    async def test_approval_raises(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=APPROVAL_DECISION)
        mw = GuardianMiddleware(client)

        with pytest.raises(ApprovalRequired):
            await mw.before_tool_call("payment", {"amount": 1000})

    async def test_tracks_proposal_id(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)
        mw = GuardianMiddleware(client)

        await mw.before_tool_call("bash", {"command": "ls"})
        assert mw._last_proposal_id == "prop-001"


class TestAfterToolCall:
    async def test_report_with_explicit_id(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(
            json={"status": "recorded", "proposal_id": "prop-001"},
        )
        mw = GuardianMiddleware(client)

        result = await mw.after_tool_call(
            "prop-001", tool_name="bash", success=True
        )
        assert result["status"] == "recorded"

    async def test_report_uses_last_proposal_id(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)
        httpx_mock.add_response(
            json={"status": "recorded", "proposal_id": "prop-001"},
        )
        mw = GuardianMiddleware(client)

        await mw.before_tool_call("bash", {"command": "ls"})
        result = await mw.after_tool_call(tool_name="bash", success=True)
        assert result["status"] == "recorded"

    async def test_raises_without_proposal_id(self, client: GuardianClient):
        mw = GuardianMiddleware(client)

        with pytest.raises(ValueError, match="No proposal_id"):
            await mw.after_tool_call(tool_name="bash", success=True)
