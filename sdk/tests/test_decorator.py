"""Tests for the @guard decorator."""

import pytest
from pytest_httpx import HTTPXMock

from dataguard.client import GuardianClient
from dataguard.decorator import guard
from dataguard.exceptions import ToolBlocked
from dataguard.models import ToolCategory

from .conftest import ALLOW_DECISION, DENY_DECISION, REWRITE_DECISION


class TestAsyncGuard:
    async def test_allow_executes(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)

        @guard(client)
        async def list_files(path: str = "/tmp") -> str:
            return f"listing {path}"

        result = await list_files(path="/home")
        assert result == "listing /home"

    async def test_deny_raises(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=DENY_DECISION)

        @guard(client)
        async def dangerous(command: str = "") -> str:
            return "should not run"

        with pytest.raises(ToolBlocked):
            await dangerous(command="rm -rf /")

    async def test_rewrite_auto_applies(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=REWRITE_DECISION)

        @guard(client)
        async def bash(command: str = "") -> str:
            return f"executed: {command}"

        result = await bash(command="rm -rf /tmp/data")
        assert "interactive" in result

    async def test_rewrite_raises_when_disabled(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=REWRITE_DECISION)

        @guard(client, auto_rewrite=False)
        async def bash(command: str = "") -> str:
            return f"executed: {command}"

        with pytest.raises(ToolBlocked):
            await bash(command="rm -rf /tmp/data")

    async def test_custom_tool_name(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)

        @guard(client, tool_name="shell_exec", tool_category=ToolCategory.CODE_EXECUTION)
        async def run(cmd: str = "") -> str:
            return cmd

        result = await run(cmd="ls")
        assert result == "ls"

        import json
        request = httpx_mock.get_request()
        payload = json.loads(request.read())
        assert payload["proposal"]["tool_name"] == "shell_exec"
        assert payload["proposal"]["tool_category"] == "code_execution"


class TestSyncGuard:
    def test_allow_executes(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=ALLOW_DECISION)

        @guard(client)
        def list_files(path: str = "/tmp") -> str:
            return f"listing {path}"

        result = list_files(path="/home")
        assert result == "listing /home"

    def test_deny_raises(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=DENY_DECISION)

        @guard(client)
        def dangerous(command: str = "") -> str:
            return "should not run"

        with pytest.raises(ToolBlocked):
            dangerous(command="rm -rf /")

    def test_rewrite_auto_applies(
        self, client: GuardianClient, httpx_mock: HTTPXMock
    ):
        httpx_mock.add_response(json=REWRITE_DECISION)

        @guard(client)
        def bash(command: str = "") -> str:
            return f"executed: {command}"

        result = bash(command="rm -rf /tmp/data")
        assert "interactive" in result

    def test_preserves_function_metadata(self, client: GuardianClient):
        @guard(client)
        def my_func():
            """My docstring."""

        assert my_func.__name__ == "my_func"
        assert my_func.__doc__ == "My docstring."
