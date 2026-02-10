"""GuardianMiddleware — base class for agent framework integrations."""

from __future__ import annotations

from typing import Any

from dataguard.client import GuardianClient
from dataguard.models import DecisionVerdict


class GuardianMiddleware:
    """Base middleware that agent frameworks can extend.

    Provides before/after hooks around tool calls. The ``before_tool_call``
    method evaluates the proposal and returns the (possibly rewritten)
    tool name and args.  ``after_tool_call`` reports the outcome for audit.

    Usage::

        mw = GuardianMiddleware(client)
        tool_name, tool_args = await mw.before_tool_call("bash", {"command": "ls"})
        result = execute_tool(tool_name, tool_args)
        await mw.after_tool_call(proposal_id, success=True, response_data=result)
    """

    def __init__(self, client: GuardianClient) -> None:
        self.client = client
        self._last_proposal_id: str | None = None

    async def before_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[str, dict[str, Any]]:
        """Evaluate a tool call; return (tool_name, tool_args) to execute.

        Raises ToolBlocked or ApprovalRequired on deny / require_approval.
        On rewrite, returns the rewritten values.
        On allow, returns the originals unchanged.
        """
        decision = await self.client.evaluate(tool_name, tool_args)
        self._last_proposal_id = decision.proposal_id

        if decision.verdict == DecisionVerdict.REWRITE and decision.rewritten_call:
            return (
                decision.rewritten_call.rewritten_tool_name,
                decision.rewritten_call.rewritten_tool_args,
            )
        return tool_name, tool_args

    async def after_tool_call(
        self,
        proposal_id: str | None = None,
        *,
        tool_name: str = "",
        success: bool = True,
        response_data: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        """Report tool execution outcome for audit."""
        pid = proposal_id or self._last_proposal_id
        if pid is None:
            raise ValueError("No proposal_id available. Call before_tool_call first.")
        return await self.client.report_outcome(
            pid,
            tool_name,
            success,
            response_data=response_data,
            error_message=error_message,
        )
