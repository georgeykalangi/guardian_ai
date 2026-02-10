"""GuardianClient — async and sync HTTP client for the DataGuard API."""

from __future__ import annotations

import uuid
from typing import Any

import httpx

from dataguard.exceptions import ApprovalRequired, ConnectionError, ToolBlocked
from dataguard.models import (
    DecisionVerdict,
    EvaluateRequest,
    GuardianDecision,
    OutcomeReport,
    ToolCallContext,
    ToolCallProposal,
    ToolCategory,
)


class GuardianClient:
    """Client for the DataGuard governance API.

    Args:
        base_url: DataGuard server URL (e.g. "http://localhost:8000").
        agent_id: Identifier for the calling agent.
        tenant_id: Tenant / project identifier.
        timeout: HTTP request timeout in seconds.
        raise_on_deny: If True (default), raise ToolBlocked on deny verdicts.
        session_id: Optional fixed session ID. Auto-generated if omitted.
    """

    def __init__(
        self,
        base_url: str,
        agent_id: str,
        tenant_id: str = "default",
        *,
        timeout: float = 5.0,
        raise_on_deny: bool = True,
        session_id: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.raise_on_deny = raise_on_deny
        self.session_id = session_id or str(uuid.uuid4())
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None

    # -- Async API --

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout
            )
        return self._async_client

    async def evaluate(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        *,
        tool_category: ToolCategory = ToolCategory.UNKNOWN,
        intended_outcome: str = "",
        policy_id: str | None = None,
    ) -> GuardianDecision:
        """Evaluate a tool call proposal asynchronously."""
        request = self._build_request(
            tool_name, tool_args or {}, tool_category, intended_outcome, policy_id
        )
        try:
            resp = await self.async_client.post(
                "/v1/guardian/evaluate",
                json=request.model_dump(mode="json"),
            )
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from exc
        resp.raise_for_status()
        decision = GuardianDecision.model_validate(resp.json())
        return self._handle_verdict(decision)

    async def evaluate_batch(
        self,
        proposals: list[dict[str, Any]],
        *,
        policy_id: str | None = None,
    ) -> list[GuardianDecision]:
        """Evaluate multiple proposals in one call.

        Each item in *proposals* should have keys: tool_name, tool_args,
        and optionally tool_category, intended_outcome.
        """
        requests = [
            self._build_request(
                p["tool_name"],
                p.get("tool_args", {}),
                p.get("tool_category", ToolCategory.UNKNOWN),
                p.get("intended_outcome", ""),
                policy_id,
            ).model_dump(mode="json")
            for p in proposals
        ]
        try:
            resp = await self.async_client.post(
                "/v1/guardian/evaluate-batch", json=requests
            )
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from exc
        resp.raise_for_status()
        decisions = [GuardianDecision.model_validate(d) for d in resp.json()]
        return [self._handle_verdict(d) for d in decisions]

    async def report_outcome(
        self,
        proposal_id: str,
        tool_name: str,
        success: bool,
        *,
        response_data: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any]:
        """Report tool execution outcome for audit."""
        report = OutcomeReport(
            proposal_id=proposal_id,
            tool_name=tool_name,
            success=success,
            response_data=response_data,
            error_message=error_message,
        )
        try:
            resp = await self.async_client.post(
                "/v1/guardian/report-outcome",
                json=report.model_dump(mode="json"),
            )
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from exc
        resp.raise_for_status()
        return resp.json()

    async def approve(
        self,
        decision_id: str,
        *,
        approved: bool = True,
        reviewer: str = "unknown",
    ) -> GuardianDecision:
        """Approve or reject a decision pending human review."""
        try:
            resp = await self.async_client.post(
                f"/v1/guardian/approve/{decision_id}",
                params={"approved": approved, "reviewer": reviewer},
            )
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from exc
        resp.raise_for_status()
        return GuardianDecision.model_validate(resp.json())

    async def aclose(self) -> None:
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()

    # -- Sync API --

    @property
    def sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self.base_url, timeout=self.timeout
            )
        return self._sync_client

    def evaluate_sync(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        *,
        tool_category: ToolCategory = ToolCategory.UNKNOWN,
        intended_outcome: str = "",
        policy_id: str | None = None,
    ) -> GuardianDecision:
        """Evaluate a tool call proposal synchronously."""
        request = self._build_request(
            tool_name, tool_args or {}, tool_category, intended_outcome, policy_id
        )
        try:
            resp = self.sync_client.post(
                "/v1/guardian/evaluate",
                json=request.model_dump(mode="json"),
            )
        except httpx.ConnectError as exc:
            raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from exc
        resp.raise_for_status()
        decision = GuardianDecision.model_validate(resp.json())
        return self._handle_verdict(decision)

    def close(self) -> None:
        if self._sync_client and not self._sync_client.is_closed:
            self._sync_client.close()

    # -- Context managers --

    async def __aenter__(self) -> GuardianClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    def __enter__(self) -> GuardianClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # -- Internal helpers --

    def _build_request(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_category: ToolCategory,
        intended_outcome: str,
        policy_id: str | None,
    ) -> EvaluateRequest:
        return EvaluateRequest(
            proposal=ToolCallProposal(
                tool_name=tool_name,
                tool_args=tool_args,
                tool_category=tool_category,
                intended_outcome=intended_outcome,
            ),
            context=ToolCallContext(
                agent_id=self.agent_id,
                tenant_id=self.tenant_id,
                session_id=self.session_id,
            ),
            policy_id=policy_id,
        )

    def _handle_verdict(self, decision: GuardianDecision) -> GuardianDecision:
        if self.raise_on_deny and decision.verdict == DecisionVerdict.DENY:
            raise ToolBlocked(decision)
        if decision.verdict == DecisionVerdict.REQUIRE_APPROVAL:
            raise ApprovalRequired(decision)
        return decision
