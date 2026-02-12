"""GuardianClient — async and sync HTTP client for the DataGuard API."""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx

from dataguard.exceptions import (
    ApprovalRequired,
    CircuitBreakerOpen,
    ConnectionError,
    ToolBlocked,
)
from dataguard.models import (
    AuditLogEntry,
    AuditQuery,
    DecisionVerdict,
    EvaluateRequest,
    GuardianDecision,
    OutcomeReport,
    PolicySpec,
    StatsSummary,
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
        api_key: API key for authentication. None = no auth header sent.
        max_retries: Max retry attempts on transient failures (default 3).
        circuit_breaker_threshold: Consecutive failures before circuit opens (default 5).
        circuit_breaker_timeout: Seconds before circuit half-opens (default 30).
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
        api_key: str | None = None,
        max_retries: int = 3,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.tenant_id = tenant_id
        self.timeout = timeout
        self.raise_on_deny = raise_on_deny
        self.session_id = session_id or str(uuid.uuid4())
        self.api_key = api_key
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout
        self._async_client: httpx.AsyncClient | None = None
        self._sync_client: httpx.Client | None = None
        # Circuit breaker state
        self._consecutive_failures: int = 0
        self._circuit_open_since: float | None = None

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def _check_circuit(self) -> None:
        """Raise if circuit breaker is open; reset if timeout has elapsed."""
        if self._circuit_open_since is None:
            return
        elapsed = time.monotonic() - self._circuit_open_since
        if elapsed < self.circuit_breaker_timeout:
            raise CircuitBreakerOpen(self._consecutive_failures, self.circuit_breaker_timeout)
        # Half-open: allow one attempt, will reset on success or re-open on failure

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_since = None

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.circuit_breaker_threshold:
            self._circuit_open_since = time.monotonic()

    # -- Async API --

    @property
    def async_client(self) -> httpx.AsyncClient:
        if self._async_client is None or self._async_client.is_closed:
            self._async_client = httpx.AsyncClient(
                base_url=self.base_url, timeout=self.timeout, headers=self._headers()
            )
        return self._async_client

    async def _request_with_retry(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Make an async HTTP request with retry and circuit breaker."""
        self._check_circuit()
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = await getattr(self.async_client, method)(url, **kwargs)
                self._record_success()
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                self._record_failure()
                if attempt < self.max_retries - 1:
                    # Exponential backoff: 0.5s, 1s, 2s, ...
                    import asyncio

                    await asyncio.sleep(0.5 * (2**attempt))
        raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from last_exc

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
        resp = await self._request_with_retry(
            "post", "/v1/guardian/evaluate", json=request.model_dump(mode="json")
        )
        resp.raise_for_status()
        decision = GuardianDecision.model_validate(resp.json())
        return self._handle_verdict(decision)

    async def evaluate_batch(
        self,
        proposals: list[dict[str, Any]],
        *,
        policy_id: str | None = None,
    ) -> list[GuardianDecision]:
        """Evaluate multiple proposals in one call."""
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
        resp = await self._request_with_retry(
            "post", "/v1/guardian/evaluate-batch", json=requests
        )
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
        resp = await self._request_with_retry(
            "post", "/v1/guardian/report-outcome", json=report.model_dump(mode="json")
        )
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
        resp = await self._request_with_retry(
            "post",
            f"/v1/guardian/approve/{decision_id}",
            params={"approved": approved, "reviewer": reviewer},
        )
        resp.raise_for_status()
        return GuardianDecision.model_validate(resp.json())

    async def get_policy(self) -> PolicySpec:
        """Fetch the currently active policy."""
        resp = await self._request_with_retry("get", "/v1/policies/active")
        resp.raise_for_status()
        return PolicySpec.model_validate(resp.json())

    async def update_policy(self, policy: PolicySpec) -> PolicySpec:
        """Replace the active policy (requires admin role)."""
        resp = await self._request_with_retry(
            "put", "/v1/policies/active", json=policy.model_dump(mode="json")
        )
        resp.raise_for_status()
        return PolicySpec.model_validate(resp.json())

    async def query_audit(
        self,
        *,
        tenant_id: str | None = None,
        agent_id: str | None = None,
        verdict: str | None = None,
        tool_name: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditLogEntry]:
        """Query audit logs with optional filters."""
        query = AuditQuery(
            tenant_id=tenant_id,
            agent_id=agent_id,
            verdict=verdict,
            tool_name=tool_name,
            limit=limit,
            offset=offset,
        )
        resp = await self._request_with_retry(
            "post",
            "/v1/audit/query",
            json=query.model_dump(mode="json", exclude_none=True),
        )
        resp.raise_for_status()
        return [AuditLogEntry.model_validate(entry) for entry in resp.json()]

    async def get_stats(self, *, hours: int = 24) -> StatsSummary:
        """Fetch decision summary stats."""
        resp = await self._request_with_retry(
            "get", "/v1/stats/summary", params={"hours": hours}
        )
        resp.raise_for_status()
        return StatsSummary.model_validate(resp.json())

    async def aclose(self) -> None:
        if self._async_client and not self._async_client.is_closed:
            await self._async_client.aclose()

    # -- Sync API --

    @property
    def sync_client(self) -> httpx.Client:
        if self._sync_client is None or self._sync_client.is_closed:
            self._sync_client = httpx.Client(
                base_url=self.base_url, timeout=self.timeout, headers=self._headers()
            )
        return self._sync_client

    def _request_with_retry_sync(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Make a sync HTTP request with retry and circuit breaker."""
        self._check_circuit()
        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                resp = getattr(self.sync_client, method)(url, **kwargs)
                self._record_success()
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                self._record_failure()
                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (2**attempt))
        raise ConnectionError(f"Cannot reach DataGuard at {self.base_url}") from last_exc

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
        resp = self._request_with_retry_sync(
            "post", "/v1/guardian/evaluate", json=request.model_dump(mode="json")
        )
        resp.raise_for_status()
        decision = GuardianDecision.model_validate(resp.json())
        return self._handle_verdict(decision)

    def get_policy_sync(self) -> PolicySpec:
        """Fetch the currently active policy (sync)."""
        resp = self._request_with_retry_sync("get", "/v1/policies/active")
        resp.raise_for_status()
        return PolicySpec.model_validate(resp.json())

    def get_stats_sync(self, *, hours: int = 24) -> StatsSummary:
        """Fetch decision summary stats (sync)."""
        resp = self._request_with_retry_sync(
            "get", "/v1/stats/summary", params={"hours": hours}
        )
        resp.raise_for_status()
        return StatsSummary.model_validate(resp.json())

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
