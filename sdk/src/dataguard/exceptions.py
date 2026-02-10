"""SDK exceptions mapped to DataGuard decision verdicts."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dataguard.models import GuardianDecision


class DataGuardError(Exception):
    """Base exception for all DataGuard SDK errors."""


class ToolBlocked(DataGuardError):
    """Raised when the Guardian denies a tool call (verdict=deny)."""

    def __init__(self, decision: GuardianDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Tool blocked: {decision.reason or 'denied by policy'} "
            f"(risk={decision.risk_score.final_score})"
        )


class ApprovalRequired(DataGuardError):
    """Raised when the Guardian requires human approval (verdict=require_approval)."""

    def __init__(self, decision: GuardianDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Approval required: {decision.reason or 'needs human review'} "
            f"(decision_id={decision.decision_id})"
        )


class ConnectionError(DataGuardError):
    """Raised when the DataGuard server is unreachable."""


class CircuitBreakerOpen(DataGuardError):
    """Raised when the circuit breaker is open due to consecutive failures."""

    def __init__(self, failures: int, timeout: float) -> None:
        self.failures = failures
        self.timeout = timeout
        super().__init__(
            f"Circuit breaker open after {failures} consecutive failures. "
            f"Will retry after {timeout}s."
        )
