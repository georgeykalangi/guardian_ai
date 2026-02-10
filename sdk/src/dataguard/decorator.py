"""@guard decorator — wraps functions to auto-evaluate through DataGuard."""

from __future__ import annotations

import asyncio
import functools
import inspect
from typing import Any, Callable

from dataguard.client import GuardianClient
from dataguard.exceptions import ApprovalRequired, ToolBlocked
from dataguard.models import DecisionVerdict, ToolCategory


def guard(
    client: GuardianClient,
    *,
    tool_name: str | None = None,
    tool_category: ToolCategory = ToolCategory.UNKNOWN,
    auto_rewrite: bool = True,
) -> Callable:
    """Decorator that evaluates function calls through the DataGuard API.

    Args:
        client: A configured GuardianClient instance.
        tool_name: Override the tool name (defaults to function name).
        tool_category: Category for policy matching.
        auto_rewrite: If True, silently apply rewrites. If False, raise on rewrite.
    """

    def decorator(func: Callable) -> Callable:
        resolved_name = tool_name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _bind_args(func, args, kwargs)
                decision = await client.evaluate(
                    resolved_name,
                    bound,
                    tool_category=tool_category,
                )
                return await _execute_async(func, args, kwargs, decision, auto_rewrite)

            return async_wrapper

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _bind_args(func, args, kwargs)
                decision = client.evaluate_sync(
                    resolved_name,
                    bound,
                    tool_category=tool_category,
                )
                return _execute_sync(func, args, kwargs, decision, auto_rewrite)

            return sync_wrapper

    return decorator


def _bind_args(func: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Extract keyword arguments from a function call for the proposal."""
    sig = inspect.signature(func)
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        return dict(kwargs)


async def _execute_async(
    func: Callable,
    args: tuple,
    kwargs: dict,
    decision: Any,
    auto_rewrite: bool,
) -> Any:
    if decision.verdict == DecisionVerdict.REWRITE:
        if not auto_rewrite:
            raise ToolBlocked(decision)
        rewritten = decision.rewritten_call.rewritten_tool_args
        return await func(**rewritten)
    # verdict == allow (deny/require_approval already raised by client)
    return await func(*args, **kwargs)


def _execute_sync(
    func: Callable,
    args: tuple,
    kwargs: dict,
    decision: Any,
    auto_rewrite: bool,
) -> Any:
    if decision.verdict == DecisionVerdict.REWRITE:
        if not auto_rewrite:
            raise ToolBlocked(decision)
        rewritten = decision.rewritten_call.rewritten_tool_args
        return func(**rewritten)
    return func(*args, **kwargs)
