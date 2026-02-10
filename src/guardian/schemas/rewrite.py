"""Pydantic models for rewrite operations."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RewriteResult(BaseModel):
    """Output of applying a rewrite rule to a tool call."""

    rule_id: str
    original_tool_name: str
    original_tool_args: dict[str, Any]
    rewritten_tool_name: str
    rewritten_tool_args: dict[str, Any]
    description: str = ""
