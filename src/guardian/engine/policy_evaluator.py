"""Deterministic JSON rule matcher. First-match-wins evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from guardian.schemas.policy import MatchCondition, PolicyAction, PolicyRule, PolicySpec
from guardian.schemas.tool_call import ToolCallProposal


@dataclass
class PolicyMatchResult:
    """Returned when a rule matches a proposal."""

    rule_id: str
    action: PolicyAction
    reason: str
    rewrite_rule_id: str | None = None


class PolicyEvaluator:
    """Stateless evaluator. Walks rules top-to-bottom, returns first match or None."""

    def match(self, proposal: ToolCallProposal, policy: PolicySpec) -> PolicyMatchResult | None:
        for rule in policy.rules:
            if self._rule_matches(proposal, rule.match):
                return PolicyMatchResult(
                    rule_id=rule.rule_id,
                    action=rule.action,
                    reason=rule.reason,
                    rewrite_rule_id=rule.rewrite_rule_id,
                )
        return None

    def _rule_matches(self, proposal: ToolCallProposal, cond: MatchCondition) -> bool:
        checks: list[bool] = []

        if cond.tool_name is not None:
            checks.append(self._match_string_condition(proposal.tool_name, cond.tool_name))
        if cond.tool_category is not None:
            checks.append(
                self._match_string_condition(proposal.tool_category.value, cond.tool_category)
            )
        if cond.tool_args_contains is not None:
            checks.append(self._match_args_contains(proposal.tool_args, cond.tool_args_contains))
        if cond.tool_args_field_check is not None:
            checks.append(
                self._match_field_check(proposal.tool_args, cond.tool_args_field_check)
            )

        # All conditions in a rule must be true (AND logic). No conditions = no match.
        return len(checks) > 0 and all(checks)

    def _match_string_condition(self, value: str, condition: dict[str, Any]) -> bool:
        if "in" in condition:
            return value in condition["in"]
        if "eq" in condition:
            return value == condition["eq"]
        if "not_in" in condition:
            return value not in condition["not_in"]
        return False

    def _match_args_contains(self, args: dict[str, Any], condition: dict[str, str]) -> bool:
        pattern = condition.get("pattern", "")
        if not pattern:
            return False
        serialized = json.dumps(args)
        return bool(re.search(pattern, serialized))

    def _match_field_check(self, args: dict[str, Any], condition: dict[str, Any]) -> bool:
        field = condition.get("field", "")
        check_type = condition.get("condition", "")
        value = condition.get("value")

        field_val = args.get(field)
        if field_val is None:
            return False

        if check_type == "length_gt" and isinstance(field_val, list):
            return len(field_val) > value

        if check_type == "length_lt" and isinstance(field_val, list):
            return len(field_val) < value

        if check_type == "eq":
            return field_val == value

        if check_type == "gt" and isinstance(field_val, int | float):
            return field_val > value

        if check_type == "lt" and isinstance(field_val, int | float):
            return field_val < value

        if check_type == "contains" and isinstance(field_val, str):
            return value in field_val

        if check_type == "matches" and isinstance(field_val, str):
            return bool(re.search(value, field_val))

        if check_type == "domain_not_in" and isinstance(field_val, str):
            try:
                domain = urlparse(field_val).hostname
                return domain not in value
            except Exception:
                return True  # Malformed URL — flag it

        if check_type == "domain_in" and isinstance(field_val, str):
            try:
                domain = urlparse(field_val).hostname
                return domain in value
            except Exception:
                return False

        return False
