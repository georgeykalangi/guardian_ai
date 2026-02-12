"""Deterministic rewrite transforms for unsafe tool calls.

Each rule is a pure function: (tool_name, tool_args) -> (tool_name, tool_args).
Rules are registered by ID and invoked by the orchestrator when the verdict is 'rewrite'.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from guardian.engine.detectors import redact_pii, scan_for_pii
from guardian.schemas.rewrite import RewriteResult


@dataclass
class RewriteRule:
    rule_id: str
    description: str
    applies_to: Callable[[str, dict[str, Any]], bool]
    transform: Callable[[str, dict[str, Any]], tuple[str, dict[str, Any]]]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REWRITE_REGISTRY: dict[str, RewriteRule] = {}


def register_rule(rule: RewriteRule) -> None:
    REWRITE_REGISTRY[rule.rule_id] = rule


def apply_rewrite(rule_id: str, tool_name: str, tool_args: dict[str, Any]) -> RewriteResult:
    """Look up a rewrite rule by ID and apply it."""
    rule = REWRITE_REGISTRY.get(rule_id)
    if rule is None:
        raise ValueError(f"Unknown rewrite rule: {rule_id}")
    new_name, new_args = rule.transform(tool_name, tool_args)
    return RewriteResult(
        rule_id=rule_id,
        original_tool_name=tool_name,
        original_tool_args=tool_args,
        rewritten_tool_name=new_name,
        rewritten_tool_args=new_args,
        description=rule.description,
    )


def find_applicable_rewrite(
    tool_name: str, tool_args: dict[str, Any]
) -> RewriteRule | None:
    """Find the first rewrite rule that applies to this tool call."""
    for rule in REWRITE_REGISTRY.values():
        if rule.applies_to(tool_name, tool_args):
            return rule
    return None


# ---------------------------------------------------------------------------
# Rule 1: strip-force-flags
# Remove --force / -f from shell commands
# ---------------------------------------------------------------------------


def _strip_force_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("bash", "shell", "code_execution"):
        return False
    cmd = args.get("command", "")
    return bool(re.search(r"\s--force\b|\s-f\b", cmd))


def _strip_force_transform(tool_name: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    cmd = args.get("command", "")
    cmd = re.sub(r"\s--force\b", " ", cmd)
    cmd = re.sub(r"\s-f\b", " ", cmd)
    return tool_name, {**args, "command": cmd.strip()}


# ---------------------------------------------------------------------------
# Rule 2: sandbox-code-exec
# Inject sandbox/read-only flags into code execution
# ---------------------------------------------------------------------------


def _sandbox_applies(tool_name: str, args: dict[str, Any]) -> bool:
    return tool_name in ("code_execution", "exec", "run_code")


def _sandbox_transform(tool_name: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    new_args = {**args, "sandbox": True, "read_only": True}
    return tool_name, new_args


# ---------------------------------------------------------------------------
# Rule 3: truncate-recipients
# Cap email recipients at 5
# ---------------------------------------------------------------------------


def _truncate_recipients_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("send_email", "message_send", "email"):
        return False
    recipients = args.get("recipients", [])
    return isinstance(recipients, list) and len(recipients) > 5


def _truncate_recipients_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    recipients = args.get("recipients", [])
    truncated = recipients[:5]
    new_args = {
        **args,
        "recipients": truncated,
        "_guardian_note": f"Truncated from {len(recipients)} to 5 recipients.",
    }
    return tool_name, new_args


# ---------------------------------------------------------------------------
# Rule 4: redact-secrets-in-args
# Replace secret values in tool args with [REDACTED]
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(secret|token|bearer)\s*[=:]\s*\S+"),
    re.compile(r"(?i)(authorization)\s*[=:]\s*\S+"),
    re.compile(r"\b(sk-[a-zA-Z0-9]{20,})\b"),
    re.compile(r"\b(ghp_[a-zA-Z0-9]{36,})\b"),
    re.compile(r"\b(xoxb-[a-zA-Z0-9\-]+)\b"),
]


def _redact_secrets_applies(tool_name: str, args: dict[str, Any]) -> bool:
    serialized = str(args)
    return any(p.search(serialized) for p in _SECRET_PATTERNS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        result = value
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub("[REDACTED]", result)
        return result
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def _redact_secrets_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    return tool_name, _redact_value(args)


# ---------------------------------------------------------------------------
# Rule 5: downgrade-write-to-dryrun
# Add --dry-run or --noop to write operations
# ---------------------------------------------------------------------------

_WRITE_COMMANDS = re.compile(
    r"\b(mv|cp|rm|mkdir|touch|chmod|chown|git\s+push|git\s+reset)\b"
)


def _dryrun_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("bash", "shell", "file_system"):
        return False
    cmd = args.get("command", "")
    return bool(_WRITE_COMMANDS.search(cmd))


def _dryrun_transform(tool_name: str, args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    cmd = args.get("command", "")
    # For git commands, add --dry-run
    if re.search(r"\bgit\s+(push|reset)\b", cmd):
        cmd = re.sub(r"(git\s+(?:push|reset))", r"\1 --dry-run", cmd)
    else:
        # For filesystem commands, prepend echo to simulate
        cmd = f"echo '[DRY RUN] Would execute:' && echo '{cmd}'"
    return tool_name, {**args, "command": cmd}


# ---------------------------------------------------------------------------
# Rule 6: replace-wildcard-delete
# Prevent unbounded deletes
# ---------------------------------------------------------------------------


def _wildcard_delete_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name in ("bash", "shell"):
        cmd = args.get("command", "")
        return bool(re.search(r"\brm\s+.*\*", cmd))
    if tool_name in ("database", "sql"):
        query = args.get("query", "")
        return bool(re.search(r"(?i)delete\s+from\s+\S+\s*$", query.strip()))
    return False


def _wildcard_delete_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    if tool_name in ("bash", "shell"):
        cmd = args.get("command", "")
        # Replace rm with ls to preview what would be deleted
        cmd = re.sub(r"\brm\b", "ls", cmd)
        return tool_name, {
            **args,
            "command": cmd,
            "_guardian_note": "Wildcard delete converted to ls preview.",
        }
    if tool_name in ("database", "sql"):
        query = args.get("query", "")
        query = query.rstrip().rstrip(";") + " LIMIT 1;"
        return tool_name, {**args, "query": query}
    return tool_name, args


# ---------------------------------------------------------------------------
# Rule 7: cap-http-timeout
# Enforce max 30s timeout on HTTP requests
# ---------------------------------------------------------------------------

_MAX_TIMEOUT_MS = 30_000


def _cap_timeout_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("http_request", "http_fetch", "curl"):
        return False
    timeout = args.get("timeout")
    return timeout is None or (isinstance(timeout, int | float) and timeout > _MAX_TIMEOUT_MS)


def _cap_timeout_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    return tool_name, {**args, "timeout": _MAX_TIMEOUT_MS}


# ---------------------------------------------------------------------------
# Rule 8: enforce-https
# Rewrite http:// to https:// (except localhost)
# ---------------------------------------------------------------------------


def _enforce_https_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("http_request", "http_fetch", "curl"):
        return False
    url = args.get("url", "")
    return url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url


def _enforce_https_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    url = args.get("url", "")
    url = re.sub(r"^http://", "https://", url)
    return tool_name, {**args, "url": url}


# ---------------------------------------------------------------------------
# Rule 9: limit-query-rows
# Add LIMIT 1000 to SELECT queries without LIMIT
# ---------------------------------------------------------------------------

_DEFAULT_ROW_LIMIT = 1000


def _limit_query_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("database", "sql", "query"):
        return False
    query = args.get("query", "")
    has_select = bool(re.search(r"(?i)\bSELECT\b", query))
    has_limit = bool(re.search(r"(?i)\bLIMIT\s+\d+", query))
    return has_select and not has_limit


def _limit_query_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    query = args.get("query", "").rstrip().rstrip(";")
    query = f"{query} LIMIT {_DEFAULT_ROW_LIMIT};"
    return tool_name, {**args, "query": query}


# ---------------------------------------------------------------------------
# Rule 10: neutralize-sudo
# Strip sudo prefix from commands
# ---------------------------------------------------------------------------


def _neutralize_sudo_applies(tool_name: str, args: dict[str, Any]) -> bool:
    if tool_name not in ("bash", "shell", "code_execution"):
        return False
    cmd = args.get("command", "")
    return bool(re.search(r"\bsudo\s", cmd))


def _neutralize_sudo_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    cmd = args.get("command", "")
    cmd = re.sub(r"\bsudo\s+", "", cmd)
    return tool_name, {**args, "command": cmd}


# ---------------------------------------------------------------------------
# Rule 11: redact-pii
# Auto-redact PII (SSNs, emails, phones, etc.) found in tool args
# ---------------------------------------------------------------------------


def _redact_pii_applies(tool_name: str, args: dict[str, Any]) -> bool:
    return scan_for_pii(str(args)).found


def _redact_pii_value(value: Any) -> Any:
    """Recursively walk a value and redact PII from all strings."""
    if isinstance(value, str):
        redacted, _ = redact_pii(value)
        return redacted
    if isinstance(value, dict):
        return {k: _redact_pii_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_pii_value(item) for item in value]
    return value


def _redact_pii_transform(
    tool_name: str, args: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    return tool_name, _redact_pii_value(args)


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


def init_default_rules() -> None:
    """Register all 11 default rewrite rules. Called at app startup."""
    rules = [
        RewriteRule(
            rule_id="strip-force-flags",
            description="Remove --force / -f from shell commands",
            applies_to=_strip_force_applies,
            transform=_strip_force_transform,
        ),
        RewriteRule(
            rule_id="sandbox-code-exec",
            description="Inject sandbox/read-only flags into code execution",
            applies_to=_sandbox_applies,
            transform=_sandbox_transform,
        ),
        RewriteRule(
            rule_id="truncate-recipients",
            description="Cap email recipients at 5",
            applies_to=_truncate_recipients_applies,
            transform=_truncate_recipients_transform,
        ),
        RewriteRule(
            rule_id="redact-secrets",
            description="Replace secret values with [REDACTED]",
            applies_to=_redact_secrets_applies,
            transform=_redact_secrets_transform,
        ),
        RewriteRule(
            rule_id="downgrade-write-to-dryrun",
            description="Add --dry-run or preview mode to write operations",
            applies_to=_dryrun_applies,
            transform=_dryrun_transform,
        ),
        RewriteRule(
            rule_id="replace-wildcard-delete",
            description="Convert wildcard deletes to preview/limited operations",
            applies_to=_wildcard_delete_applies,
            transform=_wildcard_delete_transform,
        ),
        RewriteRule(
            rule_id="cap-http-timeout",
            description="Enforce max 30s timeout on HTTP requests",
            applies_to=_cap_timeout_applies,
            transform=_cap_timeout_transform,
        ),
        RewriteRule(
            rule_id="enforce-https",
            description="Upgrade http:// to https://",
            applies_to=_enforce_https_applies,
            transform=_enforce_https_transform,
        ),
        RewriteRule(
            rule_id="limit-query-rows",
            description="Add LIMIT 1000 to unbounded SELECT queries",
            applies_to=_limit_query_applies,
            transform=_limit_query_transform,
        ),
        RewriteRule(
            rule_id="neutralize-sudo",
            description="Strip sudo prefix from commands",
            applies_to=_neutralize_sudo_applies,
            transform=_neutralize_sudo_transform,
        ),
        RewriteRule(
            rule_id="redact-pii",
            description="Auto-redact PII (SSNs, emails, phones, etc.) in tool arguments",
            applies_to=_redact_pii_applies,
            transform=_redact_pii_transform,
        ),
    ]
    for rule in rules:
        register_rule(rule)
