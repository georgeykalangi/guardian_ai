"""Shared PII and prompt-injection detection utilities.

Pure functions — no async, no guardian imports. Used by both the risk scorer
(to bump scores) and the rewriter (to auto-redact PII).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionMatch:
    """A single pattern match."""

    pattern_id: str
    category: str  # "pii" or "injection"
    matched_text: str
    replacement: str = ""


@dataclass
class DetectionResult:
    """Aggregated result from scanning text."""

    found: bool
    pattern_ids: list[str] = field(default_factory=list)
    matches: list[DetectionMatch] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PII patterns (12)
# ---------------------------------------------------------------------------

_PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN REDACTED]"),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL REDACTED]",
    ),
    (
        "credit_card",
        re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        "[CARD REDACTED]",
    ),
    (
        "password_literal",
        re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*\S+"),
        "[PASSWORD REDACTED]",
    ),
    (
        "phone_us",
        re.compile(r"\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b"),
        "[PHONE REDACTED]",
    ),
    (
        "phone_intl",
        re.compile(r"\+\d{1,3}[\s.-]\d{3,5}[\s.-]\d{3,8}"),
        "[PHONE REDACTED]",
    ),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS KEY REDACTED]"),
    (
        "aws_secret",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*\S+"),
        "[AWS SECRET REDACTED]",
    ),
    (
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "[JWT REDACTED]",
    ),
    (
        "ipv4_address",
        re.compile(
            r"\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)"
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "[IP REDACTED]",
    ),
    (
        "date_of_birth",
        re.compile(r"(?i)\bdob\s*[=:]\s*\S+"),
        "[DOB REDACTED]",
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN\s[\w\s]*PRIVATE\sKEY-----"),
        "[PRIVATE KEY REDACTED]",
    ),
]

# ---------------------------------------------------------------------------
# Injection patterns (11)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(r"(?i)ignore\s+(?:previous|all|prior|above)\s+(?:instructions?|prompts?)"),
    ),
    ("role_override", re.compile(r"(?i)you\s+are\s+now\s+")),
    (
        "system_prompt_fake",
        re.compile(r"(?im)^(?:system|assistant)\s*:\s*"),
    ),
    (
        "override_instructions",
        re.compile(r"(?i)override\s+(?:instructions?|policy|rules?|guidelines?)"),
    ),
    (
        "forget_instructions",
        re.compile(r"(?i)forget\s+(?:everything|all|your\s+instructions?)"),
    ),
    (
        "do_anything_now",
        re.compile(r"(?i)\b(?:DAN|do\s+anything\s+now)\b"),
    ),
    (
        "delimiter_injection",
        re.compile(r"(?i)(?:```\s*system|---\s*instruction|###\s*admin)"),
    ),
    (
        "pretend_mode",
        re.compile(r"(?i)pretend\s+you\s+have\s+no\s+(?:rules|restrictions|limits)"),
    ),
    (
        "disregard_prompt",
        re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)"),
    ),
    (
        "reveal_instructions",
        re.compile(r"(?i)(?:reveal|show|output|print)\s+(?:your\s+)?(?:system\s+prompt|instructions?)"),
    ),
    (
        "concatenation_attack",
        re.compile(r"(?i)concatenate\s+(?:previous\s+)?system\s+output"),
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_for_pii(text: str) -> DetectionResult:
    """Scan text for PII patterns. Returns all matches found."""
    matches: list[DetectionMatch] = []
    seen_ids: set[str] = set()

    for pattern_id, regex, replacement in _PII_PATTERNS:
        for m in regex.finditer(text):
            if pattern_id not in seen_ids:
                seen_ids.add(pattern_id)
            matches.append(
                DetectionMatch(
                    pattern_id=pattern_id,
                    category="pii",
                    matched_text=m.group(),
                    replacement=replacement,
                )
            )

    return DetectionResult(
        found=len(matches) > 0,
        pattern_ids=sorted(seen_ids),
        matches=matches,
    )


def scan_for_injection(text: str) -> DetectionResult:
    """Scan text for prompt-injection patterns."""
    matches: list[DetectionMatch] = []
    seen_ids: set[str] = set()

    for pattern_id, regex in _INJECTION_PATTERNS:
        for m in regex.finditer(text):
            if pattern_id not in seen_ids:
                seen_ids.add(pattern_id)
            matches.append(
                DetectionMatch(
                    pattern_id=pattern_id,
                    category="injection",
                    matched_text=m.group(),
                )
            )

    return DetectionResult(
        found=len(matches) > 0,
        pattern_ids=sorted(seen_ids),
        matches=matches,
    )


def redact_pii(text: str) -> tuple[str, list[str]]:
    """Replace all PII occurrences in *text*. Returns (redacted, pattern_ids)."""
    result = text
    seen_ids: set[str] = set()

    for pattern_id, regex, replacement in _PII_PATTERNS:
        if regex.search(result):
            seen_ids.add(pattern_id)
            result = regex.sub(replacement, result)

    return result, sorted(seen_ids)


def collect_all_text_fields(
    tool_args: dict[str, Any],
    conversation_summary: str = "",
    intended_outcome: str = "",
) -> str:
    """Concatenate all scannable text fields into a single string."""
    parts = [str(tool_args)]
    if conversation_summary:
        parts.append(conversation_summary)
    if intended_outcome:
        parts.append(intended_outcome)
    return "\n".join(parts)
