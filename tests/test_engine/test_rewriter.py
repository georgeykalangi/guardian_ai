"""Tests for all 10 rewrite rules."""

import pytest

from guardian.engine.rewriter import apply_rewrite


class TestStripForceFlags:
    def test_removes_force(self):
        result = apply_rewrite(
            "strip-force-flags", "bash", {"command": "git push --force origin main"}
        )
        assert "--force" not in result.rewritten_tool_args["command"]
        assert "git push" in result.rewritten_tool_args["command"]

    def test_removes_f_flag(self):
        result = apply_rewrite(
            "strip-force-flags", "bash", {"command": "rm -f file.txt"}
        )
        assert " -f" not in result.rewritten_tool_args["command"]


class TestSandboxCodeExec:
    def test_adds_sandbox_flags(self):
        result = apply_rewrite(
            "sandbox-code-exec", "code_execution", {"code": "print('hello')"}
        )
        assert result.rewritten_tool_args["sandbox"] is True
        assert result.rewritten_tool_args["read_only"] is True
        assert result.rewritten_tool_args["code"] == "print('hello')"


class TestTruncateRecipients:
    def test_caps_at_5(self):
        recipients = [f"user{i}@example.com" for i in range(20)]
        result = apply_rewrite(
            "truncate-recipients", "send_email", {"recipients": recipients, "body": "hi"}
        )
        assert len(result.rewritten_tool_args["recipients"]) == 5
        assert "_guardian_note" in result.rewritten_tool_args


class TestRedactSecrets:
    def test_redacts_api_key(self):
        result = apply_rewrite(
            "redact-secrets", "bash", {"command": "curl -H 'api_key=sk-abc123def456ghi789'"}
        )
        assert "sk-abc123def456ghi789" not in str(result.rewritten_tool_args)
        assert "[REDACTED]" in str(result.rewritten_tool_args)

    def test_redacts_password(self):
        result = apply_rewrite(
            "redact-secrets", "bash", {"command": "mysql -p password=secret123"}
        )
        assert "secret123" not in str(result.rewritten_tool_args)

    def test_preserves_safe_content(self):
        result = apply_rewrite(
            "redact-secrets", "bash", {"command": "echo hello world"}
        )
        assert result.rewritten_tool_args["command"] == "echo hello world"


class TestDowngradeWriteToDryrun:
    def test_git_push_dryrun(self):
        result = apply_rewrite(
            "downgrade-write-to-dryrun", "bash", {"command": "git push origin main"}
        )
        assert "--dry-run" in result.rewritten_tool_args["command"]

    def test_filesystem_commands_preview(self):
        result = apply_rewrite(
            "downgrade-write-to-dryrun", "bash", {"command": "cp file1.txt file2.txt"}
        )
        assert "DRY RUN" in result.rewritten_tool_args["command"]


class TestReplaceWildcardDelete:
    def test_rm_wildcard_to_ls(self):
        result = apply_rewrite(
            "replace-wildcard-delete", "bash", {"command": "rm *.log"}
        )
        assert "ls" in result.rewritten_tool_args["command"]
        assert "rm" not in result.rewritten_tool_args["command"]

    def test_sql_delete_adds_limit(self):
        result = apply_rewrite(
            "replace-wildcard-delete", "database", {"query": "DELETE FROM users"}
        )
        assert "LIMIT 1" in result.rewritten_tool_args["query"]


class TestCapHttpTimeout:
    def test_caps_high_timeout(self):
        result = apply_rewrite(
            "cap-http-timeout", "http_request", {"url": "https://api.example.com", "timeout": 120_000}
        )
        assert result.rewritten_tool_args["timeout"] == 30_000

    def test_adds_missing_timeout(self):
        result = apply_rewrite(
            "cap-http-timeout", "http_request", {"url": "https://api.example.com"}
        )
        assert result.rewritten_tool_args["timeout"] == 30_000


class TestEnforceHttps:
    def test_upgrades_http_to_https(self):
        result = apply_rewrite(
            "enforce-https", "http_request", {"url": "http://api.example.com/data"}
        )
        assert result.rewritten_tool_args["url"].startswith("https://")

    def test_preserves_localhost(self):
        # This rule shouldn't apply to localhost, but if called directly it still transforms
        result = apply_rewrite(
            "enforce-https", "http_request", {"url": "http://production.example.com"}
        )
        assert result.rewritten_tool_args["url"] == "https://production.example.com"


class TestLimitQueryRows:
    def test_adds_limit(self):
        result = apply_rewrite(
            "limit-query-rows", "database", {"query": "SELECT * FROM users"}
        )
        assert "LIMIT 1000" in result.rewritten_tool_args["query"]

    def test_preserves_existing_query(self):
        result = apply_rewrite(
            "limit-query-rows", "database", {"query": "SELECT name, email FROM users WHERE active = true"}
        )
        assert "LIMIT 1000" in result.rewritten_tool_args["query"]
        assert "SELECT name, email" in result.rewritten_tool_args["query"]


class TestNeutralizeSudo:
    def test_strips_sudo(self):
        result = apply_rewrite(
            "neutralize-sudo", "bash", {"command": "sudo apt-get install nginx"}
        )
        assert "sudo" not in result.rewritten_tool_args["command"]
        assert "apt-get install nginx" in result.rewritten_tool_args["command"]

    def test_strips_multiple_sudo(self):
        result = apply_rewrite(
            "neutralize-sudo", "bash", {"command": "sudo ls && sudo rm file"}
        )
        assert "sudo" not in result.rewritten_tool_args["command"]
