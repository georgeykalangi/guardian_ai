"""Tests for the deterministic policy evaluator."""

import pytest

from guardian.engine.policy_evaluator import PolicyEvaluator
from guardian.schemas.policy import PolicyAction, PolicySpec
from tests.conftest import make_proposal


class TestPolicyEvaluator:
    def setup_method(self):
        self.evaluator = PolicyEvaluator()

    def test_deny_rm_rf(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="bash",
            tool_args={"command": "rm -rf /tmp/data"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.DENY
        assert result.rule_id == "deny-rm-rf"

    def test_deny_rm_force(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="shell",
            tool_args={"command": "rm -f important.db"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.DENY

    def test_deny_drop_table(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="database",
            tool_args={"query": "DROP TABLE users;"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.DENY
        assert result.rule_id == "deny-drop-table"

    def test_deny_drop_database(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="sql",
            tool_args={"query": "drop database production"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.DENY

    def test_deny_secret_in_url(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="http_request",
            tool_args={"url": "https://api.example.com?api_key=sk-abc123"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.DENY

    def test_require_approval_payment(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="stripe_charge",
            tool_category="payment",
            tool_args={"amount": 9999, "currency": "usd"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REQUIRE_APPROVAL
        assert result.rule_id == "require-approval-payment"

    def test_require_approval_mass_email(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="send_email",
            tool_args={
                "recipients": [f"user{i}@example.com" for i in range(10)],
                "subject": "Newsletter",
            },
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REQUIRE_APPROVAL

    def test_require_approval_unknown_domain(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="http_request",
            tool_args={"url": "https://evil.com/exfiltrate"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REQUIRE_APPROVAL

    def test_allow_known_domain(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="http_request",
            tool_args={"url": "https://api.github.com/repos"},
        )
        result = self.evaluator.match(proposal, default_policy)
        # Should NOT match the unknown-domain rule
        assert result is None or result.rule_id != "require-approval-unknown-domain"

    def test_rewrite_force_flags(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="bash",
            tool_args={"command": "git push --force origin main"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REWRITE
        assert result.rewrite_rule_id == "strip-force-flags"

    def test_rewrite_enforce_https(self, default_policy: PolicySpec):
        # Use an allowlisted domain with http:// so the unknown-domain rule doesn't fire first
        proposal = make_proposal(
            tool_name="http_request",
            tool_args={"url": "http://api.github.com/repos"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REWRITE
        assert result.rewrite_rule_id == "enforce-https"

    def test_rewrite_sudo(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="bash",
            tool_args={"command": "sudo apt-get install nginx"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is not None
        assert result.action == PolicyAction.REWRITE
        assert result.rewrite_rule_id == "neutralize-sudo"

    def test_safe_command_passes(self, default_policy: PolicySpec):
        proposal = make_proposal(
            tool_name="bash",
            tool_args={"command": "ls -la /tmp"},
        )
        result = self.evaluator.match(proposal, default_policy)
        assert result is None  # No rule matched — passes to risk scorer

    def test_no_conditions_no_match(self, default_policy: PolicySpec):
        """A rule with no conditions should never match."""
        proposal = make_proposal(tool_name="anything")
        from guardian.engine.policy_evaluator import PolicyEvaluator
        from guardian.schemas.policy import MatchCondition, PolicyRule, PolicySpec, RiskThresholds

        policy = PolicySpec(
            policy_id="test",
            rules=[
                PolicyRule(
                    rule_id="empty",
                    match=MatchCondition(),  # no conditions
                    action="deny",
                )
            ],
        )
        result = self.evaluator.match(proposal, policy)
        assert result is None
