"""Validation tests for all Pydantic schemas."""

import pytest
from pydantic import ValidationError

from guardian.schemas.audit import AuditLogEntry, AuditQuery
from guardian.schemas.auth import ApiKeyInfo, Role
from guardian.schemas.decision import (
    DecisionVerdict,
    GuardianDecision,
    RewrittenCall,
    RiskScore,
)
from guardian.schemas.policy import (
    MatchCondition,
    PolicyAction,
    PolicyRule,
    PolicySpec,
    RiskThresholds,
)
from guardian.schemas.rewrite import RewriteResult
from guardian.schemas.tool_call import (
    ToolCallContext,
    ToolCallProposal,
    ToolCategory,
    ToolResponse,
)


# ---------------------------------------------------------------------------
# ToolCallProposal
# ---------------------------------------------------------------------------


class TestToolCallProposal:
    def test_minimal(self):
        p = ToolCallProposal(tool_name="bash")
        assert p.tool_name == "bash"
        assert p.tool_args == {}
        assert p.tool_category == ToolCategory.UNKNOWN
        assert p.intended_outcome == ""
        assert p.proposal_id  # auto-generated UUID

    def test_tool_name_normalized(self):
        p = ToolCallProposal(tool_name="  BASH  ")
        assert p.tool_name == "bash"

    def test_tool_name_required(self):
        with pytest.raises(ValidationError):
            ToolCallProposal(tool_name="")

    def test_tool_name_max_length(self):
        with pytest.raises(ValidationError):
            ToolCallProposal(tool_name="x" * 257)

    def test_intended_outcome_max_length(self):
        with pytest.raises(ValidationError):
            ToolCallProposal(tool_name="bash", intended_outcome="x" * 1025)

    def test_full(self):
        p = ToolCallProposal(
            tool_name="http_request",
            tool_args={"url": "https://example.com"},
            tool_category="http_request",
            intended_outcome="Fetch data",
        )
        assert p.tool_category == ToolCategory.HTTP_REQUEST
        assert p.tool_args["url"] == "https://example.com"


class TestToolCallContext:
    def test_defaults(self):
        c = ToolCallContext(agent_id="a1")
        assert c.agent_id == "a1"
        assert c.tenant_id == "default"
        assert c.user_id is None
        assert c.conversation_summary == ""
        assert c.prior_decisions == []
        assert c.session_id  # auto-generated

    def test_conversation_summary_max_length(self):
        with pytest.raises(ValidationError):
            ToolCallContext(agent_id="a1", conversation_summary="x" * 4097)


class TestToolResponse:
    def test_minimal(self):
        r = ToolResponse(proposal_id="p1", tool_name="bash", success=True)
        assert r.success is True
        assert r.error_message is None

    def test_failure(self):
        r = ToolResponse(
            proposal_id="p1",
            tool_name="bash",
            success=False,
            error_message="timeout",
        )
        assert r.success is False
        assert r.error_message == "timeout"


# ---------------------------------------------------------------------------
# PolicySpec
# ---------------------------------------------------------------------------


class TestPolicySpec:
    def test_minimal(self):
        p = PolicySpec(policy_id="test-v1")
        assert p.version == 1
        assert p.rules == []
        assert p.risk_thresholds.allow_max == 30

    def test_with_rules(self):
        p = PolicySpec(
            policy_id="test-v1",
            rules=[
                PolicyRule(
                    rule_id="deny-rm",
                    match=MatchCondition(tool_name={"in": ["bash"]}),
                    action=PolicyAction.DENY,
                    reason="blocked",
                )
            ],
        )
        assert len(p.rules) == 1
        assert p.rules[0].action == PolicyAction.DENY

    def test_rule_id_required(self):
        with pytest.raises(ValidationError):
            PolicyRule(
                rule_id="",
                match=MatchCondition(),
                action=PolicyAction.ALLOW,
            )


class TestRiskThresholds:
    def test_defaults(self):
        t = RiskThresholds()
        assert t.allow_max == 30
        assert t.rewrite_confirm_min == 31
        assert t.rewrite_confirm_max == 60
        assert t.block_approval_min == 61

    def test_custom_values(self):
        t = RiskThresholds(allow_max=50, block_approval_min=80)
        assert t.allow_max == 50

    def test_out_of_range(self):
        with pytest.raises(ValidationError):
            RiskThresholds(allow_max=101)

        with pytest.raises(ValidationError):
            RiskThresholds(allow_max=-1)


# ---------------------------------------------------------------------------
# DecisionVerdict / GuardianDecision
# ---------------------------------------------------------------------------


class TestRiskScore:
    def test_valid(self):
        rs = RiskScore(final_score=50, explanation="medium risk")
        assert rs.deterministic_score is None
        assert rs.llm_score is None

    def test_out_of_range(self):
        with pytest.raises(ValidationError):
            RiskScore(final_score=101)

        with pytest.raises(ValidationError):
            RiskScore(final_score=-1)


class TestGuardianDecision:
    def test_allow(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.ALLOW,
            risk_score=RiskScore(final_score=10),
        )
        assert d.requires_human is False
        assert d.rewritten_call is None
        assert d.decision_id  # auto-generated

    def test_rewrite_with_call(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.REWRITE,
            risk_score=RiskScore(final_score=40),
            rewritten_call=RewrittenCall(
                original_tool_name="bash",
                original_tool_args={"command": "sudo rm"},
                rewritten_tool_name="bash",
                rewritten_tool_args={"command": "rm"},
                rewrite_rule_id="neutralize-sudo",
            ),
        )
        assert d.rewritten_call.rewrite_rule_id == "neutralize-sudo"

    def test_serialization_roundtrip(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.DENY,
            risk_score=RiskScore(final_score=100, explanation="blocked"),
            reason="rm -rf detected",
        )
        json_str = d.model_dump_json()
        d2 = GuardianDecision.model_validate_json(json_str)
        assert d2.verdict == DecisionVerdict.DENY
        assert d2.risk_score.final_score == 100


# ---------------------------------------------------------------------------
# RewriteResult
# ---------------------------------------------------------------------------


class TestRewriteResult:
    def test_construction(self):
        r = RewriteResult(
            rule_id="strip-force-flags",
            original_tool_name="bash",
            original_tool_args={"command": "git push --force"},
            rewritten_tool_name="bash",
            rewritten_tool_args={"command": "git push"},
            description="Removed --force",
        )
        assert r.rule_id == "strip-force-flags"


# ---------------------------------------------------------------------------
# AuditQuery / AuditLogEntry
# ---------------------------------------------------------------------------


class TestAuditQuery:
    def test_defaults(self):
        q = AuditQuery()
        assert q.limit == 50
        assert q.offset == 0
        assert q.verdict is None

    def test_limit_max(self):
        with pytest.raises(ValidationError):
            AuditQuery(limit=501)

    def test_offset_negative(self):
        with pytest.raises(ValidationError):
            AuditQuery(offset=-1)


class TestAuditLogEntry:
    def test_from_dict(self):
        entry = AuditLogEntry(
            id=1,
            decision_id="d1",
            proposal_id="p1",
            agent_id="a1",
            session_id="s1",
            tenant_id="default",
            user_id=None,
            tool_name="bash",
            tool_category="code_execution",
            verdict="allow",
            risk_score_final=10,
            matched_rule_id=None,
            reason="safe",
            requires_human=False,
            approved_by=None,
            outcome_success=True,
            created_at="2025-01-01T00:00:00",
        )
        assert entry.verdict == "allow"
        assert entry.outcome_success is True


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------


class TestApiKeyInfo:
    def test_defaults(self):
        k = ApiKeyInfo(key="test-123")
        assert k.tenant_id == "default"
        assert k.role == Role.ADMIN

    def test_agent_role(self):
        k = ApiKeyInfo(key="agent-key", tenant_id="acme", role=Role.AGENT)
        assert k.role == Role.AGENT
        assert k.tenant_id == "acme"


class TestToolCategory:
    def test_all_values(self):
        categories = [e.value for e in ToolCategory]
        assert "file_system" in categories
        assert "database" in categories
        assert "http_request" in categories
        assert "code_execution" in categories
        assert "message_send" in categories
        assert "payment" in categories
        assert "auth" in categories
        assert "unknown" in categories


class TestDecisionVerdictEnum:
    def test_all_values(self):
        verdicts = [e.value for e in DecisionVerdict]
        assert "allow" in verdicts
        assert "deny" in verdicts
        assert "rewrite" in verdicts
        assert "require_approval" in verdicts


class TestPolicyActionEnum:
    def test_all_values(self):
        actions = [e.value for e in PolicyAction]
        assert "allow" in actions
        assert "deny" in actions
        assert "rewrite" in actions
        assert "require_approval" in actions
