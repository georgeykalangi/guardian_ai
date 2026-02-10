"""Tests for SDK Pydantic models."""

from dataguard.models import (
    DecisionVerdict,
    EvaluateRequest,
    GuardianDecision,
    OutcomeReport,
    RewrittenCall,
    RiskScore,
    ToolCallContext,
    ToolCallProposal,
    ToolCategory,
)


class TestToolCategory:
    def test_enum_values(self):
        assert ToolCategory.FILE_SYSTEM == "file_system"
        assert ToolCategory.DATABASE == "database"
        assert ToolCategory.CODE_EXECUTION == "code_execution"
        assert ToolCategory.UNKNOWN == "unknown"

    def test_all_categories(self):
        assert len(ToolCategory) == 8


class TestDecisionVerdict:
    def test_enum_values(self):
        assert DecisionVerdict.ALLOW == "allow"
        assert DecisionVerdict.DENY == "deny"
        assert DecisionVerdict.REWRITE == "rewrite"
        assert DecisionVerdict.REQUIRE_APPROVAL == "require_approval"


class TestToolCallProposal:
    def test_minimal(self):
        p = ToolCallProposal(tool_name="bash")
        assert p.tool_name == "bash"
        assert p.tool_args == {}
        assert p.tool_category == ToolCategory.UNKNOWN
        assert p.proposal_id  # auto-generated

    def test_full(self):
        p = ToolCallProposal(
            tool_name="http_fetch",
            tool_args={"url": "https://example.com"},
            tool_category=ToolCategory.HTTP_REQUEST,
            intended_outcome="Fetch data",
        )
        assert p.tool_args["url"] == "https://example.com"
        assert p.tool_category == ToolCategory.HTTP_REQUEST

    def test_serialization_roundtrip(self):
        p = ToolCallProposal(
            tool_name="bash",
            tool_args={"command": "ls"},
        )
        data = p.model_dump(mode="json")
        p2 = ToolCallProposal.model_validate(data)
        assert p2.tool_name == p.tool_name
        assert p2.tool_args == p.tool_args
        assert p2.proposal_id == p.proposal_id


class TestToolCallContext:
    def test_defaults(self):
        ctx = ToolCallContext(agent_id="agent-1")
        assert ctx.agent_id == "agent-1"
        assert ctx.tenant_id == "default"
        assert ctx.user_id is None
        assert ctx.session_id  # auto-generated

    def test_full(self):
        ctx = ToolCallContext(
            agent_id="agent-1",
            tenant_id="proj-x",
            user_id="user-42",
            session_id="sess-1",
        )
        assert ctx.tenant_id == "proj-x"
        assert ctx.user_id == "user-42"


class TestGuardianDecision:
    def test_allow_decision(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.ALLOW,
            risk_score=RiskScore(final_score=10),
        )
        assert d.verdict == "allow"
        assert d.risk_score.final_score == 10
        assert d.rewritten_call is None
        assert not d.requires_human

    def test_rewrite_decision(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.REWRITE,
            risk_score=RiskScore(final_score=60),
            rewritten_call=RewrittenCall(
                original_tool_name="bash",
                original_tool_args={"command": "rm -rf /"},
                rewritten_tool_name="bash",
                rewritten_tool_args={"command": "ls /"},
                rewrite_rule_id="rule-1",
            ),
        )
        assert d.rewritten_call is not None
        assert d.rewritten_call.rewritten_tool_args["command"] == "ls /"

    def test_serialization_roundtrip(self):
        d = GuardianDecision(
            proposal_id="p1",
            verdict=DecisionVerdict.DENY,
            risk_score=RiskScore(final_score=95, explanation="Dangerous"),
            reason="Blocked",
        )
        data = d.model_dump(mode="json")
        d2 = GuardianDecision.model_validate(data)
        assert d2.verdict == d.verdict
        assert d2.risk_score.final_score == d.risk_score.final_score
        assert d2.reason == d.reason


class TestEvaluateRequest:
    def test_construction(self):
        req = EvaluateRequest(
            proposal=ToolCallProposal(tool_name="bash", tool_args={"command": "ls"}),
            context=ToolCallContext(agent_id="agent-1"),
        )
        assert req.proposal.tool_name == "bash"
        assert req.context.agent_id == "agent-1"
        assert req.policy_id is None

    def test_json_roundtrip(self):
        req = EvaluateRequest(
            proposal=ToolCallProposal(tool_name="bash"),
            context=ToolCallContext(agent_id="agent-1"),
            policy_id="policy-v2",
        )
        data = req.model_dump(mode="json")
        req2 = EvaluateRequest.model_validate(data)
        assert req2.policy_id == "policy-v2"


class TestOutcomeReport:
    def test_construction(self):
        r = OutcomeReport(
            proposal_id="p1",
            tool_name="bash",
            success=True,
            response_data={"output": "file.txt"},
        )
        assert r.success is True
        assert r.response_data == {"output": "file.txt"}
        assert r.error_message is None
