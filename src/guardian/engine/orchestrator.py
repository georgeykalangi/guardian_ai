"""Decision orchestrator — merges deterministic policy evaluation with LLM risk scoring.

Decision flow:
  ToolCallProposal + Context
         |
  [1] PolicyEvaluator.match(proposal, policy)
         |
    matched? ── YES ─> map action to verdict
         |
         NO
         |
  [2] RiskScorer.score(proposal, context)
         |
  [3] Apply risk_thresholds:
         0-30   -> ALLOW
         31-60  -> REWRITE (if applicable) or REQUIRE_APPROVAL
         61-100 -> REQUIRE_APPROVAL
         |
  [4] Return GuardianDecision
"""

from __future__ import annotations

from guardian.engine.policy_evaluator import PolicyEvaluator, PolicyMatchResult
from guardian.engine.rewriter import apply_rewrite, find_applicable_rewrite
from guardian.engine.risk_scorer import BaseRiskScorer, RiskAssessment
from guardian.schemas.decision import (
    DecisionVerdict,
    GuardianDecision,
    RewrittenCall,
    RiskScore,
)
from guardian.schemas.policy import PolicyAction, PolicySpec, RiskThresholds
from guardian.schemas.tool_call import ToolCallContext, ToolCallProposal


# Maps deterministic policy actions to risk scores and verdicts
_ACTION_SCORE: dict[PolicyAction, int] = {
    PolicyAction.DENY: 100,
    PolicyAction.REQUIRE_APPROVAL: 80,
    PolicyAction.REWRITE: 50,
    PolicyAction.ALLOW: 0,
}

_ACTION_VERDICT: dict[PolicyAction, DecisionVerdict] = {
    PolicyAction.DENY: DecisionVerdict.DENY,
    PolicyAction.REQUIRE_APPROVAL: DecisionVerdict.REQUIRE_APPROVAL,
    PolicyAction.REWRITE: DecisionVerdict.REWRITE,
    PolicyAction.ALLOW: DecisionVerdict.ALLOW,
}


class DecisionOrchestrator:
    def __init__(
        self,
        policy: PolicySpec,
        risk_scorer: BaseRiskScorer,
    ):
        self._policy = policy
        self._risk_scorer = risk_scorer
        self._evaluator = PolicyEvaluator()
        # In-memory store for pending approvals
        self._pending: dict[str, GuardianDecision] = {}

    def update_policy(self, policy: PolicySpec) -> None:
        """Hot-reload policy without restarting."""
        self._policy = policy

    async def evaluate(
        self,
        proposal: ToolCallProposal,
        context: ToolCallContext,
        policy_id: str | None = None,
    ) -> GuardianDecision:
        policy = self._policy  # In v1, we use the loaded default

        # Step 1: deterministic rule matching
        rule_match = self._evaluator.match(proposal, policy)

        if rule_match is not None:
            decision = self._build_deterministic_decision(proposal, rule_match)
        else:
            # Step 2: LLM / heuristic risk scoring
            assessment = await self._risk_scorer.score(proposal, context)
            # Step 3: apply thresholds
            decision = self._build_threshold_decision(
                proposal, assessment, policy.risk_thresholds
            )

        # Track pending approvals
        if decision.requires_human:
            self._pending[decision.decision_id] = decision

        return decision

    async def resolve_approval(
        self,
        decision_id: str,
        approved: bool,
        reviewer: str,
    ) -> GuardianDecision | None:
        decision = self._pending.pop(decision_id, None)
        if decision is None:
            return None

        if approved:
            return GuardianDecision(
                decision_id=decision.decision_id,
                proposal_id=decision.proposal_id,
                verdict=DecisionVerdict.ALLOW,
                risk_score=decision.risk_score,
                matched_rule_id=decision.matched_rule_id,
                reason=f"Approved by {reviewer}. Original: {decision.reason}",
                requires_human=False,
            )
        else:
            return GuardianDecision(
                decision_id=decision.decision_id,
                proposal_id=decision.proposal_id,
                verdict=DecisionVerdict.DENY,
                risk_score=decision.risk_score,
                matched_rule_id=decision.matched_rule_id,
                reason=f"Rejected by {reviewer}. Original: {decision.reason}",
                requires_human=False,
            )

    def _build_deterministic_decision(
        self,
        proposal: ToolCallProposal,
        rule_match: PolicyMatchResult,
    ) -> GuardianDecision:
        action = rule_match.action
        score = _ACTION_SCORE[action]
        verdict = _ACTION_VERDICT[action]

        rewritten = None
        if action == PolicyAction.REWRITE and rule_match.rewrite_rule_id:
            rw = apply_rewrite(
                rule_match.rewrite_rule_id, proposal.tool_name, proposal.tool_args
            )
            rewritten = RewrittenCall(
                original_tool_name=proposal.tool_name,
                original_tool_args=proposal.tool_args,
                rewritten_tool_name=rw.rewritten_tool_name,
                rewritten_tool_args=rw.rewritten_tool_args,
                rewrite_rule_id=rw.rule_id,
                description=rw.description,
            )

        return GuardianDecision(
            proposal_id=proposal.proposal_id,
            verdict=verdict,
            risk_score=RiskScore(
                deterministic_score=score,
                llm_score=None,
                final_score=score,
                explanation=f"Matched rule: {rule_match.rule_id}",
            ),
            matched_rule_id=rule_match.rule_id,
            reason=rule_match.reason,
            rewritten_call=rewritten,
            requires_human=(action == PolicyAction.REQUIRE_APPROVAL),
        )

    def _build_threshold_decision(
        self,
        proposal: ToolCallProposal,
        assessment: RiskAssessment,
        thresholds: RiskThresholds,
    ) -> GuardianDecision:
        score = assessment.final_score

        if score <= thresholds.allow_max:
            verdict = DecisionVerdict.ALLOW
            requires_human = False
        elif score <= thresholds.rewrite_confirm_max:
            # Try to find an applicable rewrite
            rw_rule = find_applicable_rewrite(proposal.tool_name, proposal.tool_args)
            if rw_rule:
                verdict = DecisionVerdict.REWRITE
                requires_human = False
            else:
                verdict = DecisionVerdict.REQUIRE_APPROVAL
                requires_human = True
        else:
            verdict = DecisionVerdict.REQUIRE_APPROVAL
            requires_human = True

        rewritten = None
        if verdict == DecisionVerdict.REWRITE:
            rw_rule = find_applicable_rewrite(proposal.tool_name, proposal.tool_args)
            if rw_rule:
                rw = apply_rewrite(rw_rule.rule_id, proposal.tool_name, proposal.tool_args)
                rewritten = RewrittenCall(
                    original_tool_name=proposal.tool_name,
                    original_tool_args=proposal.tool_args,
                    rewritten_tool_name=rw.rewritten_tool_name,
                    rewritten_tool_args=rw.rewritten_tool_args,
                    rewrite_rule_id=rw.rule_id,
                    description=rw.description,
                )

        return GuardianDecision(
            proposal_id=proposal.proposal_id,
            verdict=verdict,
            risk_score=RiskScore(
                deterministic_score=None,
                llm_score=score,
                final_score=score,
                explanation=assessment.explanation,
            ),
            reason=assessment.explanation,
            rewritten_call=rewritten,
            requires_human=requires_human,
        )
