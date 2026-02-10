# Contributing to DataGuard

## Development Setup

### Prerequisites

- Python 3.12+ (`python3 --version`)
- Git

### Clone and install

```bash
git clone <repo-url>
cd agentic_ai
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Environment note (macOS with conda/miniforge)

If you have conda or miniforge installed, their site-packages can contaminate `sys.path`. If you see import errors from the wrong Python version, prefix commands with `PYTHONPATH=""`:

```bash
PYTHONPATH="" .venv/bin/python -m pytest tests/ -v
```

### Run the server locally

```bash
# No Postgres needed for dev — uses SQLite
GUARDIAN_DATABASE_URL="sqlite+aiosqlite:///dataguard.db" \
  uvicorn guardian.main:app --reload
```

API docs: http://localhost:8000/docs

### Run tests

```bash
python -m pytest tests/ -v          # Full suite (55 tests)
python -m pytest tests/ -v -x       # Stop on first failure
python -m pytest tests/test_engine/  # Engine tests only
python -m pytest tests/test_api/     # API tests only
```

### Lint

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Architecture

### Decision flow

```
ToolCallProposal + ToolCallContext
        |
        v
  PolicyEvaluator.match()    <-- deterministic JSON rules, first-match-wins
        |
  rule matched?
     YES --> map action to verdict (deny/allow/require_approval/rewrite)
     NO  --> RiskScorer.score()  <-- heuristic or LLM-based
                |
                v
           Apply risk_thresholds --> verdict
        |
        v
  GuardianDecision (returned to caller)
```

### Key design decisions

1. **Deterministic rules always win.** If a policy rule matches, the risk scorer is never called. This makes behavior predictable and auditable.

2. **First-match-wins ordering.** Rules are evaluated top-to-bottom. Put the most restrictive rules first (deny), then approval gates, then rewrites. This mirrors firewall rule semantics.

3. **Rewrite over block.** When possible, DataGuard rewrites an unsafe tool call into a safe one rather than blocking it. This keeps agents productive.

4. **Pure function rewrites.** Every rewrite rule is `(tool_name, tool_args) -> (tool_name, tool_args)` with no side effects. This makes them trivially testable.

5. **Multi-tenancy from day 1.** Every request carries a `tenant_id`. This is threaded through to audit logs and will support per-tenant policies in v2.

## Adding a new policy rule

1. Define the rule in `policies/default_policy.json` (or a custom policy file)
2. If the rule uses `action: "rewrite"`, create the rewrite transform in `src/guardian/engine/rewriter.py`
3. Add a test in `tests/test_engine/test_policy_evaluator.py`
4. Add a test in `tests/test_engine/test_orchestrator.py` for end-to-end behavior
5. Run `python -m pytest tests/ -v` to verify

## Adding a new rewrite rule

1. Write the `applies_to` function (when does this rule activate?)
2. Write the `transform` function (what does it change?)
3. Register it in `init_default_rules()` in `src/guardian/engine/rewriter.py`
4. Add tests in `tests/test_engine/test_rewriter.py`
5. Reference it from a policy rule with `"rewrite_rule_id": "your-rule-id"`

## Adding a new match condition

The policy evaluator supports custom match conditions. To add one:

1. Add the new condition field to `MatchCondition` in `src/guardian/schemas/policy.py`
2. Implement the matching logic in `PolicyEvaluator._rule_matches()` in `src/guardian/engine/policy_evaluator.py`
3. Add tests

## Code style

- Pydantic v2 for all schemas
- Type hints everywhere
- No `datetime.utcnow()` — use `datetime.now(timezone.utc)`
- No global mutable state except the rewrite registry (initialized at startup)
- Tests use `pytest` + `pytest-asyncio`
