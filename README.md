# DataGuard

Inline governance layer for AI agents. Sits between your agent and its tools to score risk, enforce policy, and rewrite unsafe actions in real time.

```
Agent wants to call a tool
        |
        v
   [ DataGuard ]  <-- deterministic policies + risk scoring
        |
   allow / rewrite / require approval / deny
        |
        v
   Tool executes (or doesn't)
```

DataGuard doesn't just block dangerous actions — it **rewrites them safely** so your agent keeps working. A `git push --force` becomes `git push`. A `SELECT *` without LIMIT gets `LIMIT 1000` appended. An `http://` URL gets upgraded to `https://`.

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [API Reference](#api-reference)
- [Policy System](#policy-system)
- [Rewrite Rules](#rewrite-rules)
- [Risk Scoring](#risk-scoring)
- [Configuration](#configuration)
- [Writing Custom Policies](#writing-custom-policies)
- [Integration Guide](#integration-guide)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)

## Quick Start

### Prerequisites

- Python 3.12+
- (Optional) PostgreSQL for persistent audit logs

### Install

```bash
git clone <repo-url> && cd agentic_ai
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the server

```bash
# Using SQLite for development (no Postgres needed)
GUARDIAN_DATABASE_URL="sqlite+aiosqlite:///dataguard.db" \
  uvicorn guardian.main:app --reload
```

The API is live at `http://localhost:8000`. Interactive docs at `http://localhost:8000/docs`.

### Try it — block a dangerous command

```bash
curl -s -X POST http://localhost:8000/v1/guardian/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "proposal": {
      "tool_name": "bash",
      "tool_args": {"command": "rm -rf /var/data"}
    },
    "context": {
      "agent_id": "my-agent",
      "tenant_id": "my-project"
    }
  }' | python3 -m json.tool
```

Response:

```json
{
    "decision_id": "a1b2c3d4-...",
    "proposal_id": "e5f6g7h8-...",
    "verdict": "deny",
    "risk_score": {
        "deterministic_score": 100,
        "llm_score": null,
        "final_score": 100,
        "explanation": "Matched rule: deny-rm-rf"
    },
    "matched_rule_id": "deny-rm-rf",
    "reason": "Recursive force-delete is unconditionally blocked.",
    "rewritten_call": null,
    "requires_human": false
}
```

### Try it — rewrite an unsafe command

```bash
curl -s -X POST http://localhost:8000/v1/guardian/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "proposal": {
      "tool_name": "bash",
      "tool_args": {"command": "sudo apt-get install nginx"}
    },
    "context": {"agent_id": "my-agent"}
  }' | python3 -m json.tool
```

Response:

```json
{
    "verdict": "rewrite",
    "reason": "sudo removed — operations should not require elevated privileges.",
    "rewritten_call": {
        "original_tool_name": "bash",
        "original_tool_args": {"command": "sudo apt-get install nginx"},
        "rewritten_tool_name": "bash",
        "rewritten_tool_args": {"command": "apt-get install nginx"},
        "rewrite_rule_id": "neutralize-sudo",
        "description": "Strip sudo prefix from commands"
    }
}
```

The agent receives the rewritten command and continues working — no interruption, no human needed.

## How It Works

Every tool call flows through a two-stage pipeline:

### Stage 1: Deterministic Policy Rules

JSON rules are evaluated **top-to-bottom, first match wins**. If a rule matches, the verdict is immediate and reproducible. No LLM involved.

```
Proposal ──> Rule 1: deny-rm-rf         ── match? ──> DENY (done)
             Rule 2: deny-drop-table     ── match? ──> DENY (done)
             Rule 3: require-approval-payment ── match? ──> REQUIRE_APPROVAL (done)
             Rule 4: rewrite-sudo        ── match? ──> REWRITE (done)
             ...
             No match ──> proceed to Stage 2
```

### Stage 2: Risk Scoring (heuristic / LLM)

If no deterministic rule matched, the proposal goes through risk scoring. The current v1 scorer uses regex heuristics for:

- **PII detection**: SSNs, emails, credit card numbers, passwords in args
- **Prompt injection detection**: "ignore previous instructions", "you are now", etc.
- **Category-based risk**: payment and auth tools get a base score bump

The risk score (0-100) maps to a verdict:

| Score | Verdict |
|-------|---------|
| 0-30 | `allow` |
| 31-60 | `rewrite` (if a rewrite rule applies) or `require_approval` |
| 61-100 | `require_approval` |

### Four Possible Verdicts

| Verdict | What happens | Agent experience |
|---------|-------------|-----------------|
| `allow` | Tool call proceeds as-is | Transparent |
| `rewrite` | Tool call is modified to be safe, then proceeds | Transparent (response includes rewritten args) |
| `require_approval` | Tool call is paused until a human approves or rejects | Agent waits |
| `deny` | Tool call is blocked | Agent gets denial reason |

## API Reference

### `POST /v1/guardian/evaluate`

Evaluate a single tool call proposal.

**Request body:**

```json
{
  "proposal": {
    "tool_name": "bash",
    "tool_args": {"command": "git push --force origin main"},
    "tool_category": "code_execution",
    "intended_outcome": "Push changes to remote"
  },
  "context": {
    "agent_id": "deployment-agent",
    "tenant_id": "acme-corp",
    "session_id": "sess-123",
    "user_id": "user-456",
    "conversation_summary": "User asked to deploy latest changes."
  },
  "policy_id": null
}
```

**Required fields:** `proposal.tool_name` and `context.agent_id`. Everything else has defaults.

**Response:** `GuardianDecision` (see Quick Start examples above).

### `POST /v1/guardian/evaluate-batch`

Evaluate multiple proposals in one request. Body is an array of evaluate requests.

```bash
curl -X POST http://localhost:8000/v1/guardian/evaluate-batch \
  -H "Content-Type: application/json" \
  -d '[
    {"proposal": {"tool_name": "bash", "tool_args": {"command": "echo safe"}}, "context": {"agent_id": "a1"}},
    {"proposal": {"tool_name": "bash", "tool_args": {"command": "rm -rf /"}}, "context": {"agent_id": "a1"}}
  ]'
```

Returns an array of `GuardianDecision` in the same order.

### `POST /v1/guardian/approve/{decision_id}`

Approve or reject a pending `require_approval` decision.

**Query params:**
- `approved` (bool, required): `true` to allow, `false` to deny
- `reviewer` (string, optional): who is approving

```bash
curl -X POST "http://localhost:8000/v1/guardian/approve/abc-123?approved=true&reviewer=admin"
```

### `POST /v1/guardian/report-outcome`

Post-execution hook. After the tool runs, report the outcome for the audit trail.

```json
{
  "proposal_id": "the-original-proposal-id",
  "tool_name": "bash",
  "success": true,
  "response_data": {"output": "Pushed to origin/main"},
  "execution_duration_ms": 1200
}
```

### `GET /v1/policies/active`

Returns the currently loaded policy spec.

### `PUT /v1/policies/active`

Hot-reload the policy without restarting the server. Send a full `PolicySpec` JSON body.

### `GET /health`

Returns `{"status": "healthy", "service": "dataguard"}`.

### `GET /ready`

Returns `{"status": "ready"}`.

## Policy System

Policies are JSON files containing ordered rule arrays. They live in `policies/` and are loaded at startup.

### Rule structure

```json
{
  "rule_id": "deny-rm-rf",
  "description": "Block recursive force-delete commands",
  "match": {
    "tool_name": {"in": ["bash", "shell"]},
    "tool_args_contains": {"pattern": "rm\\s+-(r|f|rf|fr)"}
  },
  "action": "deny",
  "reason": "Recursive force-delete is unconditionally blocked."
}
```

### Match conditions

All conditions within a rule are ANDed — every condition must match for the rule to fire.

| Condition | Matches against | Operators |
|-----------|----------------|-----------|
| `tool_name` | The tool's canonical name | `in`, `eq`, `not_in` |
| `tool_category` | The tool's category enum | `in`, `eq` |
| `tool_args_contains` | JSON-serialized tool args | `pattern` (regex) |
| `tool_args_field_check` | A specific field in tool args | See below |

**Field check operators:**

| Operator | Description | Example value |
|----------|-------------|---------------|
| `length_gt` | List field length > value | `5` |
| `length_lt` | List field length < value | `2` |
| `eq` | Field equals value | `"active"` |
| `gt` / `lt` | Numeric comparison | `1000` |
| `contains` | String contains substring | `"admin"` |
| `matches` | String matches regex | `"^https://"` |
| `domain_not_in` | URL domain not in allowlist | `["github.com", "localhost"]` |
| `domain_in` | URL domain in list | `["api.internal.com"]` |

### Actions

| Action | Effect |
|--------|--------|
| `allow` | Explicitly allow (stops further rule evaluation) |
| `deny` | Block the tool call |
| `require_approval` | Pause for human approval |
| `rewrite` | Transform the tool call using a rewrite rule (requires `rewrite_rule_id`) |

### Default policy rules (shipped)

| Rule | Action | What it catches |
|------|--------|----------------|
| `deny-rm-rf` | deny | `rm -rf`, `rm -f` in shell commands |
| `deny-drop-table` | deny | `DROP TABLE`, `DROP DATABASE` in SQL |
| `deny-env-exfiltration` | deny | Piping env vars to curl |
| `deny-secret-in-url` | deny | API keys, tokens in URL query params |
| `require-approval-payment` | require_approval | Any tool with category `payment` |
| `require-approval-auth-changes` | require_approval | Credential modifications |
| `require-approval-mass-email` | require_approval | Emails to >5 recipients |
| `require-approval-unknown-domain` | require_approval | HTTP requests to non-allowlisted domains |
| `rewrite-force-flags` | rewrite | `--force` / `-f` in git/shell commands |
| `rewrite-enforce-https` | rewrite | `http://` URLs (except localhost) |
| `rewrite-sudo` | rewrite | `sudo` prefix in commands |

### Rule evaluation order

Rules are evaluated **top-to-bottom**. The first matching rule wins. This means:

1. Put deny rules first (hard blocks)
2. Then require-approval rules (human gate)
3. Then rewrite rules (auto-fix)
4. Then allow rules (explicit permits)

If no rule matches, the proposal goes to risk scoring.

## Rewrite Rules

The rewrite engine is DataGuard's differentiator. Instead of blocking an agent and halting the workflow, DataGuard fixes the unsafe action and lets work continue.

### Built-in rewrite transforms

| Rule ID | What it does | Before | After |
|---------|-------------|--------|-------|
| `strip-force-flags` | Removes `--force` / `-f` | `git push --force origin main` | `git push origin main` |
| `sandbox-code-exec` | Adds sandbox + read-only flags | `{"code": "..."}` | `{"code": "...", "sandbox": true, "read_only": true}` |
| `truncate-recipients` | Caps email recipients at 5 | 20 recipients | 5 recipients + note |
| `redact-secrets` | Replaces secrets with `[REDACTED]` | `api_key=sk-abc123` | `[REDACTED]` |
| `downgrade-write-to-dryrun` | Adds `--dry-run` or preview | `git push origin main` | `git push --dry-run origin main` |
| `replace-wildcard-delete` | Converts `rm *` to `ls *` | `rm *.log` | `ls *.log` |
| `cap-http-timeout` | Caps timeout at 30s | `timeout: 120000` | `timeout: 30000` |
| `enforce-https` | Upgrades to HTTPS | `http://api.example.com` | `https://api.example.com` |
| `limit-query-rows` | Adds `LIMIT 1000` to SELECTs | `SELECT * FROM users` | `SELECT * FROM users LIMIT 1000` |
| `neutralize-sudo` | Strips sudo prefix | `sudo apt-get install nginx` | `apt-get install nginx` |

### Custom rewrite rules

Register custom rules in your code:

```python
from guardian.engine.rewriter import RewriteRule, register_rule

def my_transform(tool_name, tool_args):
    # Your logic here
    return tool_name, modified_args

register_rule(RewriteRule(
    rule_id="my-custom-rewrite",
    description="What this rule does",
    applies_to=lambda name, args: name == "my_tool",
    transform=my_transform,
))
```

Then reference it in your policy JSON with `"rewrite_rule_id": "my-custom-rewrite"`.

## Risk Scoring

When no deterministic rule matches, DataGuard runs heuristic risk scoring.

### What the v1 scorer detects

**PII patterns** (score +20):
- Social Security Numbers: `123-45-6789`
- Email addresses
- Credit card numbers: `4111-1111-1111-1111`
- Password assignments: `password=secret123`

**Prompt injection patterns** (score +40):
- `ignore previous instructions`
- `you are now`
- `system:` prefix
- `override instructions`
- `forget everything`

**Category risk** (score +15):
- Tool category is `payment` or `auth`

### Score thresholds

Configured in the policy JSON under `risk_thresholds`:

```json
{
  "risk_thresholds": {
    "allow_max": 30,
    "rewrite_confirm_min": 31,
    "rewrite_confirm_max": 60,
    "block_approval_min": 61
  }
}
```

### Plugging in a real LLM scorer

Implement the `BaseRiskScorer` interface:

```python
from guardian.engine.risk_scorer import BaseRiskScorer, RiskAssessment

class AnthropicRiskScorer(BaseRiskScorer):
    async def score(self, proposal, context) -> RiskAssessment:
        # Call Claude API to assess risk
        # Return RiskAssessment(final_score=..., explanation=..., flags=[...])
        ...
```

## Configuration

All settings are configured via environment variables with the `GUARDIAN_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDIAN_DATABASE_URL` | `postgresql+asyncpg://guardian:guardian@localhost:5432/guardian` | Database connection string |
| `GUARDIAN_DEFAULT_POLICY_PATH` | `policies/default_policy.json` | Path to the default policy file |
| `GUARDIAN_LLM_PROVIDER` | `stub` | Risk scorer backend: `stub`, `anthropic`, `openai` |
| `GUARDIAN_LLM_API_KEY` | (empty) | API key for the LLM provider |
| `GUARDIAN_LLM_MODEL` | `claude-sonnet-4-5-20250929` | Model to use for risk scoring |
| `GUARDIAN_HOST` | `0.0.0.0` | Server bind address |
| `GUARDIAN_PORT` | `8000` | Server port |
| `GUARDIAN_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warning`, `error` |

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

### Development mode (no Postgres)

For local development, use SQLite:

```bash
GUARDIAN_DATABASE_URL="sqlite+aiosqlite:///dataguard.db" uvicorn guardian.main:app --reload
```

## Writing Custom Policies

### Step 1: Create your policy JSON

```json
{
  "policy_id": "my-org-policy",
  "version": 1,
  "description": "Policy for Acme Corp production agents.",
  "scope": ["tool_call", "message_send"],
  "rules": [
    {
      "rule_id": "block-production-db-writes",
      "description": "No writes to production database",
      "match": {
        "tool_category": {"eq": "database"},
        "tool_args_contains": {"pattern": "(?i)(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP)"}
      },
      "action": "deny",
      "reason": "Production database writes are blocked for this agent."
    },
    {
      "rule_id": "cap-api-spend",
      "description": "Block API calls over $10",
      "match": {
        "tool_category": {"eq": "payment"},
        "tool_args_field_check": {
          "field": "amount",
          "condition": "gt",
          "value": 1000
        }
      },
      "action": "deny",
      "reason": "Transaction exceeds the $10 limit for automated agents."
    }
  ],
  "risk_thresholds": {
    "allow_max": 20,
    "rewrite_confirm_min": 21,
    "rewrite_confirm_max": 50,
    "block_approval_min": 51
  }
}
```

### Step 2: Load it

**Option A:** Set the env var:

```bash
GUARDIAN_DEFAULT_POLICY_PATH=policies/my-org-policy.json uvicorn guardian.main:app
```

**Option B:** Hot-reload via API:

```bash
curl -X PUT http://localhost:8000/v1/policies/active \
  -H "Content-Type: application/json" \
  -d @policies/my-org-policy.json
```

## Integration Guide

### Direct HTTP integration

Any agent framework that makes HTTP calls can integrate:

```python
import httpx

async def guarded_tool_call(tool_name: str, tool_args: dict) -> dict:
    """Wrap any tool call with DataGuard evaluation."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/v1/guardian/evaluate",
            json={
                "proposal": {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                },
                "context": {
                    "agent_id": "my-agent",
                    "tenant_id": "my-project",
                },
            },
        )
        decision = response.json()

        if decision["verdict"] == "allow":
            return execute_tool(tool_name, tool_args)
        elif decision["verdict"] == "rewrite":
            rewritten = decision["rewritten_call"]
            return execute_tool(
                rewritten["rewritten_tool_name"],
                rewritten["rewritten_tool_args"],
            )
        elif decision["verdict"] == "require_approval":
            raise PendingApprovalError(decision["decision_id"], decision["reason"])
        else:  # deny
            raise ToolBlockedError(decision["reason"])
```

### Multi-tenancy

Every request accepts a `tenant_id` in the context. Use this to scope evaluations per project, team, or customer:

```json
{
  "context": {
    "agent_id": "support-bot",
    "tenant_id": "acme-corp"
  }
}
```

Tenant IDs flow through to the audit log, so you can query decisions per tenant.

## Testing

### Run the full test suite

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

### Test structure

```
tests/
  test_api/
    test_guardian_endpoint.py    # End-to-end API tests (10 tests)
  test_engine/
    test_policy_evaluator.py    # Deterministic rule matching (15 tests)
    test_rewriter.py            # All 10 rewrite rules (14 tests)
    test_orchestrator.py        # Full decision pipeline (10 tests)
```

55 tests covering:
- Every policy rule in the default policy fires correctly
- Every rewrite rule transforms as expected
- The orchestrator merges deterministic + risk scoring correctly
- The approval flow (approve -> allow, reject -> deny)
- Risk scoring flags PII and prompt injection patterns
- API endpoints return correct status codes and response shapes
- Batch evaluation works

### Run a specific test file

```bash
python -m pytest tests/test_engine/test_rewriter.py -v
python -m pytest tests/test_api/ -v
```

## Project Structure

```
agentic_ai/
  policies/
    default_policy.json          # Shipped policy (11 rules)
  src/guardian/
    main.py                      # FastAPI app factory
    config.py                    # Settings (env vars)
    dependencies.py              # DI: orchestrator, policy loader
    schemas/
      tool_call.py               # ToolCallProposal, ToolCallContext, ToolResponse
      policy.py                  # PolicySpec, PolicyRule, MatchCondition
      decision.py                # GuardianDecision, RiskScore, DecisionVerdict
      rewrite.py                 # RewriteResult
      audit.py                   # AuditLogEntry, AuditQuery
    engine/
      orchestrator.py            # DecisionOrchestrator (core decision logic)
      policy_evaluator.py        # Deterministic first-match-wins rule engine
      rewriter.py                # 10 rewrite transforms + registry
      risk_scorer.py             # BaseRiskScorer interface + StubRiskScorer
    api/v1/
      guardian.py                # POST /evaluate, /evaluate-batch, /approve, /report-outcome
      policies.py                # GET/PUT /policies/active
      audit.py                   # POST /audit/query
    models/
      audit_log.py               # SQLAlchemy ORM for audit_log table
    db/
      session.py                 # Async session factory
      repositories/
        audit_repo.py            # Audit log persistence + queries
  tests/                         # 55 tests
```

## Roadmap

### v1.0 (current)
- [x] Deterministic policy engine (first-match-wins JSON rules)
- [x] 10 rewrite transforms
- [x] Heuristic risk scoring (PII, prompt injection, category risk)
- [x] Approval flow for human-in-the-loop
- [x] Multi-tenancy support (`tenant_id` on every request)
- [x] 55-test safety regression suite

### v1.1 (next)
- [ ] Persistent audit logs (Postgres integration)
- [ ] Python SDK (`pip install dataguard-sdk`) with `@guard` decorator
- [ ] LangChain / CrewAI middleware adapters
- [ ] LLM-backed risk scorer (Anthropic Claude)

### v2.0
- [ ] Policy inheritance (org -> team -> project)
- [ ] Dashboard (runs list, run detail, policy editor)
- [ ] Policy simulation ("what-if" analysis on past traces)
- [ ] Risk drift monitoring (alert on score distribution changes)
- [ ] Webhook notifications for deny/approval events

## License

MIT
