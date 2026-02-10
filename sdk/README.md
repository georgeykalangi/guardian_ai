# DataGuard SDK

Python SDK for the [DataGuard](https://github.com/your-org/dataguard) governance API. Add tool-call governance to any AI agent in 3 lines of code.

## Installation

```bash
pip install dataguard-sdk
```

## Quick Start

```python
from dataguard import GuardianClient

client = GuardianClient(
    base_url="http://localhost:8000",
    agent_id="my-agent",
    tenant_id="my-project",
)

# Synchronous
decision = client.evaluate_sync("bash", {"command": "ls /tmp"})
print(decision.verdict)  # "allow"

# Async
decision = await client.evaluate("bash", {"command": "rm -rf /"})
# Raises ToolBlocked — the command is denied
```

## The `@guard` Decorator

Wrap any function to auto-evaluate through DataGuard before execution:

```python
from dataguard import GuardianClient, guard

client = GuardianClient("http://localhost:8000", agent_id="my-agent")

@guard(client, tool_category="database")
async def query_users(sql: str):
    return db.execute(sql)

# When called, the decorator:
# 1. Builds a ToolCallProposal from function name + kwargs
# 2. Evaluates it through the DataGuard API
# 3. allow  -> executes the function
# 4. rewrite -> executes with rewritten args (configurable)
# 5. deny   -> raises ToolBlocked
# 6. require_approval -> raises ApprovalRequired
result = await query_users(sql="SELECT * FROM users")
```

Works with both `async` and sync functions. Set `auto_rewrite=False` to raise on rewrites instead of silently applying them.

## Middleware

For agent framework integrations, use `GuardianMiddleware`:

```python
from dataguard import GuardianClient, GuardianMiddleware

client = GuardianClient("http://localhost:8000", agent_id="my-agent")
mw = GuardianMiddleware(client)

# Before executing a tool
tool_name, tool_args = await mw.before_tool_call("bash", {"command": "ls"})

# Execute the tool with (possibly rewritten) name/args
result = execute_tool(tool_name, tool_args)

# Report the outcome for audit
await mw.after_tool_call(tool_name="bash", success=True, response_data=result)
```

## Exception Handling

```python
from dataguard import GuardianClient, ToolBlocked, ApprovalRequired

client = GuardianClient("http://localhost:8000", agent_id="my-agent")

try:
    decision = await client.evaluate("bash", {"command": "rm -rf /"})
except ToolBlocked as e:
    print(f"Blocked: {e.decision.reason}")
    print(f"Risk score: {e.decision.risk_score.final_score}")
except ApprovalRequired as e:
    print(f"Needs approval: {e.decision.decision_id}")
```

Set `raise_on_deny=False` to get the decision object back instead of raising on deny:

```python
client = GuardianClient("http://localhost:8000", agent_id="a", raise_on_deny=False)
decision = await client.evaluate("bash", {"command": "rm -rf /"})
if decision.verdict == "deny":
    print("Denied, but no exception raised")
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `base_url` | required | DataGuard server URL |
| `agent_id` | required | Your agent identifier |
| `tenant_id` | `"default"` | Tenant / project ID |
| `timeout` | `5.0` | HTTP timeout in seconds |
| `raise_on_deny` | `True` | Raise `ToolBlocked` on deny |
| `session_id` | auto-generated | Fixed session ID |

## Development

```bash
cd sdk
pip install -e ".[dev]"
pytest tests/ -v
```
