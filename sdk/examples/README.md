# DataGuard SDK Examples

Integration examples showing how to use the DataGuard SDK with AI agent frameworks.

## Prerequisites

1. A running DataGuard server:
   ```bash
   cd ../.. && docker compose up -d
   # or: uvicorn guardian.main:app --reload
   ```

2. Install the SDK:
   ```bash
   pip install dataguard-sdk
   # or from source: cd .. && pip install -e .
   ```

3. Set environment variables:
   ```bash
   export DATAGUARD_URL=http://localhost:8000
   export DATAGUARD_API_KEY=your-api-key
   ```

## Examples

### `langchain_example.py`

Demonstrates three integration patterns:

| Pattern | Use case | How it works |
|---------|----------|-------------|
| **`@guard` decorator** | Wrap individual functions | Evaluates each call through DataGuard before execution. Denied calls raise `ToolBlocked`. |
| **`GuardianMiddleware`** | Wrap a generic executor | Wraps any callable so every invocation is governed. Good for tool dispatchers. |
| **`@tool` + `@guard` stacking** | LangChain tools | Stack `@guard` (outer) with LangChain's `@tool` (inner). Governance runs before LangChain dispatch. |

Run it:
```bash
python langchain_example.py
```

## Error Handling

All patterns raise the same exceptions:

- **`ToolBlocked`** — policy denied the action. The agent should try an alternative or inform the user.
- **`ApprovalRequired`** — a human must approve before the action proceeds. The decision ID is available on the exception.
- **`DataGuardError`** — base exception for SDK errors (network failures, unexpected responses).

Decide your **fail-open vs fail-closed** strategy: if the DataGuard server is unreachable, should the agent proceed (fail-open) or halt (fail-closed)? The SDK does not make this choice for you.
