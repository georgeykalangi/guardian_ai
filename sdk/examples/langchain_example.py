"""DataGuard + LangChain integration examples.

Demonstrates three patterns for integrating DataGuard governance
into LangChain-based AI agent workflows.

Prerequisites:
    pip install dataguard-sdk langchain-core
    # DataGuard server running at http://localhost:8000

Usage:
    export DATAGUARD_URL=http://localhost:8000
    export DATAGUARD_API_KEY=your-api-key
    python langchain_example.py
"""

from __future__ import annotations

import os

from dataguard import GuardianClient, GuardianMiddleware, ToolBlocked, ApprovalRequired, guard


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

DATAGUARD_URL = os.getenv("DATAGUARD_URL", "http://localhost:8000")
DATAGUARD_API_KEY = os.getenv("DATAGUARD_API_KEY", "")

client = GuardianClient(base_url=DATAGUARD_URL, api_key=DATAGUARD_API_KEY)


# ---------------------------------------------------------------------------
# Pattern 1: @guard decorator on plain functions
# ---------------------------------------------------------------------------
# Wrap any function with @guard to evaluate it through DataGuard before
# execution. If the call is denied, ToolBlocked is raised. If rewritten,
# the modified arguments are passed to the function instead.

@guard(client=client, tool_name="file_read", agent_id="example-agent")
def read_file(path: str) -> str:
    """Read a file from disk."""
    with open(path) as f:
        return f.read()


def demo_decorator():
    """Demonstrate the @guard decorator pattern."""
    print("=== Pattern 1: @guard decorator ===")
    try:
        content = read_file(path="/etc/hostname")
        print(f"File content: {content[:100]}")
    except ToolBlocked as e:
        print(f"Blocked by policy: {e}")
    except ApprovalRequired as e:
        print(f"Needs human approval: {e}")
    print()


# ---------------------------------------------------------------------------
# Pattern 2: GuardianMiddleware for framework-level interception
# ---------------------------------------------------------------------------
# GuardianMiddleware wraps a callable so every invocation is governed.
# This is useful when you have a generic tool executor.

def execute_shell(command: str) -> str:
    """Execute a shell command (example — do not use in production)."""
    import subprocess

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


guarded_shell = GuardianMiddleware(
    client=client,
    func=execute_shell,
    tool_name="shell_exec",
    agent_id="example-agent",
)


def demo_middleware():
    """Demonstrate the GuardianMiddleware pattern."""
    print("=== Pattern 2: GuardianMiddleware ===")
    try:
        output = guarded_shell(command="echo hello")
        print(f"Output: {output.strip()}")
    except ToolBlocked as e:
        print(f"Blocked by policy: {e}")
    print()


# ---------------------------------------------------------------------------
# Pattern 3: @tool + @guard stacking for LangChain tools
# ---------------------------------------------------------------------------
# If you have langchain-core installed, you can stack @guard with
# LangChain's @tool decorator. The @guard decorator should be outermost
# so governance runs before LangChain dispatches the tool.

def demo_langchain_tool():
    """Demonstrate LangChain @tool + @guard stacking."""
    print("=== Pattern 3: LangChain @tool + @guard ===")
    try:
        from langchain_core.tools import tool
    except ImportError:
        print("langchain-core not installed — skipping this pattern.")
        print("Install with: pip install langchain-core\n")
        return

    @guard(client=client, tool_name="database_query", agent_id="example-agent")
    @tool
    def query_database(sql: str) -> str:
        """Run a SQL query against the application database."""
        # In real code, this would execute the query
        return f"[mock result for: {sql}]"

    try:
        result = query_database.invoke({"sql": "SELECT * FROM users LIMIT 10"})
        print(f"Query result: {result}")
    except ToolBlocked as e:
        print(f"Blocked by policy: {e}")
    except ApprovalRequired as e:
        print(f"Needs human approval: {e}")
    print()


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

def demo_error_handling():
    """Show how to handle DataGuard errors gracefully."""
    print("=== Error Handling ===")

    @guard(client=client, tool_name="dangerous_op", agent_id="example-agent")
    def dangerous_operation(target: str) -> str:
        return f"Operated on {target}"

    try:
        dangerous_operation(target="production-db")
    except ToolBlocked as e:
        # The agent's action was denied by policy
        print(f"Action denied: {e}")
        print("Suggestion: try a safer alternative or escalate to a human.")
    except ApprovalRequired as e:
        # The action needs human sign-off before proceeding
        print(f"Awaiting approval: {e}")
        print("Decision ID for follow-up: check the exception attributes.")
    except Exception as e:
        # Network errors, server unavailable, etc.
        print(f"DataGuard unavailable: {e}")
        print("Decide your fail-open/fail-closed policy here.")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("DataGuard + LangChain Integration Examples\n")
    demo_decorator()
    demo_middleware()
    demo_langchain_tool()
    demo_error_handling()
