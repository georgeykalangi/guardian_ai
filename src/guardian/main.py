"""FastAPI application factory for DataGuard."""

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI

from guardian.engine.rewriter import init_default_rules


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # Startup
    init_default_rules()
    yield
    # Shutdown (cleanup if needed)


def create_app() -> FastAPI:
    app = FastAPI(
        title="DataGuard",
        description=(
            "Inline governance layer for AI agents — "
            "scores risk, enforces policy, rewrites unsafe actions."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # Include routers
    from guardian.api.health import router as health_router
    from guardian.api.v1.audit import router as audit_router
    from guardian.api.v1.guardian import router as guardian_router
    from guardian.api.v1.policies import router as policies_router

    app.include_router(health_router)
    app.include_router(guardian_router)
    app.include_router(audit_router)
    app.include_router(policies_router)

    return app


app = create_app()
