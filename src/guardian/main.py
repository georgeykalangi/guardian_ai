"""FastAPI application factory for DataGuard."""

import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from guardian.config import settings
from guardian.db.session import engine
from guardian.engine.rewriter import init_default_rules
from guardian.models.base import Base
from guardian.models.audit_log import AuditLog  # noqa: F401 — register model

logger = logging.getLogger("guardian")


def configure_logging() -> None:
    """Set up structured JSON-style logging."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}'
    )
    handler.setFormatter(formatter)
    root = logging.getLogger("guardian")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "request_id=%s method=%s path=%s status=%d duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        response.headers["X-Request-ID"] = request_id
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    # Startup
    configure_logging()
    init_default_rules()
    # Auto-create tables for dev/test (production uses Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("DataGuard started")
    yield
    # Shutdown
    logger.info("DataGuard shutting down")


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

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request logging
    app.add_middleware(RequestLoggingMiddleware)

    # Include routers
    from guardian.api.health import router as health_router
    from guardian.api.v1.audit import router as audit_router
    from guardian.api.v1.guardian import router as guardian_router
    from guardian.api.v1.policies import router as policies_router
    from guardian.api.v1.stats import router as stats_router
    from guardian.api.dashboard import router as dashboard_router

    app.include_router(health_router)
    app.include_router(guardian_router)
    app.include_router(audit_router)
    app.include_router(policies_router)
    app.include_router(stats_router)
    app.include_router(dashboard_router)

    return app


app = create_app()
