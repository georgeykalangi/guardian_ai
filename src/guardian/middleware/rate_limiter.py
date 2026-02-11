"""In-memory sliding-window rate limiter middleware."""

from __future__ import annotations

import time
from collections import defaultdict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

_EXEMPT_PATHS = {"/health", "/ready"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter keyed by API key or client IP.

    Args:
        app: The ASGI application.
        rpm: Requests per minute. 0 disables rate limiting entirely.
    """

    def __init__(self, app, rpm: int = 60) -> None:
        super().__init__(app)
        self.rpm = rpm
        self.window = 60.0  # seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next) -> Response:
        if self.rpm == 0:
            return await call_next(request)

        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        key = request.headers.get("x-api-key") or (
            request.client.host if request.client else "unknown"
        )

        now = time.monotonic()
        cutoff = now - self.window

        # Prune expired timestamps
        timestamps = self._requests[key]
        self._requests[key] = [t for t in timestamps if t > cutoff]
        timestamps = self._requests[key]

        if len(timestamps) >= self.rpm:
            retry_after = int(self.window - (now - timestamps[0])) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded."},
                headers={"Retry-After": str(retry_after)},
            )

        timestamps.append(now)
        return await call_next(request)
