"""
app/middleware/request_id.py

Lightweight request-ID middleware.

Attaches a UUID request_id to every request via:
  - A state attribute on the Request object (request.state.request_id)
  - An X-Request-ID response header

The request_id is included in structured error responses so operators
can correlate client errors with server logs.

Never logs credentials, email content, or internal paths.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject a unique request_id into every request/response cycle."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Accept a caller-supplied ID (e.g., from load balancer) or generate one.
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = request_id

        response: Response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
