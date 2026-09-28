"""
api/auth.py

Authentication middleware for ASHIELDER.

Two parallel auth strategies coexist:

1. Legacy / service-to-service: X-API-Key header
   - Used by existing integrations.
   - verify_api_key(request) — raises 401/429, returns key string.

2. JWT Bearer tokens: Authorization: Bearer <token>
   - Used by human users after POST /api/v1/users/login.
   - verify_jwt_token(request) — returns UserModel.
   - require_role("admin") — role-gated variant.

Dual-auth (accept either):
   verify_api_key_or_jwt(request) — returns api_key string OR UserModel.
"""

from __future__ import annotations

import time
from typing import Optional, Union

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader

from app.core.config import settings

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Simple in-memory rate limiter (e.g. 10 requests per minute per IP)
RATE_LIMIT = 10
RATE_LIMIT_WINDOW = 60
_rate_limits: dict = {}


def check_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()

    if client_ip not in _rate_limits:
        _rate_limits[client_ip] = []

    # Clean up old requests
    _rate_limits[client_ip] = [
        t for t in _rate_limits[client_ip] if current_time - t < RATE_LIMIT_WINDOW
    ]

    if len(_rate_limits[client_ip]) >= RATE_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
        )

    _rate_limits[client_ip].append(current_time)


# ---------------------------------------------------------------------------
# Legacy: X-API-Key
# ---------------------------------------------------------------------------

async def verify_api_key(
    request: Request, api_key: str = Depends(api_key_header)
) -> str:
    """Validate X-API-Key header (legacy / service-to-service auth)."""
    if settings.DEMO_MODE:
        return "demo_mode_sih_2026"
    check_rate_limit(request)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key is missing",
        )
    if api_key != settings.SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key


# ---------------------------------------------------------------------------
# JWT: Bearer token
# ---------------------------------------------------------------------------

async def verify_jwt_token(request: Request):
    """
    FastAPI dependency: require a valid Bearer JWT.
    Returns the authenticated UserModel.
    """
    from app.api.jwt_auth import get_current_user
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

    scheme = request.headers.get("Authorization", "")
    if not scheme.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = scheme.split(" ", 1)[1]
    from fastapi.security import HTTPAuthorizationCredentials
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    return await get_current_user(creds)


def require_role(*roles: str):
    """
    Dependency factory: ensure the JWT user has one of the specified roles.
    Re-exports from jwt_auth for convenience.
    """
    from app.api.jwt_auth import require_role as _require_role
    return _require_role(*roles)


# ---------------------------------------------------------------------------
# Dual-auth: accept EITHER X-API-Key OR Bearer JWT
# ---------------------------------------------------------------------------

async def verify_api_key_or_jwt(
    request: Request,
    api_key: Optional[str] = Depends(api_key_header),
):
    """
    Dual-auth dependency: accepts X-API-Key (returns key string) OR Bearer JWT
    (returns UserModel). Raises 401 if neither is present/valid.

    When DEMO_MODE=true, bypasses authentication entirely and returns a
    deterministic demo context. This MUST be disabled in production.

    Precedence: DEMO_MODE > Bearer > X-API-Key.
    """
    # 0. Demo mode bypass — SIH demonstration only
    if settings.DEMO_MODE:
        return "demo_mode_sih_2026"

    check_rate_limit(request)

    # 1. Try Bearer JWT first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
        from fastapi.security import HTTPAuthorizationCredentials
        from app.api.jwt_auth import get_current_user
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        return await get_current_user(creds)

    # 2. Fall back to X-API-Key
    if api_key and api_key == settings.SECRET_KEY:
        return api_key

    # 3. Neither present / valid
    if api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide X-API-Key or Authorization: Bearer <token>",
    )
