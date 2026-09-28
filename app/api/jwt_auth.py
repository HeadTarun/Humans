"""
api/jwt_auth.py

JWT-based authentication for ASHIELDER.

Token payload:
    sub   — user UUID
    email — user email address
    role  — admin | analyst | viewer
    exp   — expiry timestamp (UTC)
    iss   — "ashielder"

Usage (as FastAPI dependency):
    @router.get("/me")
    async def me(user: UserModel = Depends(get_current_user)):
        ...

    @router.post("/admin-only")
    async def admin(user: UserModel = Depends(require_role("admin"))):
        ...
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings

logger = logging.getLogger(__name__)

_BEARER = HTTPBearer(auto_error=False)
_ISSUER = "ashielder"


def _jwt_secret() -> str:
    """Resolve JWT secret: JWT_SECRET_KEY falls back to SECRET_KEY."""
    return settings.JWT_SECRET_KEY or settings.SECRET_KEY


# ---------------------------------------------------------------------------
# Token creation
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: str,
    email: str,
    role: str,
    tenant_id: str,
    expires_in: Optional[timedelta] = None,
) -> str:
    """
    Mint a signed JWT access token.

    Args:
        user_id:    UUID string of the user.
        email:      User's email address.
        role:       One of admin | analyst | viewer.
        tenant_id:  Organization/tenant the user belongs to (authoritative).
        expires_in: Override the default expiry window.

    Returns:
        Signed JWT string (HS256).

    Security note:
        tenant_id is embedded in the token and validated server-side.
        Clients MUST NOT send tenant_id as a query param or body field for
        authorization purposes — the token claim is the authoritative source.
    """
    try:
        from jose import jwt
    except ImportError as exc:
        raise RuntimeError(
            "python-jose is required for JWT auth. "
            "Add 'python-jose[cryptography]' to requirements.txt"
        ) from exc

    if expires_in is None:
        expires_in = timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant_id": tenant_id,
        "iss": _ISSUER,
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=settings.JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# Token decoding / validation
# ---------------------------------------------------------------------------

def decode_access_token(token: str) -> dict:
    """
    Decode and validate a JWT token.

    Raises:
        HTTPException 401 on invalid / expired tokens.
    """
    try:
        from jose import JWTError, jwt
        from jose.exceptions import ExpiredSignatureError
    except ImportError as exc:
        raise RuntimeError("python-jose is required for JWT auth") from exc

    try:
        payload = jwt.decode(
            token,
            _jwt_secret(),
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_iss": True},
            issuer=_ISSUER,
        )
        return payload
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_BEARER),
):
    """
    FastAPI dependency: extract and validate the Bearer JWT, return the UserModel.

    Raises 401 if no valid token is provided.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing 'sub' claim",
        )

    # Load from DB to get fresh is_active / role state
    from app.repositories.db import SessionLocal
    from app.models.user_model import UserModel

    with SessionLocal() as session:
        user = session.get(UserModel, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    return user


def require_role(*roles: str):
    """
    FastAPI dependency factory: enforce that the JWT user has one of the given roles.

    Usage:
        @router.delete("/cases/{id}", dependencies=[Depends(require_role("admin"))])
    """
    async def _check(user=Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not permitted. Required: {list(roles)}",
            )
        return user

    return _check


async def optional_jwt_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_BEARER),
):
    """
    FastAPI dependency: return the authenticated user if a valid Bearer token is
    provided, or None if no Authorization header is present.

    Used for dual-auth endpoints that accept either X-API-Key OR Bearer JWT.
    """
    if not credentials:
        return None
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None
