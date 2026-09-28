"""
api/v1/users.py

User management endpoints.

POST /api/v1/users/register  — create a new user account
POST /api/v1/users/login     — authenticate, receive JWT
GET  /api/v1/users/me        — current user profile
PATCH /api/v1/users/{id}/role — admin: change a user's role
GET  /api/v1/users/          — admin: list all users

Registration policy:
    - First-ever user is automatically granted the 'admin' role.
    - Subsequent registrations require an admin Bearer JWT (X-API-Key also works
      so that service bootstrapping can happen without a user JWT).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from app.api.auth import verify_api_key_or_jwt, verify_api_key
from app.api.jwt_auth import create_access_token, get_current_user, require_role
from app.models.user_model import UserModel

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    role: str = Field("analyst", pattern="^(admin|analyst|viewer)$")
    tenant_id: str = Field(
        "default_tenant",
        min_length=2,
        max_length=64,
        description="Organization/tenant identifier. All users sharing a tenant_id form an isolated workspace.",
    )


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user_id: str
    email: str
    role: str
    tenant_id: str  # included so frontend can initialize tenant context


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]


class RoleUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|viewer)$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Hash a password using bcrypt. Raises RuntimeError if passlib unavailable."""
    from app.core.security import hash_password
    return hash_password(password)


def _verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash. Raises RuntimeError if passlib unavailable."""
    from app.core.security import verify_password
    try:
        return verify_password(plain, hashed)
    except RuntimeError:
        # passlib unavailable — never authenticate
        logger.error("PASSWORD_VERIFICATION_FAILED: passlib unavailable")
        return False


def _user_to_response(u: UserModel) -> UserResponse:
    return UserResponse(
        id=u.id,
        email=u.email,
        role=u.role,
        tenant_id=u.tenant_id,
        is_active=u.is_active,
        created_at=u.created_at,
        last_login=u.last_login,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(body: RegisterRequest, request: Request):
    """
    Create a user account.

    - First user ever → automatically becomes admin (no auth required).
    - Subsequent users → require admin JWT or X-API-Key.

    The tenant_id from the request body is stored as-is and embedded in the
    resulting JWT. It is the caller's responsibility to supply the correct
    tenant slug for their organization.
    """
    from app.repositories.db import SessionLocal

    with SessionLocal() as session:
        # Check whether any user exists
        from sqlalchemy import select, func
        count_q = session.execute(select(func.count()).select_from(UserModel))
        user_count: int = count_q.scalar_one()

        is_first_user = user_count == 0

        if is_first_user:
            # Bootstrap protection: require ADMIN_BOOTSTRAP_TOKEN env var
            import os
            bootstrap_token = os.environ.get("ADMIN_BOOTSTRAP_TOKEN", "")
            if bootstrap_token:
                # Token is configured — verify it matches
                provided_token = request.headers.get("X-Bootstrap-Token", "")
                if not provided_token or provided_token != bootstrap_token:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="ADMIN_BOOTSTRAP_TOKEN required to create first admin user. Set X-Bootstrap-Token header.",
                    )
            # If ADMIN_BOOTSTRAP_TOKEN is not set, open bootstrap is allowed
            # (dev/test environments without the env var set)

        if not is_first_user:
            # Enforce admin auth for subsequent registrations
            auth = request.headers.get("Authorization", "")
            api_key_hdr = request.headers.get("X-API-Key", "")
            from app.core.config import settings

            is_admin_key = bool(api_key_hdr and api_key_hdr == settings.SECRET_KEY)
            is_admin_jwt = False

            if auth.lower().startswith("bearer "):
                try:
                    from fastapi.security import HTTPAuthorizationCredentials
                    creds = HTTPAuthorizationCredentials(
                        scheme="Bearer", credentials=auth.split(" ", 1)[1]
                    )
                    caller = await get_current_user(creds)
                    is_admin_jwt = caller.is_admin()
                except HTTPException:
                    pass

            if not (is_admin_key or is_admin_jwt):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only admins can register new users",
                )

        # Check email uniqueness
        from sqlalchemy import select as sa_select
        existing = session.execute(
            sa_select(UserModel).where(UserModel.email == body.email)
        ).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        role = "admin" if is_first_user else body.role
        user = UserModel(
            id=str(uuid.uuid4()),
            email=body.email,
            hashed_password=_hash_password(body.password),
            role=role,
            tenant_id=body.tenant_id,
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        session.add(user)
        session.commit()
        session.refresh(user)

        logger.info(
            "User registered id=%s email=%s role=%s tenant=%s",
            user.id, user.email, user.role, user.tenant_id,
        )
        return _user_to_response(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login and obtain a JWT access token",
)
async def login(body: LoginRequest):
    """Authenticate with email + password, receive a signed JWT.

    The JWT embeds tenant_id from the database record (authoritative).
    Clients must use the tenant_id from the token response to initialize
    their tenant context — it is NOT accepted as a login input field.
    """
    from app.repositories.db import SessionLocal
    from sqlalchemy import select as sa_select
    from app.core.config import settings

    with SessionLocal() as session:
        user = session.execute(
            sa_select(UserModel).where(UserModel.email == body.email)
        ).scalar_one_or_none()

    if not user or not _verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Update last_login
    with SessionLocal() as session:
        db_user = session.get(UserModel, user.id)
        if db_user:
            db_user.last_login = datetime.now(timezone.utc)
            session.commit()

    token = create_access_token(user.id, user.email, user.role, user.tenant_id)
    expire_seconds = settings.JWT_EXPIRE_MINUTES * 60

    logger.info("User logged in id=%s role=%s tenant=%s", user.id, user.role, user.tenant_id)
    return TokenResponse(
        access_token=token,
        expires_in=expire_seconds,
        user_id=user.id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
)
async def me(current_user: UserModel = Depends(get_current_user)):
    return _user_to_response(current_user)


@router.get(
    "/",
    response_model=List[UserResponse],
    summary="List all users (admin only)",
)
async def list_users(
    _admin: UserModel = Depends(require_role("admin")),
):
    from app.repositories.db import SessionLocal
    from sqlalchemy import select as sa_select

    with SessionLocal() as session:
        users = session.execute(sa_select(UserModel).order_by(UserModel.created_at)).scalars().all()
    return [_user_to_response(u) for u in users]


@router.patch(
    "/{user_id}/role",
    response_model=UserResponse,
    summary="Update a user's role (admin only)",
)
async def update_role(
    user_id: str,
    body: RoleUpdateRequest,
    _admin: UserModel = Depends(require_role("admin")),
):
    from app.repositories.db import SessionLocal

    with SessionLocal() as session:
        user = session.get(UserModel, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.role = body.role
        session.commit()
        session.refresh(user)
        return _user_to_response(user)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a user (admin only)",
)
async def deactivate_user(
    user_id: str,
    _admin: UserModel = Depends(require_role("admin")),
):
    from app.repositories.db import SessionLocal

    with SessionLocal() as session:
        user = session.get(UserModel, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.is_active = False
        session.commit()
