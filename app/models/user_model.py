"""
models/user_model.py

SQLAlchemy ORM model for system users (RBAC + multi-tenancy).

Roles:
    admin   — full access to all cases across the tenant + admin operations
    analyst — create investigations + read/manage tenant cases
    viewer  — read-only access to tenant cases

Tenant isolation:
    Every user belongs to exactly one tenant_id (organization).
    All data queries MUST be scoped by tenant_id from the authenticated principal.
    user_id is NOT a substitute for tenant_id.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="analyst"
    )  # admin | analyst | viewer
    tenant_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True, default="default_tenant"
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def is_admin(self) -> bool:
        return self.role == "admin"

    def can_create(self) -> bool:
        return self.role in ("admin", "analyst")

    def can_read_all(self) -> bool:
        """Admin can read all cases within their tenant."""
        return self.role == "admin"

    def __repr__(self) -> str:  # pragma: no cover
        return f"<UserModel id={self.id} email={self.email} role={self.role} tenant={self.tenant_id}>"
