"""Async SQLAlchemy persistence for the FastAPI runtime.

PostgreSQL/Supabase uses ``postgresql+asyncpg``.  SQLite remains an
isolated test fixture through the synchronous compatibility repository until
the test environment installs ``aiosqlite`` (declared in requirements.txt).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.contracts.audit import AuditRecord
from app.contracts.evidence import EvidenceItem
from app.contracts.result import InvestigationResult
from app.core.config import settings
from app.models.base import Base
from app.repositories.historical_repository import HistoricalRepository


ASYNC_PERSISTENCE_ENABLED = settings.DATABASE_URL.startswith("postgresql+asyncpg://") or settings.DATABASE_URL.startswith("sqlite+aiosqlite://")

# Pass statement_cache_size=0 to fix asyncpg on PgBouncer (Supabase default)
engine_kwargs = {"pool_pre_ping": True}
if "postgresql+asyncpg" in settings.DATABASE_URL:
    engine_kwargs["connect_args"] = {"statement_cache_size": 0}

async_engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs) if ASYNC_PERSISTENCE_ENABLED else None
AsyncSessionLocal = async_sessionmaker(async_engine, expire_on_commit=False, class_=AsyncSession) if async_engine else None

async def get_async_session():
    if AsyncSessionLocal:
        async with AsyncSessionLocal() as session:
            yield session


async def init_async_db() -> None:
    if async_engine is None:
        return
    async with async_engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def persist_investigation(
    result: InvestigationResult,
    evidence: list[EvidenceItem],
    audit_records: list[AuditRecord],
    user_id: str | None = None,
    tenant_id: str = "default_tenant",
) -> None:
    if AsyncSessionLocal is None:
        raise RuntimeError("Async persistence is unavailable for the configured DATABASE_URL")
    async with AsyncSessionLocal() as session:
        # ``run_sync`` keeps all ORM operations in one AsyncSession-backed
        # transaction while reusing the audited repository mapping logic.
        await session.run_sync(
            lambda sync_session: HistoricalRepository(sync_session).save_investigation(
                result, evidence, audit_records, user_id=user_id, tenant_id=tenant_id
            )
        )
