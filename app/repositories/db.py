from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys
from app.models.base import Base
from app.core.config import settings


def _sync_database_url(url: str) -> str:
    """Use the configured production database instead of an in-memory runtime DB.

    The existing historical repository remains SQLAlchemy-session compatible;
    async API callers can safely offload it until the async repository is
    selected by deployment. Both standard Supabase PostgreSQL URLs and the
    SQLite test URL are normalized here.
    """
    if url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    if url.startswith("sqlite+aiosqlite://"):
        return url.replace("sqlite+aiosqlite://", "sqlite://", 1)
    return url


DATABASE_URL = _sync_database_url(settings.DATABASE_URL)

# Tests use one isolated in-memory SQLite engine per Python test process;
# production always honors DATABASE_URL (PostgreSQL/Supabase included).
# ``python -m pytest`` imports ``_pytest`` before application modules, while
# the public ``pytest`` name is not guaranteed to be present yet.
_is_test_runtime = any(name == "pytest" or name.startswith("_pytest") for name in sys.modules)
_is_test_sqlite = _is_test_runtime
if _is_test_sqlite:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    _sqlite_options = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
    engine = create_engine(DATABASE_URL, connect_args=_sqlite_options)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    from app.models import Base
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
