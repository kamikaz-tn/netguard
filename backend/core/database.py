"""
netguard/backend/core/database.py
──────────────────────────────────
Async SQLAlchemy engine + session factory.
All models import Base from here.
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from .config import settings


# ── Engine ────────────────────────────────────────────────────────────────────
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,       # logs SQL when debug=True
    future=True,
)

# ── Session factory ───────────────────────────────────────────────────────────
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Base class all models inherit from ───────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Dependency injected into every route that needs DB ───────────────────────
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# ── Create all tables on startup ──────────────────────────────────────────────
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
