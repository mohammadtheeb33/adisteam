"""Async session factory."""

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create the session factory bound to ``engine``.

    - ``expire_on_commit=False``: objects stay readable after commit without an implicit
      (and, in async code, illegal) lazy refresh.
    - ``autoflush=False``: flushes happen explicitly or at commit, never as a hidden side
      effect of a query.
    """
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
