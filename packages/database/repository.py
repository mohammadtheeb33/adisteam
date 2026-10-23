"""Repository abstraction over async SQLAlchemy sessions."""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase


class Repository[ModelT: DeclarativeBase]:
    """Base class for repositories: persistence operations for one ORM model.

    Repositories never commit or roll back. The caller owns the unit of work (typically
    ``Database.transaction()`` or the ``Database.provide_session`` dependency), so several
    repositories can take part in one transaction.

    Subclasses bind the model::

        class HostRepository(Repository[Host]):
            model = Host
    """

    model: type[ModelT]

    def __init__(self, session: AsyncSession) -> None:
        if not isinstance(getattr(type(self), "model", None), type):
            raise TypeError(f"{type(self).__name__} must define the 'model' class attribute")
        self._session = session

    @property
    def session(self) -> AsyncSession:
        """The session this repository works in."""
        return self._session

    async def get(self, identity: object) -> ModelT | None:
        """Return the entity with primary key ``identity``, or ``None``."""
        return await self._session.get(self.model, identity)

    def add(self, entity: ModelT) -> ModelT:
        """Stage ``entity`` for insertion; it is written at the next flush or commit."""
        self._session.add(entity)
        return entity

    async def delete(self, entity: ModelT) -> None:
        """Stage ``entity`` for deletion."""
        await self._session.delete(entity)

    async def flush(self) -> None:
        """Write staged changes to the database inside the current transaction."""
        await self._session.flush()
