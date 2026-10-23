"""Repository base class: delegation to the session, and no transaction control."""

from unittest.mock import MagicMock, create_autospec

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from packages.database import Repository


class _TestBase(DeclarativeBase):
    """Isolated declarative base so test models never touch ADIS metadata."""


class Widget(_TestBase):
    """Minimal mapped model."""

    __tablename__ = "widget"

    id: Mapped[int] = mapped_column(primary_key=True)


class WidgetRepository(Repository[Widget]):
    """Repository under test."""

    model = Widget


@pytest.fixture
def session() -> MagicMock:
    mock: MagicMock = create_autospec(AsyncSession, instance=True)
    return mock


async def test_get_delegates_to_session(session: MagicMock) -> None:
    widget = Widget(id=1)
    session.get.return_value = widget

    assert await WidgetRepository(session).get(1) is widget
    session.get.assert_awaited_once_with(Widget, 1)


def test_add_stages_entity(session: MagicMock) -> None:
    widget = Widget(id=1)

    assert WidgetRepository(session).add(widget) is widget
    session.add.assert_called_once_with(widget)


async def test_delete_and_flush_delegate_to_session(session: MagicMock) -> None:
    widget = Widget(id=1)
    repository = WidgetRepository(session)

    await repository.delete(widget)
    await repository.flush()

    session.delete.assert_awaited_once_with(widget)
    session.flush.assert_awaited_once_with()


async def test_repository_never_controls_the_transaction(session: MagicMock) -> None:
    repository = WidgetRepository(session)

    repository.add(Widget(id=1))
    await repository.get(1)
    await repository.flush()

    session.commit.assert_not_called()
    session.rollback.assert_not_called()
    session.close.assert_not_called()


def test_session_property(session: MagicMock) -> None:
    assert WidgetRepository(session).session is session


def test_repository_without_model_is_rejected(session: MagicMock) -> None:
    class IncompleteRepository(Repository[Widget]):
        """Forgets to bind ``model``."""

    with pytest.raises(TypeError, match="model"):
        IncompleteRepository(session)
