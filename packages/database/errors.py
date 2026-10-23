"""Classification of database errors: outages versus problems with the data."""

from typing import Final

from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

# SQLSTATE classes and codes that describe the server or connection, not the data:
# 08 connection exception, 53 insufficient resources, 57 operator intervention
# (shutdown, statement timeout), 40001 serialization failure, 40P01 deadlock.
_TRANSIENT_SQLSTATE_CLASSES: Final = frozenset({"08", "53", "57"})
_TRANSIENT_SQLSTATES: Final = frozenset({"40001", "40P01"})


def sqlstate_of(error: BaseException) -> str | None:
    """The five-character SQLSTATE of a database error, if it carries one."""
    origin = error.orig if isinstance(error, DBAPIError) else error
    code = getattr(origin, "sqlstate", None)
    return code if isinstance(code, str) and len(code) == 5 else None


def is_transient_database_error(error: BaseException) -> bool:
    """Whether ``error`` is a database outage (connection, resources, locks, timeouts).

    Data errors (constraint violations, invalid input, missing relations) are not.
    """
    if isinstance(error, PoolTimeoutError):
        return True
    if not isinstance(error, DBAPIError):
        return False
    if error.connection_invalidated or isinstance(error, OperationalError | InterfaceError):
        return True
    sqlstate = sqlstate_of(error)
    return sqlstate is not None and (
        sqlstate[:2] in _TRANSIENT_SQLSTATE_CLASSES or sqlstate in _TRANSIENT_SQLSTATES
    )
