"""Session vectors: user behavior derived from authentication and access logs.

The specification (pentra.pdf, section 2, step 3) lists user behavior as coming from
authentication and access logs, in the form of *session vectors*. A session starts with a
successful logon (Windows 4624 of an interactive type, an sshd ``session opened``) and ends
with a logoff (4634/4647, ``session closed``). For each one the tracker builds a fixed-order
numeric vector plus its named fields:

=================================  ===============================================
``duration_seconds``               logoff time minus logon time (0 at the start)
``start_hour_utc``                 hour of the logon, 0-23
``start_weekday_utc``              0 = Monday ... 6 = Sunday
``logon_type``                     Windows logon type; 0 where the source has none
``failed_attempts_before``         failed logons of the same account in the window
``distinct_failure_sources``       distinct source addresses of those failures
``privileged``                     1 if the session got administrative privileges
``remote``                         1 if the logon came from a network address
``concurrent_sessions``            other open sessions of the account at the logon
``explicit_credential_uses``       4648 explicit-credential uses during the session
=================================  ===============================================

These describe what the logs record; they are not a threat assessment. Only sessions
whose start this agent saw while running get a duration; the tracker holds a bounded
number of open sessions and failure records.
"""

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from pydantic import JsonValue

VECTOR_FIELDS: Final = (
    "duration_seconds",
    "start_hour_utc",
    "start_weekday_utc",
    "logon_type",
    "failed_attempts_before",
    "distinct_failure_sources",
    "privileged",
    "remote",
    "concurrent_sessions",
    "explicit_credential_uses",
)
"""Order of the numbers in ``session_vector``."""

VECTOR_SCHEMA: Final = "adis.session_vector.v1"
_MAX_FAILURES_PER_ACCOUNT: Final = 1_000


@dataclass(slots=True)
class OpenSession:
    """A session that started and has not ended yet."""

    account: str
    started_at: datetime
    logon_type: int
    source_ip: str | None
    failed_attempts_before: int
    distinct_failure_sources: int
    concurrent_sessions: int
    privileged: bool = False
    explicit_credential_uses: int = 0


@dataclass(slots=True)
class _Failures:
    attempts: deque[tuple[datetime, str | None]] = field(default_factory=deque)


class SessionTracker:
    """Tracks failures and open sessions per account and builds session vectors."""

    def __init__(self, *, max_open: int, failure_window: timedelta) -> None:
        self._max_open = max_open
        self._failure_window = failure_window
        self._open: OrderedDict[tuple[str, str], OpenSession] = OrderedDict()
        self._failures: OrderedDict[str, _Failures] = OrderedDict()
        self._aliases: OrderedDict[str, str] = OrderedDict()

    @property
    def open_sessions(self) -> int:
        """Sessions started and not yet ended."""
        return len(self._open)

    def failure(self, account: str | None, at: datetime, source_ip: str | None) -> None:
        """Record a failed logon of ``account`` (unknown accounts are not tracked)."""
        if not account:
            return
        key = account.lower()
        record = self._failures.pop(key, None) or _Failures()
        record.attempts.append((at, source_ip))
        while len(record.attempts) > _MAX_FAILURES_PER_ACCOUNT:
            record.attempts.popleft()
        self._failures[key] = record
        while len(self._failures) > self._max_open:
            self._failures.popitem(last=False)

    def start(
        self,
        session_id: str,
        account: str,
        at: datetime,
        *,
        logon_type: int = 0,
        source_ip: str | None = None,
        privileged: bool = False,
    ) -> dict[str, JsonValue]:
        """Open a session; returns the vector known at its start."""
        failures = self._recent_failures(account, at)
        concurrent = sum(1 for key in self._open if key[1] == account.lower())
        session = OpenSession(
            account=account,
            started_at=at,
            logon_type=logon_type,
            source_ip=source_ip,
            failed_attempts_before=len(failures),
            distinct_failure_sources=len({source for _, source in failures if source}),
            concurrent_sessions=concurrent,
            privileged=privileged,
        )
        key = (session_id, account.lower())
        self._open[key] = session
        self._open.move_to_end(key)
        while len(self._open) > self._max_open:
            self._open.popitem(last=False)
        return self._vector(session, ended_at=at)

    def alias(self, alias_id: str, session_id: str) -> None:
        """Let ``alias_id`` name the session ``session_id`` (Windows linked logon ids)."""
        self._aliases[alias_id] = session_id
        self._aliases.move_to_end(alias_id)
        while len(self._aliases) > self._max_open:
            self._aliases.popitem(last=False)

    def mark_privileged(self, session_id: str, account: str | None = None) -> None:
        """A special-privileges assignment (Windows 4672) for an open session."""
        session_id = self._aliases.get(session_id, session_id)
        for key, session in self._open.items():
            if key[0] == session_id and (account is None or key[1] == account.lower()):
                session.privileged = True

    def explicit_credentials(self, session_id: str) -> None:
        """An explicit-credential use (Windows 4648) inside an open session."""
        session_id = self._aliases.get(session_id, session_id)
        for key, session in self._open.items():
            if key[0] == session_id:
                session.explicit_credential_uses += 1

    def end(self, session_id: str, account: str, at: datetime) -> dict[str, JsonValue] | None:
        """Close a session; returns its full vector, or ``None`` if its start was not seen."""
        session = self._open.pop((session_id, account.lower()), None)
        if session is None or at < session.started_at:
            return None
        return self._vector(session, ended_at=at)

    def _recent_failures(self, account: str, at: datetime) -> list[tuple[datetime, str | None]]:
        record = self._failures.get(account.lower())
        if record is None:
            return []
        since = at - self._failure_window
        return [(moment, source) for moment, source in record.attempts if since <= moment <= at]

    @staticmethod
    def _vector(session: OpenSession, *, ended_at: datetime) -> dict[str, JsonValue]:
        started = session.started_at
        values: dict[str, JsonValue] = {
            "duration_seconds": round((ended_at - started).total_seconds(), 3),
            "start_hour_utc": started.hour,
            "start_weekday_utc": started.weekday(),
            "logon_type": session.logon_type,
            "failed_attempts_before": session.failed_attempts_before,
            "distinct_failure_sources": session.distinct_failure_sources,
            "privileged": int(session.privileged),
            "remote": int(session.source_ip is not None),
            "concurrent_sessions": session.concurrent_sessions,
            "explicit_credential_uses": session.explicit_credential_uses,
        }
        return {
            "schema": VECTOR_SCHEMA,
            "fields": list(VECTOR_FIELDS),
            "vector": [values[name] for name in VECTOR_FIELDS],
            "values": values,
            "started_at": started.isoformat(),
        }
