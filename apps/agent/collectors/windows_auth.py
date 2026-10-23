"""Windows Security log: logons, logoffs and session vectors (authentication, user behavior).

Each supported Security event becomes one ``AuthenticationEvent``:

=====  ========================================  =======================================
4624   ``authentication.login`` (success)        logon type, logon id, package, source
4625   ``authentication.login`` (failure)        normalized ``failure_reason``
4634   ``authentication.logout``                 logon id
4647   ``authentication.logout_requested``       logon id
4648   ``authentication.explicit_credentials``   target account and server
4672   ``authentication.special_privileges``     administrative logon
4740   ``authentication.account_locked``         caller computer
=====  ========================================  =======================================

Interactive logons and their logoffs also produce ``authentication.session_started`` and
``authentication.session_ended`` events whose ``metadata.session_vector`` is the session
vector of :mod:`apps.agent.collectors.sessions`. Only ``authentication.login`` events are
login attempts for the feature generator; the others describe what the log recorded.

Only fields Windows actually recorded are sent ("-" and similar placeholders mean "not
recorded"); SIDs and logon GUIDs never. A failed logon for a name that is not an account
(status 0xc0000064) withholds the typed name, which may be a password typed in the wrong
box. Events recorded on another computer are skipped.
"""

import ipaddress
import logging
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Final
from uuid import UUID, uuid5

from pydantic import JsonValue

from apps.agent.collectors.base import CollectorContext
from apps.agent.collectors.sessions import SessionTracker
from apps.agent.collectors.windows_events import (
    EVENT_ID_NAMESPACE,
    SEVERITY_FOR_LEVEL,
    WindowsEvent,
    level_name,
    windows_event_id,
    windows_metadata,
)
from packages.events.canonical import (
    AnyCanonicalEvent,
    AuthenticationEvent,
    AuthFailureReason,
    AuthMethod,
)

logger = logging.getLogger(__name__)

SOURCE_TYPE: Final = "windows_security_log"
SECURITY_CHANNEL: Final = "Security"
SECURITY_PROVIDER: Final = "Microsoft-Windows-Security-Auditing"
SUPPORTED_EVENT_IDS: Final = frozenset({4624, 4625, 4634, 4647, 4648, 4672, 4740})

EVENT_TYPES: Final = {
    4624: "authentication.login",
    4625: "authentication.login",
    4634: "authentication.logout",
    4647: "authentication.logout_requested",
    4648: "authentication.explicit_credentials",
    4672: "authentication.special_privileges",
    4740: "authentication.account_locked",
}
SESSION_STARTED: Final = "authentication.session_started"
SESSION_ENDED: Final = "authentication.session_ended"

LOGON_TYPE_NAMES: Final = {
    0: "system",
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
    12: "cached_remote_interactive",
    13: "cached_unlock",
}
FAILURE_REASONS: Final = {
    "0xc0000064": AuthFailureReason.UNKNOWN_USER,
    "0xc000006a": AuthFailureReason.INVALID_CREDENTIALS,
    "0xc000006d": AuthFailureReason.INVALID_CREDENTIALS,
    "0xc000006e": AuthFailureReason.POLICY_DENIED,
    "0xc000006f": AuthFailureReason.POLICY_DENIED,
    "0xc0000070": AuthFailureReason.POLICY_DENIED,
    "0xc0000071": AuthFailureReason.EXPIRED_CREDENTIALS,
    "0xc0000072": AuthFailureReason.ACCOUNT_DISABLED,
    "0xc000015b": AuthFailureReason.POLICY_DENIED,
    "0xc0000193": AuthFailureReason.EXPIRED_CREDENTIALS,
    "0xc0000224": AuthFailureReason.EXPIRED_CREDENTIALS,
    "0xc0000234": AuthFailureReason.ACCOUNT_LOCKED,
}
UNKNOWN_ACCOUNT_STATUS: Final = "0xc0000064"
AUTH_PACKAGES: Final = {
    "ntlm": AuthMethod.NTLM,
    "kerberos": AuthMethod.KERBEROS,
    "negotiate": AuthMethod.OTHER,
}
ELEVATED_TOKEN: Final = {"%%1842": True, "%%1843": False}
DEFAULT_EXCLUDED_ACCOUNTS: Final = (
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
    "DWM-*",
    "UMFD-*",
    "*$",
)
_NOT_RECORDED: Final = frozenset({"", "-", "0x0", "S-1-0-0", "NULL SID"})


def recorded(value: str | None) -> str | None:
    """``value``, or ``None`` when Windows wrote a placeholder meaning "not recorded"."""
    if value is None:
        return None
    stripped = value.strip()
    return None if stripped in _NOT_RECORDED else stripped


def account_name(user: str | None, domain: str | None) -> str | None:
    r"""``DOMAIN\user``, ``user``, or ``None``."""
    user, domain = recorded(user), recorded(domain)
    if user is None:
        return None
    return f"{domain}\\{user}" if domain else user


def account_matches(name: str | None, patterns: tuple[str, ...]) -> bool:
    r"""Whether ``name`` (``DOMAIN\user`` or ``user``) matches a wildcard pattern."""
    if not name or not patterns:
        return False
    candidates = {name.lower(), name.rsplit("\\", 1)[-1].lower()}
    return any(fnmatchcase(candidate, p.lower()) for candidate in candidates for p in patterns)


def same_computer(event_computer: str, local_computer: str) -> bool:
    """Whether two computer names (possibly FQDNs) name the same machine."""
    return event_computer.split(".")[0].lower() == local_computer.split(".")[0].lower()


def _int(value: str | None) -> int | None:
    text = recorded(value)
    if text is None:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = recorded(value)
    if text is None:
        return None
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return None if address.is_loopback or address.is_unspecified else address


def _status(value: str | None) -> str | None:
    text = recorded(value)
    return text.lower() if text else None


class AuthenticationMapper:
    """Security-channel events → ``AuthenticationEvent`` and session vectors."""

    def __init__(
        self,
        context: CollectorContext,
        *,
        exclude_logon_types: frozenset[int],
        session_logon_types: frozenset[int],
        failure_window: timedelta,
        max_open_sessions: int,
        exclude_accounts: tuple[str, ...] = DEFAULT_EXCLUDED_ACCOUNTS,
    ) -> None:
        self._context = context
        self._exclude_logon_types = exclude_logon_types
        self._session_logon_types = session_logon_types
        self._exclude_accounts = exclude_accounts
        self._sessions = SessionTracker(max_open=max_open_sessions, failure_window=failure_window)
        self._other_computers: set[str] = set()

    @property
    def channels(self) -> tuple[str, ...]:
        """Only the Security channel."""
        return (SECURITY_CHANNEL,)

    def event_ids(self, channel: str) -> frozenset[int] | None:
        """The supported Security events (filtered by the Event Log service)."""
        return SUPPORTED_EVENT_IDS

    def select(self, channel: str, event: WindowsEvent) -> bool:
        """This computer's supported events, minus excluded logon types."""
        if event.provider != SECURITY_PROVIDER or event.event_id not in SUPPORTED_EVENT_IDS:
            return False
        local = self._context.identity.hostname
        if not same_computer(event.computer, local):
            if event.computer not in self._other_computers:
                self._other_computers.add(event.computer)
                logger.warning(
                    "skipping Security events recorded on another computer",
                    extra={"action": "agent_security_foreign_computer"},
                )
            return False
        logon_type = _int(event.fields().get("LogonType"))
        return logon_type not in self._exclude_logon_types

    def to_events(self, event: WindowsEvent, message: str | None) -> list[AnyCanonicalEvent]:
        """The authentication event, plus a session event for interactive sessions."""
        fields = event.fields()
        auth = self._authentication(event, fields)
        events: list[AnyCanonicalEvent] = [auth] if auth is not None else []
        session = self._session(event, fields)
        if session is not None:
            events.append(session)
        return events

    def _authentication(
        self, event: WindowsEvent, fields: dict[str, str]
    ) -> AuthenticationEvent | None:
        event_id = event.event_id
        metadata = windows_metadata(event)
        username = _primary_account(event_id, fields)
        success = True
        failure_reason: AuthFailureReason | None = None
        method: AuthMethod | None = None
        logon_type = _int(fields.get("LogonType"))
        if logon_type is not None:
            metadata["logon_type"] = logon_type
            metadata["logon_type_name"] = LOGON_TYPE_NAMES.get(logon_type, "other")
        if event_id in (4624, 4634, 4647):
            metadata["logon_id"] = recorded(fields.get("TargetLogonId"))
        if event_id in (4624, 4625):
            package = recorded(fields.get("AuthenticationPackageName"))
            if package:
                metadata["authentication_package"] = package
                method = AUTH_PACKAGES.get(package.lower(), AuthMethod.OTHER)
            metadata["logon_process"] = recorded(fields.get("LogonProcessName"))
            metadata["workstation_name"] = recorded(fields.get("WorkstationName"))
            metadata["process_name"] = recorded(fields.get("ProcessName"))
            port = _int(fields.get("IpPort"))
            metadata["source_port"] = port or None
        if event_id == 4624:
            metadata["elevated_token"] = ELEVATED_TOKEN.get(fields.get("ElevatedToken", ""))
            metadata["linked_logon_id"] = recorded(fields.get("TargetLinkedLogonId"))
        elif event_id == 4625:
            success = False
            status, sub_status = _status(fields.get("Status")), _status(fields.get("SubStatus"))
            metadata["failure_status"], metadata["failure_sub_status"] = status, sub_status
            code = sub_status if sub_status in FAILURE_REASONS else status
            failure_reason = FAILURE_REASONS.get(code or "", AuthFailureReason.OTHER)
            if UNKNOWN_ACCOUNT_STATUS in (status, sub_status):
                username = None
                metadata["account_name_withheld"] = True
            failed_from = _ip(fields.get("IpAddress"))
            self._sessions.failure(
                username, event.time_created, str(failed_from) if failed_from else None
            )
        elif event_id == 4648:
            logon_id = recorded(fields.get("SubjectLogonId"))
            metadata["logon_id"] = logon_id
            metadata["target_account"] = account_name(
                fields.get("TargetUserName"), fields.get("TargetDomainName")
            )
            metadata["target_server"] = recorded(fields.get("TargetServerName"))
            metadata["process_name"] = recorded(fields.get("ProcessName"))
            if logon_id:
                self._sessions.explicit_credentials(logon_id)
        elif event_id == 4672:
            logon_id = recorded(fields.get("SubjectLogonId"))
            metadata["logon_id"] = logon_id
            if logon_id:
                self._sessions.mark_privileged(logon_id)
            if account_matches(username, self._exclude_accounts):
                return None
        elif event_id == 4740:
            success = False
            failure_reason = AuthFailureReason.ACCOUNT_LOCKED
            metadata["caller_computer"] = recorded(fields.get("TargetDomainName"))
        identity = self._context.identity
        return AuthenticationEvent(
            event_id=windows_event_id(event),
            event_type=EVENT_TYPES[event_id],
            timestamp=event.time_created,
            source_type=SOURCE_TYPE,
            source_name=self._context.source_name("windows_security"),
            host_id=identity.host_id,
            agent_id=self._context.agent_id,
            severity_hint=SEVERITY_FOR_LEVEL[level_name(event.level)],
            username=username,
            auth_method=method,
            success=success,
            failure_reason=failure_reason,
            src_ip=_ip(fields.get("IpAddress")),
            metadata={key: value for key, value in metadata.items() if value is not None},
        )

    def _session(self, event: WindowsEvent, fields: dict[str, str]) -> AuthenticationEvent | None:
        if event.event_id not in (4624, 4634, 4647):
            return None
        user = account_name(fields.get("TargetUserName"), fields.get("TargetDomainName"))
        logon_id = recorded(fields.get("TargetLogonId"))
        if user is None or logon_id is None or account_matches(user, self._exclude_accounts):
            return None
        logon_type = _int(fields.get("LogonType"))
        source_ip = _ip(fields.get("IpAddress"))
        if event.event_id == 4624:
            if logon_type not in self._session_logon_types:
                return None
            vector = self._sessions.start(
                logon_id,
                user,
                event.time_created,
                logon_type=logon_type or 0,
                source_ip=str(source_ip) if source_ip else None,
                privileged=ELEVATED_TOKEN.get(fields.get("ElevatedToken", ""), False),
            )
            linked = recorded(fields.get("TargetLinkedLogonId"))
            if linked:
                self._sessions.alias(linked, logon_id)
            event_type = SESSION_STARTED
        else:
            ended = self._sessions.end(logon_id, user, event.time_created)
            if ended is None:
                return None
            vector, event_type = ended, SESSION_ENDED
        identity = self._context.identity
        derived = windows_event_id(event)
        metadata: dict[str, JsonValue] = {
            "record_kind": "session_vector",
            "derived_from_event_id": str(derived),
            "windows_event_id": event.event_id,
            "logon_id": logon_id,
            "session_vector": vector,
        }
        if event.event_id == 4647:
            metadata["end_reason"] = "logoff_requested"
        return AuthenticationEvent(
            event_id=_derived_id(derived),
            event_type=event_type,
            timestamp=event.time_created,
            source_type=SOURCE_TYPE,
            source_name=self._context.source_name("windows_security"),
            host_id=identity.host_id,
            agent_id=self._context.agent_id,
            username=user,
            success=True,
            src_ip=source_ip,
            metadata=metadata,
        )


def _derived_id(source_event_id: UUID) -> UUID:
    return uuid5(EVENT_ID_NAMESPACE, f"session|{source_event_id}")


def _primary_account(event_id: int, fields: dict[str, str]) -> str | None:
    """The account an event is about: logged on/off, tried, locked, or acting (4648, 4672)."""
    if event_id in (4648, 4672):
        return account_name(fields.get("SubjectUserName"), fields.get("SubjectDomainName"))
    if event_id == 4740:
        return recorded(fields.get("TargetUserName"))
    return account_name(fields.get("TargetUserName"), fields.get("TargetDomainName"))
