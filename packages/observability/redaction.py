"""Best-effort removal of secrets from log output.

This is a safety net, not a licence to log sensitive data. Code must still never pass
passwords, tokens, authorization headers, private keys or raw secrets to a logger.

Two layers are applied to every log record:

- **By key:** any field whose name looks sensitive (``password``, ``token``,
  ``authorization``, ``cookie``, ``secret``, ``credential``, names ending in ``key``...)
  is replaced by :data:`REDACTED`, at any nesting depth.
- **By value:** free text (messages, exception text, string fields) is scrubbed of
  bearer/basic credentials, JWTs, PEM private keys, credentials embedded in URLs,
  ``password=...``-style pairs and Supabase secret keys.
"""

import re
from collections.abc import Callable, Mapping
from typing import Final

from pydantic import SecretBytes, SecretStr

REDACTED: Final = "[REDACTED]"
MAX_DEPTH: Final = 6

_SENSITIVE_KEY_PARTS: Final = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "sessionid",
    "dsn",
    "connectionstring",
)
_SENSITIVE_KEYS: Final = frozenset({"pwd", "auth", "jwt", "otp", "pin"})

# Names in "name=value" / "name: value" text whose value must be hidden. Mirrors
# is_sensitive_key: sensitive words anywhere in the name, or a name ending in "key".
_SENSITIVE_NAME: Final = (
    r"[\w.-]*(?:password|passwd|pwd|passphrase|secret|token|credential|cookie"
    r"|session[_-]?id|dsn)[\w.-]*|[\w.-]*key"
)

_Replacement = str | Callable[[re.Match[str]], str]

_TEXT_PATTERNS: Final[tuple[tuple[re.Pattern[str], _Replacement], ...]] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"), "[REDACTED JWT]"),
    # "Authorization: Basic dXNlcjpwYXNz", "authorization=token abc" -> keep the scheme only.
    (
        re.compile(
            r"(?i)(\bauthorization[\"']?\s*[:=]\s*[\"']?)"
            r"((?:bearer|basic|digest|negotiate|token)\s+)?[^\s\"',;}]+"
        ),
        lambda match: f"{match[1]}{match[2] or ''}{REDACTED}",
    ),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    (re.compile(r"\bsb_secret_[A-Za-z0-9_-]+"), REDACTED),
    # scheme://user:password@host -> scheme://user:[REDACTED]@host (user may be empty).
    (
        re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^:/?#@\s]*):([^@/?#\s]+)@"),
        rf"\1\2:{REDACTED}@",
    ),
    (
        re.compile(
            rf"(?i)([\"']?\b(?:{_SENSITIVE_NAME})[\"']?\s*[=:]\s*)"
            r"(?!\[REDACTED)(\"[^\"]*\"|'[^']*'|[^\s,;&}\]]+)"
        ),
        rf"\1{REDACTED}",
    ),
)


def is_sensitive_key(key: str) -> bool:
    """Whether a field name suggests a secret value.

    Names are compared case-insensitively with ``_``, ``-`` and spaces removed. Names
    ending in ``key`` (``api_key``, ``service_role_key``, ``private_key``...) count as
    sensitive, so name non-secret fields differently (``partition``, not
    ``partition_key``).
    """
    normalized = re.sub(r"[\s_\-]", "", key).lower()
    return (
        normalized in _SENSITIVE_KEYS
        or normalized.endswith("key")
        or any(part in normalized for part in _SENSITIVE_KEY_PARTS)
    )


def redact_text(text: str) -> str:
    """Scrub recognizable secrets from free text."""
    for pattern, replacement in _TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: object, *, depth: int = 0) -> object:
    """Return a JSON-friendly copy of ``value`` with secrets removed.

    Mappings are redacted by key; strings are scrubbed; ``SecretStr``/``SecretBytes`` and
    raw ``bytes`` are never rendered; unknown objects are rendered with ``str()`` and
    scrubbed. Structures deeper than :data:`MAX_DEPTH` are summarized.
    """
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, SecretStr | SecretBytes):
        return REDACTED
    if isinstance(value, bytes | bytearray | memoryview):
        return f"<{len(value)} bytes>"
    if depth >= MAX_DEPTH:
        return f"<{type(value).__name__} nested too deeply>"
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(str(key)) else redact(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [redact(item, depth=depth + 1) for item in value]
    return redact_text(str(value))
