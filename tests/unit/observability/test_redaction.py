"""Secret redaction by key and by value."""

import pytest
from pydantic import SecretBytes, SecretStr

from packages.observability import REDACTED, is_sensitive_key, redact, redact_text


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "db_password",
        "PASSWORD",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "token",
        "access_token",
        "refresh-token",
        "Authorization",
        "proxy-authorization",
        "cookie",
        "Set-Cookie",
        "api_key",
        "X-Api-Key",
        "service_role_key",
        "SUPABASE_SERVICE_ROLE_KEY",
        "private_key",
        "credentials",
        "session_id",
        "database_dsn",
        "auth",
        "jwt",
    ],
)
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "request_id",
        "trace_id",
        "event_id",
        "host_id",
        "threat_id",
        "action",
        "latency_ms",
        "error_type",
        "topic",
        "partition",
        "author",
        "status_code",
        "path",
    ],
)
def test_non_sensitive_keys(key: str) -> None:
    assert not is_sensitive_key(key)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
        ("Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("{'authorization': 'token sk-live-123456'}", "sk-live-123456"),
        ("retrying with bearer ZXlKaGJHY2lPaUpJVXpJ", "ZXlKaGJHY2lPaUpJVXpJ"),
        ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "eyJzdWIiOiIxIn0"),
        ("postgresql+asyncpg://adis:s3cr3t-pw@db.internal:5432/postgres", "s3cr3t-pw"),
        ("redis://:r3dis-pw@cache:6379/0", "r3dis-pw"),
        ("login failed: password=hunter2 user=alice", "hunter2"),
        ("db_password: 'hunter2'", "hunter2"),
        ('{"client_secret": "shh-123", "ok": true}', "shh-123"),
        ("SUPABASE_SERVICE_ROLE_KEY=abc.def.ghi", "abc.def.ghi"),
        ("using sb_secret_AbCdEf123456", "sb_secret_AbCdEf123456"),
        ("session_id=deadbeefcafe", "deadbeefcafe"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n"
            "-----END OPENSSH PRIVATE KEY-----",
            "b3BlbnNzaC1rZXk",
        ),
    ],
)
def test_secrets_are_scrubbed_from_text(text: str, secret: str) -> None:
    scrubbed = redact_text(text)

    assert secret not in scrubbed
    assert "REDACTED" in scrubbed


@pytest.mark.parametrize(
    "text",
    [
        "token validation failed for host-7",
        "basic validation passed",
        "event_type=security.token_refresh processed",
        "kafka publish failed; retrying",
        "http request completed",
        "https://example.test/path?page=2",
    ],
)
def test_ordinary_text_is_unchanged(text: str) -> None:
    assert redact_text(text) == text


def test_redaction_is_idempotent() -> None:
    once = redact_text("api_key=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig password=x")

    assert redact_text(once) == once


def test_nested_structures_are_redacted_by_key_and_value() -> None:
    value = {
        "headers": {"Authorization": "Bearer abc", "Content-Type": "application/json"},
        "attempts": 3,
        "items": [{"token": "t-1"}, "password=p-1", SecretStr("s-1")],
        "blob": b"\x00\x01",
        "raw": SecretBytes(b"k-1"),
        "flag": True,
    }

    assert redact(value) == {
        "headers": {"Authorization": REDACTED, "Content-Type": "application/json"},
        "attempts": 3,
        "items": [{"token": REDACTED}, f"password={REDACTED}", REDACTED],
        "blob": "<2 bytes>",
        "raw": REDACTED,
        "flag": True,
    }


def test_unknown_objects_are_rendered_and_scrubbed() -> None:
    class Connection:
        def __str__(self) -> str:
            return "Connection(redis://:pw-123@cache:6379/0)"

    assert redact(Connection()) == f"Connection(redis://:{REDACTED}@cache:6379/0)"


def test_deep_structures_are_summarized() -> None:
    value: dict[str, object] = {"leaf": "x"}
    for _ in range(10):
        value = {"nested": value}

    assert "nested too deeply" in str(redact(value))
