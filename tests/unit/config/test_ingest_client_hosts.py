"""``API_INGEST_CLIENT_HOSTS``: which hosts an ingestion client's token may write (OD-34)."""

from collections.abc import Callable
from uuid import uuid4

import pytest

from packages.config import (
    ADISSettings,
    ApiSettings,
    ConfigurationError,
    bound_agent_id,
    load_settings,
    parse_ingest_client_hosts,
)

LoadError = Callable[[type[ADISSettings]], ConfigurationError]
AGENT_ID = uuid4()
AGENT_CLIENT = f"agent-{AGENT_ID}"
FIRST_TOKEN = "a" * 40


def _tokens(monkeypatch: pytest.MonkeyPatch, *clients: str) -> None:
    """One distinct 40-character token per client; the first is ``FIRST_TOKEN``."""
    entries = (f"{client}:{chr(97 + position) * 40}" for position, client in enumerate(clients))
    monkeypatch.setenv("API_INGEST_TOKENS", ",".join(entries))


def test_blank_value_restricts_no_client() -> None:
    assert parse_ingest_client_hosts("") == {}
    assert parse_ingest_client_hosts("   ") == {}


def test_several_clients_and_hosts_are_parsed() -> None:
    parsed = parse_ingest_client_hosts(f"{AGENT_CLIENT}=web-1, sensor.1=edge-1|edge-2|db:5432")
    assert parsed == {
        AGENT_CLIENT: frozenset({"web-1"}),
        "sensor.1": frozenset({"edge-1", "edge-2", "db:5432"}),
    }


@pytest.mark.parametrize(
    "raw",
    [
        "no-separator",
        "=web-1",
        "agent-a=",
        "agent-a=web-1|",
        "agent-a=|web-1",
        "agent-a=web 1",
        "agent-a=-leading-dash",
        "bad client=web-1",
        "agent-a=web-1,",
        "agent-a=web-1,agent-a=web-2",
        "agent-a=web-1|web-1",
        "agent-a=" + "h" * 256,
        "agent-a=" + "|".join(f"h{i}" for i in range(1001)),
    ],
)
def test_malformed_values_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError, match=r"^entry \d+ "):
        parse_ingest_client_hosts(raw)


def test_error_messages_never_quote_the_value() -> None:
    with pytest.raises(ValueError, match=r"^entry 1 ") as error:
        parse_ingest_client_hosts("agent-a=secret-looking value")
    assert "secret-looking" not in str(error.value)


def test_bound_agent_id_needs_the_agent_prefix_and_a_uuid() -> None:
    assert bound_agent_id(AGENT_CLIENT) == AGENT_ID
    assert bound_agent_id("agent-not-a-uuid") is None
    assert bound_agent_id("zeek-connector") is None
    assert bound_agent_id(str(AGENT_ID)) is None


def test_default_restricts_no_client(monkeypatch: pytest.MonkeyPatch) -> None:
    _tokens(monkeypatch, AGENT_CLIENT)
    assert load_settings(ApiSettings).ingest_client_hosts() == {}


def test_configured_hosts_are_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    _tokens(monkeypatch, AGENT_CLIENT, "sensor.1")
    monkeypatch.setenv("API_INGEST_CLIENT_HOSTS", f"{AGENT_CLIENT}=web-1|web-2")
    assert load_settings(ApiSettings).ingest_client_hosts() == {
        AGENT_CLIENT: frozenset({"web-1", "web-2"})
    }


def test_malformed_hosts_fail_at_start_up_naming_the_variable(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    _tokens(monkeypatch, AGENT_CLIENT)
    monkeypatch.setenv("API_INGEST_CLIENT_HOSTS", f"{AGENT_CLIENT}=not a host")
    assert load_error(ApiSettings).variables == {"API_INGEST_CLIENT_HOSTS"}


def test_hosts_of_an_unknown_client_fail_at_start_up(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError
) -> None:
    """A typo in a client id must not silently leave the real client unrestricted."""
    _tokens(monkeypatch, AGENT_CLIENT)
    monkeypatch.setenv("API_INGEST_CLIENT_HOSTS", f"agent-{uuid4()}=web-1")
    issues = [str(issue) for issue in load_error(ApiSettings).issues]
    assert len(issues) == 1
    assert "not in API_INGEST_TOKENS" in issues[0]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_strict_environments_require_hosts_for_every_agent_bound_client(
    monkeypatch: pytest.MonkeyPatch, load_error: LoadError, environment: str
) -> None:
    _tokens(monkeypatch, AGENT_CLIENT, "sensor.1", "agent-not-a-uuid")
    monkeypatch.setenv("APP_ENV", environment)
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    issues = [str(issue) for issue in load_error(ApiSettings).issues]
    assert len(issues) == 1
    assert AGENT_CLIENT in issues[0]
    assert "sensor.1" not in issues[0]
    assert "agent-not-a-uuid" not in issues[0]
    assert FIRST_TOKEN not in issues[0]


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_strict_environments_accept_hosts_for_every_agent_bound_client(
    monkeypatch: pytest.MonkeyPatch, environment: str
) -> None:
    _tokens(monkeypatch, AGENT_CLIENT)
    monkeypatch.setenv("APP_ENV", environment)
    monkeypatch.setenv("API_HOST", "127.0.0.1")
    monkeypatch.setenv("API_INGEST_CLIENT_HOSTS", f"{AGENT_CLIENT}=web-1")
    assert load_settings(ApiSettings).ingest_client_hosts() == {AGENT_CLIENT: frozenset({"web-1"})}
