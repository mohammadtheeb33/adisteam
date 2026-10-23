"""Application factory, lifecycle, probes and the process entry point."""

from pathlib import Path

import pytest
import uvicorn

from apps.api import __main__ as entrypoint
from apps.api.app import create_app
from apps.api.publisher import KafkaEventPublisher
from apps.api.rate_limit import TokenBucketRateLimiter
from apps.api.services import ApiServices
from tests.unit.api.fakes import AUTH, RecordingPublisher, api_client, api_settings


def test_publisher_follows_the_application_lifecycle() -> None:
    publisher = RecordingPublisher()

    with api_client(publisher) as (client, _):
        assert (publisher.started, publisher.stopped) == (1, 0)
        client.get("/health")

    assert (publisher.started, publisher.stopped) == (1, 1)


def test_default_components_are_kafka_and_token_bucket() -> None:
    app = create_app(api_settings())

    services = app.state.services
    assert isinstance(services, ApiServices)
    assert isinstance(services.publisher, KafkaEventPublisher)
    assert isinstance(services.rate_limiter, TokenBucketRateLimiter)


def test_health_is_unauthenticated_and_correlated() -> None:
    with api_client() as (client, _):
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["X-Request-ID"]
    assert "RateLimit-Limit" not in response.headers


@pytest.mark.parametrize(
    ("ready", "status", "body"),
    [
        (True, 200, {"status": "ready", "checks": {"kafka": "ok"}}),
        (False, 503, {"status": "not_ready", "checks": {"kafka": "unavailable"}}),
    ],
)
def test_readiness_reflects_the_publisher(
    ready: bool, status: int, body: dict[str, object]
) -> None:
    with api_client(RecordingPublisher(is_ready=ready)) as (client, _):
        response = client.get("/ready")

    assert (response.status_code, response.json()) == (status, body)


def test_probes_ignore_credentials() -> None:
    with api_client() as (client, _):
        assert client.get("/ready", headers={"Authorization": "Bearer wrong"}).status_code == 200
        assert client.get("/health", headers=AUTH).status_code == 200


def test_entrypoint_fails_fast_without_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("API_INGEST_TOKENS", raising=False)

    assert entrypoint.main() == 2


def test_entrypoint_serves_with_structured_logging_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-a:{'x' * 32}")
    monkeypatch.setenv("API_PORT", "8123")
    served: dict[str, object] = {}
    configured: list[object] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **options: served.update(options))
    monkeypatch.setattr(entrypoint, "configure_logging", configured.append)

    assert entrypoint.main() == 0

    assert configured
    assert served == {
        "host": "127.0.0.1",
        "port": 8123,
        "log_config": None,
        "access_log": False,
        "server_header": False,
        "limit_concurrency": 256,
    }
