"""Test doubles and builders for the ingestion API."""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field

from fastapi.testclient import TestClient

from apps.api.app import create_app
from apps.api.publisher import IngestContext
from apps.api.rate_limit import RateLimiter
from apps.api.settings import ApiServiceSettings
from packages.events.canonical import AnyCanonicalEvent

TOKEN = "t0k3n-" + "a" * 32
OTHER_TOKEN = "t0k3n-" + "b" * 32
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def api_settings(**overrides: object) -> ApiServiceSettings:
    """Settings with two clients and small limits; no environment is read."""
    values: dict[str, object] = {
        "app_name": "adis-api",
        "api_ingest_tokens": f"agent-a:{TOKEN},agent-b:{OTHER_TOKEN}",
        "api_max_batch_size": 5,
        "api_rate_limit_events": 1_000,
        "api_publish_timeout_seconds": 2,
    }
    values.update(overrides)
    return ApiServiceSettings.model_validate(values)


@dataclass
class RecordingPublisher:
    """Collects published events; can report unreadiness or fail."""

    is_ready: bool = True
    failure: BaseException | None = None
    batches: list[tuple[list[AnyCanonicalEvent], IngestContext]] = field(default_factory=list)
    started: int = 0
    stopped: int = 0

    async def start(self) -> None:
        self.started += 1

    async def stop(self) -> None:
        self.stopped += 1

    async def ready(self) -> bool:
        return self.is_ready

    async def publish(self, events: Sequence[AnyCanonicalEvent], context: IngestContext) -> None:
        if self.failure is not None:
            raise self.failure
        self.batches.append((list(events), context))

    @property
    def events(self) -> list[AnyCanonicalEvent]:
        """Every published event, in order."""
        return [event for events, _ in self.batches for event in events]


@contextmanager
def api_client(
    publisher: RecordingPublisher | None = None,
    *,
    rate_limiter: RateLimiter | None = None,
    **settings: object,
) -> Iterator[tuple[TestClient, RecordingPublisher]]:
    """A running application (lifespan included) and its publisher."""
    recording = publisher or RecordingPublisher()
    app = create_app(api_settings(**settings), publisher=recording, rate_limiter=rate_limiter)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, recording
