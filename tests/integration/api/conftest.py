"""The ingestion API wired to a real, disposable Kafka broker.

Enabled by ``TEST_KAFKA_BOOTSTRAP_SERVERS`` (see tests/integration/kafka).
"""

from collections.abc import AsyncIterator
from pathlib import Path

import httpx2
import pytest

from apps.api.app import create_app
from apps.api.settings import ApiServiceSettings
from packages.config import load_settings
from packages.kafka import ensure_topics
from tests.integration.api.helpers import TOKEN
from tests.services import require_variable

TEST_KAFKA_VARIABLE = "TEST_KAFKA_BOOTSTRAP_SERVERS"


@pytest.fixture
def api_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ApiServiceSettings:
    """API settings pointing at the test broker; skips when it is not configured."""
    servers = require_variable(TEST_KAFKA_VARIABLE)
    monkeypatch.chdir(tmp_path)  # ignore the developer's .env
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("APP_NAME", "adis-api-it")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", servers)
    monkeypatch.setenv("API_INGEST_TOKENS", f"agent-it:{TOKEN}")
    monkeypatch.setenv("API_MAX_BATCH_SIZE", "50")
    return load_settings(ApiServiceSettings)


@pytest.fixture
async def api(api_settings: ApiServiceSettings) -> AsyncIterator[httpx2.AsyncClient]:
    """An HTTP client for the running application, with its lifespan (producer) active."""
    await ensure_topics(api_settings)
    app = create_app(api_settings)
    async with (
        app.router.lifespan_context(app),
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://adis-api.test"
        ) as client,
    ):
        yield client
