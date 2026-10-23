"""Run the ingestion API: ``python -m apps.api``."""

import logging
import sys

import uvicorn

from apps.api.app import create_app
from apps.api.settings import ApiServiceSettings
from packages.config import ConfigurationError, RateLimitBackend, RedisSettings, load_settings
from packages.observability import configure_logging
from packages.redis import RedisClient


def main() -> int:
    """Load settings, configure JSON logging and serve until interrupted."""
    try:
        settings = load_settings(ApiServiceSettings)
        redis = (
            RedisClient.from_settings(load_settings(RedisSettings), namespace="api")
            if settings.api_rate_limit_backend is RateLimitBackend.REDIS
            else None
        )
    except ConfigurationError as error:
        logging.basicConfig(level=logging.ERROR, format="%(message)s")
        logging.getLogger("adis.api").error("%s", error)
        return 2
    configure_logging(settings)
    # The request middleware writes the access log; uvicorn's own logging is disabled
    # so every line stays structured JSON.
    uvicorn.run(
        create_app(settings, redis=redis),
        host=settings.api_host,
        port=settings.api_port,
        log_config=None,
        access_log=False,
        server_header=False,
        # Beyond this, requests are answered 503 at once instead of queuing in memory.
        limit_concurrency=settings.api_max_concurrent_requests,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
