"""Components shared by request handlers, injected through ``app.state``."""

from dataclasses import dataclass

from fastapi import Request

from apps.api.auth import TokenAuthenticator
from apps.api.metrics import ApiMetrics
from apps.api.publisher import EventPublisher
from apps.api.rate_limit import RateLimiter
from apps.api.settings import ApiServiceSettings
from packages.redis import RedisClient


@dataclass(frozen=True, slots=True)
class ApiServices:
    """Everything a request handler needs; created once by ``create_app``."""

    settings: ApiServiceSettings
    publisher: EventPublisher
    rate_limiter: RateLimiter
    authenticator: TokenAuthenticator
    metrics: ApiMetrics
    redis: RedisClient | None = None


def get_services(request: Request) -> ApiServices:
    """FastAPI dependency returning the application's services."""
    services = getattr(request.app.state, "services", None)
    if not isinstance(services, ApiServices):
        raise RuntimeError("the application was not built by create_app")
    return services
