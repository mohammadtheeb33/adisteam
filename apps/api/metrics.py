"""Prometheus metrics of the ingestion API."""

from prometheus_client import CollectorRegistry, Counter

from packages.observability.metrics import HttpMetrics


class ApiMetrics:
    """Everything the API counts; one registry per application instance."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.http = HttpMetrics(self.registry, namespace="adis_api")
        self.events = Counter(
            "adis_api_events_total",
            "Submitted events by outcome (accepted, rejected).",
            ["outcome"],
            registry=self.registry,
        )
        self.publish_failures = Counter(
            "adis_api_publish_failures_total",
            "Requests answered 503 because Kafka did not acknowledge in time.",
            registry=self.registry,
        )
        self.rate_limited = Counter(
            "adis_api_rate_limited_total",
            "Requests refused by the rate limit.",
            registry=self.registry,
        )
        self.rate_limit_fallbacks = Counter(
            "adis_api_rate_limit_fallbacks_total",
            "Rate-limit decisions taken in process memory because Redis failed.",
            registry=self.registry,
        )
