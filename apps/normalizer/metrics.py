"""Prometheus metrics of the normalization pipeline."""

from collections.abc import Mapping

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from packages.observability.metrics import LATENCY_BUCKETS


class NormalizerMetrics:
    """Everything the normalizer counts; one registry per service instance."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.records = Counter(
            "adis_normalizer_records_total",
            "Kafka records handled, including duplicates and rejections.",
            registry=self.registry,
        )
        self.events = Counter(
            "adis_normalizer_events_total",
            "Events by outcome: published, duplicate, conflict, dead_lettered.",
            ["outcome"],
            registry=self.registry,
        )
        self.retries = Counter(
            "adis_normalizer_retries_total",
            "Failed attempts that were retried, by kind (outage, other).",
            ["kind"],
            registry=self.registry,
        )
        self.future_timestamps = Counter(
            "adis_normalizer_future_timestamps_total",
            "Events timestamped further ahead of received_at than allowed.",
            registry=self.registry,
        )
        self.agents_registered = Counter(
            "adis_normalizer_agent_registrations_total",
            "Agent registrations applied to adis.agents.",
            registry=self.registry,
        )
        self.batch_duration = Histogram(
            "adis_normalizer_batch_duration_seconds",
            "Time to settle one polled batch.",
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.consumer_lag = Gauge(
            "adis_normalizer_consumer_lag",
            "Records not yet consumed, per input partition.",
            ["partition"],
            registry=self.registry,
        )

    def set_lag(self, lag: Mapping[str, int]) -> None:
        """Replace the lag gauges with the current per-partition values."""
        self.consumer_lag.clear()
        for partition, value in lag.items():
            self.consumer_lag.labels(partition).set(value)
