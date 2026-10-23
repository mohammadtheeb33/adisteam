"""What the verification sent and observed, and the metrics derived from it."""

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID


class Outcome(StrEnum):
    """What the ingestion API finally did with a submitted event."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"  # 4xx for this event: the API refused it
    FAILED = "failed"  # never accepted before the retry deadline


@dataclass(slots=True)
class Submission:
    """One event submitted once (a request may carry many)."""

    event_id: UUID
    scenario: str
    category: str | None
    duplicate: bool
    first_sent: float
    outcome: Outcome = Outcome.FAILED
    accepted_at: float | None = None
    status: int | None = None
    code: str | None = None
    issues: tuple[str, ...] = ()
    attempts: int = 0


@dataclass(frozen=True, slots=True)
class DeadLetterSeen:
    """A dead-letter record of this run."""

    marker: str
    original_topic: str
    error_type: str
    consumer_group: str


@dataclass(slots=True)
class Observations:
    """What the observers saw on the output topics and in the database."""

    published: dict[UUID, list[float]] = field(default_factory=dict)
    dead_letters: list[DeadLetterSeen] = field(default_factory=list)
    stored: dict[UUID, int] = field(default_factory=dict)

    def publication_count(self, event_id: UUID) -> int:
        """How many times ``event_id`` appeared on ``adis.security.events``."""
        return len(self.published.get(event_id, ()))

    def first_published(self, event_id: UUID) -> float | None:
        """When ``event_id`` first appeared on ``adis.security.events`` (monotonic)."""
        seen = self.published.get(event_id)
        return min(seen) if seen else None


@dataclass(frozen=True, slots=True)
class Check:
    """One verified guarantee."""

    name: str
    passed: bool
    detail: str


@dataclass(slots=True)
class ScenarioResult:
    """A scenario's submissions, expectations and checks."""

    name: str
    title: str
    submissions: list[Submission] = field(default_factory=list)
    poison_markers: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    started: float = 0.0
    finished: float = 0.0

    def check(self, name: str, passed: bool, detail: str) -> None:
        """Record a check."""
        self.checks.append(Check(name, passed, detail))

    @property
    def passed(self) -> bool:
        """Whether every check passed."""
        return all(check.passed for check in self.checks)

    def unique_accepted(self) -> list[UUID]:
        """Event ids first submitted and accepted in this scenario (duplicates excluded)."""
        return [
            submission.event_id
            for submission in self.submissions
            if submission.outcome is Outcome.ACCEPTED and not submission.duplicate
        ]


@dataclass(frozen=True, slots=True)
class Metrics:
    """The report's counters and latencies for a set of scenarios."""

    sent: int
    accepted: int
    normalized: int
    stored: int
    duplicates: int
    failed: int
    dead_lettered: int
    extra_rows: int
    extra_publications: int
    e2e_latencies_ms: tuple[float, ...]
    accept_latencies_ms: tuple[float, ...]

    @property
    def e2e_p50(self) -> float | None:
        """Median send-to-normalized latency."""
        return percentile(self.e2e_latencies_ms, 50)

    @property
    def e2e_p95(self) -> float | None:
        """95th percentile send-to-normalized latency."""
        return percentile(self.e2e_latencies_ms, 95)

    @property
    def accept_p50(self) -> float | None:
        """Median send-to-accepted latency."""
        return percentile(self.accept_latencies_ms, 50)

    @property
    def accept_p95(self) -> float | None:
        """95th percentile send-to-accepted latency."""
        return percentile(self.accept_latencies_ms, 95)


def metrics(results: Iterable[ScenarioResult], observations: Observations) -> Metrics:
    """Aggregate ``results`` against what was observed.

    - ``sent``: events submitted to the API (including duplicates and invalid ones) plus
      records injected directly into Kafka.
    - ``accepted``: submissions the API accepted.
    - ``normalized`` / ``stored``: distinct first-time events that reached
      ``adis.security.events`` / ``adis.security_events``.
    - ``duplicates``: accepted re-submissions of an already submitted ``event_id``.
    - ``failed``: submissions the API rejected or that were never accepted.
    - ``dead_lettered``: dead-letter records of the scenarios' injected records.
    - ``extra_rows`` / ``extra_publications``: rows or publications beyond one per event
      (rows must be 0; publications are at-least-once).
    """
    results = list(results)
    submissions = [item for result in results for item in result.submissions]
    unique = [item for result in results for item in result.unique_accepted()]
    markers = {marker for result in results for marker in result.poison_markers}
    injected = sum(len(result.poison_markers) for result in results)
    by_id = {item.event_id: item for item in submissions if not item.duplicate}
    e2e: list[float] = []
    accept: list[float] = []
    for event_id in unique:
        submission = by_id[event_id]
        seen = observations.first_published(event_id)
        if seen is not None:
            e2e.append((seen - submission.first_sent) * 1000)
        if submission.accepted_at is not None:
            accept.append((submission.accepted_at - submission.first_sent) * 1000)
    return Metrics(
        sent=len(submissions) + injected,
        accepted=sum(1 for item in submissions if item.outcome is Outcome.ACCEPTED),
        normalized=sum(1 for event_id in unique if event_id in observations.published),
        stored=sum(1 for event_id in unique if observations.stored.get(event_id, 0) > 0),
        duplicates=sum(
            1 for item in submissions if item.duplicate and item.outcome is Outcome.ACCEPTED
        ),
        failed=sum(1 for item in submissions if item.outcome is not Outcome.ACCEPTED),
        dead_lettered=sum(1 for seen in observations.dead_letters if seen.marker in markers),
        extra_rows=sum(max(0, observations.stored.get(event_id, 0) - 1) for event_id in unique),
        extra_publications=sum(
            max(0, observations.publication_count(event_id) - 1) for event_id in unique
        ),
        e2e_latencies_ms=tuple(sorted(e2e)),
        accept_latencies_ms=tuple(sorted(accept)),
    )


def percentile(values: Sequence[float], q: float) -> float | None:
    """The ``q``-th percentile with linear interpolation (numpy's default), or ``None``."""
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q / 100
    low, high = math.floor(rank), math.ceil(rank)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)
