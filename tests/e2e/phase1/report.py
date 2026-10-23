"""Markdown and JSON rendering of a verification run."""

import json
from collections.abc import Sequence
from dataclasses import asdict
from typing import Final

from tests.e2e.phase1.ledger import Metrics, ScenarioResult, metrics
from tests.e2e.phase1.verification import SERVICE_SETTINGS, VerificationRun

STEADY_STATE: Final = ("single", "batch", "invalid", "duplicate")

_COLUMNS: Final = (
    "Sent",
    "Accepted",
    "Normalized",
    "Stored",
    "Duplicates",
    "Failed",
    "Dead-lettered",
    "Latency p50",
    "Latency p95",
)


def render_markdown(run: VerificationRun) -> str:
    """The human-readable report."""
    verdict = "PASS" if run.passed else "FAIL"
    observations = run.observations
    steady = [result for result in run.scenarios if result.name in STEADY_STATE]
    faults = [result for result in run.scenarios if result.name not in STEADY_STATE]
    lines = [
        "# Phase 1 verification report",
        "",
        f"**Result: {verdict}.** Run `{run.run_id}`, started "
        f"{run.started_at:%Y-%m-%d %H:%M:%S} UTC, took {run.duration_seconds:.0f} s.",
        "",
        "Flow under test: generator → ingestion API (HTTP) → Kafka (`system_logs`, "
        "`auth_events`, `network_flows`) → normalizer → Kafka "
        "(`adis.security.events`) and PostgreSQL (`adis.security_events`). Every service ran "
        "as a real process against a real broker and database; outages were real container "
        "stops.",
        "",
        "## Results",
        "",
        "| Scenario | " + " | ".join(_COLUMNS) + " |",
        "|---|" + "---:|" * len(_COLUMNS),
    ]
    for result in run.scenarios:
        lines.append(_row(result.title, metrics([result], observations)))
    if steady:
        lines.append(
            _row("**Steady state** (first four)", metrics(steady, observations), bold=True)
        )
    lines.append(_row("**All scenarios**", metrics(run.scenarios, observations), bold=True))
    lines += [
        "",
        "Latency is measured from the generator's first send attempt to the normalized event "
        "appearing on `adis.security.events` (both on the verifier's clock). For the outage "
        "scenarios it includes the outage itself. See [Definitions](#definitions).",
        "",
        "### Acceptance latency (HTTP 202)",
        "",
        "| Scenario | p50 | p95 |",
        "|---|---:|---:|",
    ]
    for result in run.scenarios:
        figures = metrics([result], observations)
        lines.append(f"| {result.title} | {_ms(figures.accept_p50)} | {_ms(figures.accept_p95)} |")
    lines += ["", "## Checks", ""]
    for result in [*run.scenarios, run.global_checks]:
        status = "passed" if result.passed else "**FAILED**"
        lines.append(f"### {result.title} ({status})")
        lines.append("")
        for check in result.checks:
            mark = "✅" if check.passed else "❌"
            lines.append(f"- {mark} {check.name}: {check.detail}")
        for note in result.notes:
            lines.append(f"- Note: {note}")
        lines.append("")
    if faults:
        lines += [
            "## Fault injection",
            "",
            "- Retried API requests (status or transport error: count): "
            f"{_counts(run.api_retries)}",
            f"- Normalizer log actions during the run: {_counts(run.normalizer_log)}",
            "",
        ]
    lines += [
        "## Environment and settings",
        "",
        *(f"- {name}: `{value}`" for name, value in run.environment.items()),
        f"- Service settings (others at their defaults): {_counts(SERVICE_SETTINGS)}",
        f"- Batch scenario: {run.config.batch_events} events; outages: "
        f"{run.config.outage_events} events, {run.config.outage_seconds:.0f} s down",
        "",
        "## Definitions",
        "",
        "- **Sent**: events submitted to the API (including duplicates and invalid events) plus "
        "records written straight to Kafka.",
        "- **Accepted**: submissions the API accepted (202).",
        "- **Normalized**: distinct first-time events seen on `adis.security.events`.",
        "- **Stored**: distinct first-time events with a row in `adis.security_events`.",
        "- **Duplicates**: accepted re-submissions of an event already submitted; they must "
        "create no row and no publication.",
        "- **Failed**: submissions the API rejected (4xx) or never accepted.",
        "- **Dead-lettered**: records of the scenario found on `adis.deadletter`.",
        "",
        "Reproduce with `make verify-phase1` (see [VERIFICATION.md](VERIFICATION.md)).",
        "",
    ]
    return "\n".join(lines)


def render_json(run: VerificationRun) -> str:
    """Machine-readable summary: per-scenario metrics and every check."""
    observations = run.observations

    def figures(results: Sequence[ScenarioResult]) -> dict[str, object]:
        values = metrics(results, observations)
        summary = {key: value for key, value in asdict(values).items() if not key.endswith("_ms")}
        summary |= {
            "latency_p50_ms": values.e2e_p50,
            "latency_p95_ms": values.e2e_p95,
            "accept_p50_ms": values.accept_p50,
            "accept_p95_ms": values.accept_p95,
        }
        return summary

    document = {
        "run_id": run.run_id,
        "passed": run.passed,
        "started_at": run.started_at.isoformat(),
        "duration_seconds": round(run.duration_seconds, 1),
        "environment": run.environment,
        "scenarios": [
            {
                "name": result.name,
                "passed": result.passed,
                "metrics": figures([result]),
                "checks": [asdict(check) for check in result.checks],
                "notes": result.notes,
            }
            for result in run.scenarios
        ],
        "global_checks": [asdict(check) for check in run.global_checks.checks],
        "totals": figures(run.scenarios),
        "api_retries": run.api_retries,
        "normalizer_log": run.normalizer_log,
    }
    return json.dumps(document, indent=2, default=str)


def _row(title: str, values: Metrics, *, bold: bool = False) -> str:
    cells = [
        values.sent,
        values.accepted,
        values.normalized,
        values.stored,
        values.duplicates,
        values.failed,
        values.dead_lettered,
    ]
    rendered = [f"**{cell}**" if bold else str(cell) for cell in cells]
    rendered += [_ms(values.e2e_p50), _ms(values.e2e_p95)]
    return f"| {title} | " + " | ".join(rendered) + " |"


def _ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value / 1000:.1f} s" if value >= 10_000 else f"{value:.0f} ms"


def _counts(values: dict[str, object] | dict[str, int] | dict[str, str]) -> str:
    return ", ".join(f"`{key}` = {value}" for key, value in values.items()) or "none"
