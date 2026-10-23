"""JSON log schema, correlation fields and secret safety of the formatter."""

import logging
import re

from pydantic import SecretStr

from packages.observability import REDACTED, STANDARD_FIELDS, log_context
from tests.unit.log_capture import JsonLogCapture

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
logger = logging.getLogger("tests.observability")


def test_every_standard_field_is_present_in_order(json_logs: JsonLogCapture) -> None:
    logger.info("plain message")

    [record] = json_logs.records()
    assert list(record)[: len(STANDARD_FIELDS)] == list(STANDARD_FIELDS)
    assert record["level"] == "INFO"
    assert record["service"] == "adis-test"
    assert record["environment"] == "test"
    assert record["message"] == "plain message"
    assert record["logger"] == "tests.observability"
    for field in ("request_id", "trace_id", "event_id", "host_id", "threat_id"):
        assert record[field] is None
    assert record["action"] is None
    assert record["latency_ms"] is None


def test_timestamp_is_utc_iso8601_with_milliseconds(json_logs: JsonLogCapture) -> None:
    logger.info("tick")

    [record] = json_logs.records()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", str(record["timestamp"]))


def test_correlation_fields_come_from_the_log_context(json_logs: JsonLogCapture) -> None:
    with log_context(
        request_id="req-1", trace_id=TRACE, event_id="evt-1", host_id="host-7", threat_id="thr-2"
    ):
        logger.info("in context")

    [record] = json_logs.records()
    assert (
        record["request_id"],
        record["trace_id"],
        record["event_id"],
        record["host_id"],
        record["threat_id"],
    ) == ("req-1", TRACE, "evt-1", "host-7", "thr-2")


def test_extra_fields_override_context_and_are_included(json_logs: JsonLogCapture) -> None:
    with log_context(event_id="from-context"):
        logger.warning(
            "published",
            extra={
                "event_id": "from-extra",
                "action": "kafka_publish",
                "latency_ms": 12.5,
                "topic": "system_logs",
                "attempt": 2,
            },
        )

    [record] = json_logs.records()
    assert record["event_id"] == "from-extra"
    assert record["action"] == "kafka_publish"
    assert record["latency_ms"] == 12.5
    assert record["topic"] == "system_logs"
    assert record["attempt"] == 2


def test_fixed_fields_cannot_be_overridden(json_logs: JsonLogCapture) -> None:
    logger.info("spoof attempt", extra={"service": "evil", "environment": "prod", "level": "X"})

    [record] = json_logs.records()
    assert (record["service"], record["environment"], record["level"]) == (
        "adis-test",
        "test",
        "INFO",
    )


def test_each_record_is_a_single_line(json_logs: JsonLogCapture) -> None:
    logger.info("first line\nsecond line")

    assert json_logs.text.count("\n") == 1
    assert json_logs.records()[0]["message"] == "first line\nsecond line"


def test_unserializable_extras_are_stringified(json_logs: JsonLogCapture) -> None:
    class Custom:
        def __str__(self) -> str:
            return "custom-object"

    logger.info("custom", extra={"value": Custom()})

    assert json_logs.records()[0]["value"] == "custom-object"


def test_exceptions_are_structured_and_scrubbed(json_logs: JsonLogCapture) -> None:
    try:
        raise ConnectionError("cannot reach postgresql://adis:sentinel-pw@db:5432/postgres")
    except ConnectionError:
        logger.exception("database unreachable")

    [record] = json_logs.records()
    exception = record["exception"]
    assert isinstance(exception, dict)
    assert exception["type"] == "ConnectionError"
    assert "Traceback" in exception["stacktrace"]
    assert "sentinel" not in json_logs.text
    assert record["level"] == "ERROR"


def test_secrets_never_reach_the_output(json_logs: JsonLogCapture) -> None:
    logger.info(
        "login attempt password=%s with Authorization: Bearer %s",
        "sentinel-pw-1",
        "sentinel-token-2",
        extra={
            "password": "sentinel-pw-3",
            "headers": {"authorization": "Basic sentinel-4", "accept": "text/plain"},
            "api_key": "sentinel-5",
            "settings_secret": SecretStr("sentinel-6"),
            "dsn": "redis://:sentinel-7@cache:6379/0",
            "note": (
                "private key -----BEGIN PRIVATE KEY-----\nsentinel-8\n-----END PRIVATE KEY-----"
            ),
        },
    )

    assert "sentinel" not in json_logs.text
    [record] = json_logs.records()
    assert record["password"] == REDACTED
    assert record["headers"] == {"authorization": REDACTED, "accept": "text/plain"}
