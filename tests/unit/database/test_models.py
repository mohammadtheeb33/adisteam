"""ORM model definitions of the first ADIS tables."""

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, Table
from sqlalchemy.dialects.postgresql import INET, JSONB

from packages.database.models import AgentRecord, AgentStatus, OsType, SecurityEventRecord
from packages.events.canonical import parse_canonical_event
from tests.unit.events.canonical.samples import network


def _table(model: type[AgentRecord] | type[SecurityEventRecord]) -> Table:
    table = model.__table__
    assert isinstance(table, Table)
    return table


def _nullable(table: Table) -> set[str]:
    return {column.name for column in table.columns if column.nullable}


def test_agents_table() -> None:
    table = _table(AgentRecord)

    assert (table.schema, table.name) == ("adis", "agents")
    assert list(table.columns.keys()) == [
        "id",
        "name",
        "hostname",
        "os_type",
        "agent_version",
        "status",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
    ]
    assert _nullable(table) == {"first_seen", "last_seen"}
    assert [column.name for column in table.primary_key] == ["id"]


def test_agent_vocabularies_are_constrained() -> None:
    checks = {c.name for c in _table(AgentRecord).constraints if isinstance(c, CheckConstraint)}

    assert {"ck_agents_os_type", "ck_agents_status", "ck_agents_seen_order"} <= checks
    assert [status.value for status in AgentStatus] == [
        "pending",
        "active",
        "inactive",
        "decommissioned",
    ]
    assert [os_type.value for os_type in OsType] == ["linux", "windows", "macos", "other"]


def test_security_events_table() -> None:
    table = _table(SecurityEventRecord)

    assert (table.schema, table.name) == ("adis", "security_events")
    assert _nullable(table) == {
        "agent_id",
        "host_id",
        "severity_hint",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
    }
    assert isinstance(table.columns["src_ip"].type, INET)
    assert isinstance(table.columns["payload"].type, JSONB)
    assert table.columns["timestamp"].type.timezone is True  # type: ignore[attr-defined]
    assert table.columns["event_id"].unique is True


def test_agent_foreign_key_sets_null_on_delete() -> None:
    [foreign_key] = [
        c for c in _table(SecurityEventRecord).constraints if isinstance(c, ForeignKeyConstraint)
    ]

    assert foreign_key.column_keys == ["agent_id"]
    assert foreign_key.referred_table.name == "agents"
    assert foreign_key.ondelete == "SET NULL"


def test_indexes_are_few_and_retention_friendly() -> None:
    indexes: dict[str, Index] = {index.name: index for index in _table(SecurityEventRecord).indexes}  # type: ignore[misc]

    assert set(indexes) == {
        "ix_security_events_timestamp",
        "ix_security_events_received_at_brin",
        "ix_security_events_event_type_timestamp",
        "ix_security_events_host_id_timestamp",
        "ix_security_events_agent_id_timestamp",
        "ix_security_events_src_ip",
        "ix_security_events_dst_ip",
    }
    assert (
        indexes["ix_security_events_received_at_brin"].dialect_options["postgresql"]["using"]
        == "brin"
    )
    partial = {
        name
        for name, index in indexes.items()
        if index.dialect_options["postgresql"]["where"] is not None
    }
    assert partial == {
        "ix_security_events_host_id_timestamp",
        "ix_security_events_agent_id_timestamp",
        "ix_security_events_src_ip",
        "ix_security_events_dst_ip",
    }


def test_record_rebuilds_the_canonical_event() -> None:
    event = parse_canonical_event(network())
    record = SecurityEventRecord(payload=event.model_dump(mode="json"))

    assert record.to_canonical() == event
