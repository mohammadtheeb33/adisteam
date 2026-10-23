"""The migration and the ORM models describe the same schema (checked without a database).

The migration's offline SQL is compared with the DDL SQLAlchemy compiles from the models,
column by column, constraint by constraint and index by index. The integration suite
additionally runs ``alembic check`` against a real database.
"""

import io
import re
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable

from packages.database import ADIS_SCHEMA, Base, models

REPO_ROOT = Path(__file__).resolve().parents[3]
_TABLE = re.compile("CREATE TABLE (?P<name>\\S+) \\((?P<body>.*?)\\n\\)", re.DOTALL)
_ALTERED = re.compile(
    r"^ALTER TABLE (?P<name>\S+) "
    r"(?:ADD COLUMN (?P<column>.*)|ADD (?P<clause>CONSTRAINT .*)"
    r"|DROP CONSTRAINT (?P<dropped>\S+)|DROP COLUMN (?P<dropped_column>\S+));$",
    re.MULTILINE,
)
_DIALECT = postgresql.dialect()  # type: ignore[no-untyped-call]


def _offline_sql(*, upgrade: bool) -> str:
    buffer = io.StringIO()
    config = Config(output_buffer=buffer)
    config.set_main_option("script_location", str(REPO_ROOT / "packages/database/migrations"))
    config.set_main_option("path_separator", "os")
    if upgrade:
        command.upgrade(config, "head", sql=True)
    else:
        command.downgrade(config, "head:base", sql=True)
    return buffer.getvalue()


def _normalize(line: str) -> str:
    return " ".join(line.strip().rstrip(",").split())


def _table_lines(sql: str) -> dict[str, set[str]]:
    """Each table's column and constraint lines, including constraints added later."""
    tables = {
        match["name"]: {_normalize(line) for line in match["body"].splitlines() if line.strip()}
        for match in _TABLE.finditer(sql)
    }
    for match in _ALTERED.finditer(sql):
        lines = tables[match["name"]]
        if match["column"] is not None:
            lines.add(_normalize(match["column"]))
        elif match["dropped_column"] is not None:
            lines -= {line for line in lines if line.startswith(f"{match['dropped_column']} ")}
        elif match["clause"] is not None:
            lines.add(_normalize(match["clause"]))
        else:
            lines -= {line for line in lines if line.startswith(f"CONSTRAINT {match['dropped']} ")}
    return tables


def _index_statements(sql: str) -> set[str]:
    return {
        _normalize(line).rstrip(";")
        for line in sql.splitlines()
        if line.strip().startswith(("CREATE INDEX", "CREATE UNIQUE INDEX"))
    }


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _offline_sql(upgrade=True)


def _model_ddl() -> tuple[dict[str, set[str]], set[str]]:
    assert models.__name__
    tables: dict[str, set[str]] = {}
    indexes: set[str] = set()
    for table in Base.metadata.sorted_tables:
        tables.update(_table_lines(str(CreateTable(table).compile(dialect=_DIALECT))))
        indexes |= {
            _normalize(str(CreateIndex(index).compile(dialect=_DIALECT))) for index in table.indexes
        }
    return (tables, indexes)


def test_migration_creates_exactly_the_model_tables(upgrade_sql: str) -> None:
    migrated = {
        name: lines
        for name, lines in _table_lines(upgrade_sql).items()
        if name != f"{ADIS_SCHEMA}.alembic_version"
    }
    modeled, _ = _model_ddl()
    assert set(migrated) == {"adis.agents", "adis.security_events"}
    for name, lines in modeled.items():
        assert migrated[name] == lines, f"{name} differs between migration and models"


def test_migration_creates_exactly_the_model_indexes(upgrade_sql: str) -> None:
    _, modeled = _model_ddl()
    assert _index_statements(upgrade_sql) == modeled


def test_row_level_security_is_enabled(upgrade_sql: str) -> None:
    for table in ("agents", "security_events", "alembic_version"):
        assert f"ALTER TABLE adis.{table} ENABLE ROW LEVEL SECURITY;" in upgrade_sql


def test_downgrade_drops_every_table() -> None:
    downgrade_sql = _offline_sql(upgrade=False)
    assert downgrade_sql.index("DROP TABLE adis.security_events") < downgrade_sql.index(
        "DROP TABLE adis.agents"
    )


def test_single_head_revision() -> None:
    config = Config()
    config.set_main_option("script_location", str(REPO_ROOT / "packages/database/migrations"))
    config.set_main_option("path_separator", "os")
    from alembic.script import ScriptDirectory

    assert len(ScriptDirectory.from_config(config).get_heads()) == 1
