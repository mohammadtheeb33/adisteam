"""Declarative base conventions."""

from datetime import datetime

from sqlalchemy import DateTime

from packages.database import ADIS_SCHEMA, NAMING_CONVENTION, Base


def test_tables_live_in_the_adis_schema() -> None:
    assert ADIS_SCHEMA == "adis"
    assert Base.metadata.schema == ADIS_SCHEMA


def test_constraint_naming_convention_is_applied() -> None:
    assert Base.metadata.naming_convention == NAMING_CONVENTION
    assert set(NAMING_CONVENTION) == {"ix", "uq", "ck", "fk", "pk"}


def test_datetimes_are_timezone_aware() -> None:
    datetime_type = Base.type_annotation_map[datetime]

    assert isinstance(datetime_type, DateTime)
    assert datetime_type.timezone is True
