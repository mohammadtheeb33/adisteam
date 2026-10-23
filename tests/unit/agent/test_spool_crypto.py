"""Spool encryption at rest: sealing, key storage, key checks and recovery."""

import base64
import sqlite3
import sys
from pathlib import Path

import pytest
from pydantic import SecretStr

from apps.agent.spool import Spool
from apps.agent.spool_crypto import (
    HEADER,
    KEY_BYTES,
    KEY_FILE,
    AesGcmCipher,
    NoEncryption,
    SpoolKeyError,
    decode_key,
    load_or_create_key,
    spool_cipher,
)
from tests.unit.log_capture import JsonLogCapture

PAYLOAD = b'{"event_id": "e-1", "message": "secret telemetry: user=root"}'


def _cipher(fill: int = 7) -> AesGcmCipher:
    return AesGcmCipher(bytes([fill]) * KEY_BYTES, protection="for tests")


def _preserved_spools(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.startswith("spool.sqlite3.corrupt-")]


def _file_contains(path: Path, fragment: bytes) -> bool:
    return fragment in path.read_bytes()


def _stored_payloads(path: Path) -> list[bytes]:
    with sqlite3.connect(path) as connection:
        return [bytes(row[0]) for row in connection.execute("SELECT payload FROM events")]


# ----------------------------------------------------------------------------- cipher


def test_sealed_records_round_trip_and_hide_the_payload() -> None:
    cipher = _cipher()

    sealed = cipher.seal("e-1", PAYLOAD)

    assert sealed.startswith(HEADER)
    assert b"secret telemetry" not in sealed
    assert cipher.open("e-1", sealed) == PAYLOAD
    assert cipher.seal("e-1", PAYLOAD) != sealed  # a fresh nonce per record


def test_a_record_cannot_move_to_another_event_id() -> None:
    cipher = _cipher()

    with pytest.raises(SpoolKeyError):
        cipher.open("e-2", cipher.seal("e-1", PAYLOAD))


@pytest.mark.parametrize("position", [len(HEADER) + 1, -1])
def test_altered_records_are_detected(position: int) -> None:
    cipher = _cipher()
    sealed = bytearray(cipher.seal("e-1", PAYLOAD))
    sealed[position] ^= 0x01

    with pytest.raises(SpoolKeyError):
        cipher.open("e-1", bytes(sealed))


def test_another_key_cannot_open_a_record() -> None:
    with pytest.raises(SpoolKeyError):
        _cipher(8).open("e-1", _cipher(7).seal("e-1", PAYLOAD))


def test_plaintext_records_written_before_encryption_stay_readable() -> None:
    assert _cipher().open("e-1", PAYLOAD) == PAYLOAD


def test_without_encryption_a_sealed_record_needs_the_key() -> None:
    with pytest.raises(SpoolKeyError, match="encryption is disabled"):
        NoEncryption().open("e-1", _cipher().seal("e-1", PAYLOAD))


# -------------------------------------------------------------------------------- keys


def test_the_key_is_created_once_and_reused(tmp_path: Path) -> None:
    first = load_or_create_key(tmp_path)
    second = load_or_create_key(tmp_path)

    assert len(first.key) == KEY_BYTES
    assert second.key == first.key


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_the_key_file_is_wrapped_by_dpapi_on_windows(tmp_path: Path) -> None:
    key = load_or_create_key(tmp_path)

    stored = (tmp_path / KEY_FILE).read_bytes()
    assert key.protection == "protected by DPAPI"
    assert key.key not in stored
    assert len(stored) > KEY_BYTES


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_key_file_is_private_on_posix(tmp_path: Path) -> None:
    load_or_create_key(tmp_path)

    assert (tmp_path / KEY_FILE).stat().st_mode & 0o777 == 0o600


def test_a_supplied_key_replaces_the_key_file(tmp_path: Path) -> None:
    supplied = SecretStr(base64.urlsafe_b64encode(b"k" * KEY_BYTES).decode().rstrip("="))

    cipher = spool_cipher(tmp_path, enabled=True, supplied_key=supplied)

    assert not (tmp_path / KEY_FILE).exists()
    assert "AGENT_SPOOL_KEY" in cipher.description
    assert (
        AesGcmCipher(b"k" * KEY_BYTES, protection="x").open("e-1", cipher.seal("e-1", PAYLOAD))
        == PAYLOAD
    )


@pytest.mark.parametrize("value", ["", "not base64 !!", base64.b64encode(b"short").decode()])
def test_supplied_keys_must_be_32_bytes(value: str) -> None:
    with pytest.raises(ValueError, match="32 bytes") as caught:
        decode_key(SecretStr(value))

    assert value not in str(caught.value) or not value


def test_disabled_encryption_creates_no_key(tmp_path: Path) -> None:
    cipher = spool_cipher(tmp_path, enabled=False)

    assert isinstance(cipher, NoEncryption)
    assert not (tmp_path / KEY_FILE).exists()


def test_an_unusable_key_file_is_preserved_and_replaced(
    tmp_path: Path, json_logs: JsonLogCapture
) -> None:
    (tmp_path / KEY_FILE).write_bytes(b"not a key")

    cipher = spool_cipher(tmp_path, enabled=True)

    assert cipher.open("e-1", cipher.seal("e-1", PAYLOAD)) == PAYLOAD
    assert [path.name.startswith(f"{KEY_FILE}.unusable-") for path in tmp_path.iterdir()].count(
        True
    ) == 1
    assert json_logs.records()[-1]["action"] == "agent_spool_key_unusable"


# ------------------------------------------------------------------------------- spool


async def test_the_spool_stores_only_sealed_payloads(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    with Spool(path, max_events=10, cipher=_cipher()) as spool:
        await spool.append([("e-1", PAYLOAD)])
        [event] = await spool.peek(10)

    assert event.payload == PAYLOAD
    [stored] = _stored_payloads(path)
    assert stored.startswith(HEADER)
    assert not _file_contains(path, b"secret telemetry")


async def test_a_spool_the_key_cannot_open_is_preserved_and_replaced(
    tmp_path: Path, json_logs: JsonLogCapture
) -> None:
    path = tmp_path / "spool.sqlite3"
    with Spool(path, max_events=10, cipher=_cipher(7)) as spool:
        await spool.append([("e-1", PAYLOAD)])

    with Spool.open(path, max_events=10, cipher=_cipher(8)) as reopened:
        assert (await reopened.stats()).queued == 0

    assert json_logs.records()[-1]["action"] == "agent_spool_key_mismatch"
    preserved = _preserved_spools(tmp_path)
    assert preserved
    with Spool(preserved[0], max_events=10, cipher=_cipher(7)) as original:
        assert [event.payload for event in await original.peek(10)] == [PAYLOAD]


async def test_turning_encryption_off_does_not_expose_an_encrypted_spool(
    tmp_path: Path,
) -> None:
    path = tmp_path / "spool.sqlite3"
    with Spool(path, max_events=10, cipher=_cipher()) as spool:
        await spool.append([("e-1", PAYLOAD)])

    with pytest.raises(SpoolKeyError):
        Spool(path, max_events=10, cipher=NoEncryption())


async def test_a_plaintext_spool_is_upgraded_when_encryption_is_turned_on(
    tmp_path: Path,
) -> None:
    path = tmp_path / "spool.sqlite3"
    with Spool(path, max_events=10) as spool:  # written by an agent without encryption
        await spool.append([("old", b'{"old": 1}')])

    with Spool(path, max_events=10, cipher=_cipher()) as spool:
        await spool.append([("new", b'{"new": 1}')])
        events = await spool.peek(10)

    assert [event.payload for event in events] == [b'{"old": 1}', b'{"new": 1}']
    old, new = _stored_payloads(path)
    assert (old.startswith(HEADER), new.startswith(HEADER)) == (False, True)
    with pytest.raises(SpoolKeyError):  # the key check is now encrypted too
        Spool(path, max_events=10, cipher=NoEncryption())


async def test_an_altered_record_is_quarantined_and_the_rest_delivered(
    tmp_path: Path, json_logs: JsonLogCapture
) -> None:
    path = tmp_path / "spool.sqlite3"
    with Spool(path, max_events=10, cipher=_cipher()) as spool:
        await spool.append([("e-1", PAYLOAD), ("e-2", PAYLOAD)])
    with sqlite3.connect(path) as connection:
        (stored,) = connection.execute(
            "SELECT payload FROM events WHERE event_id = 'e-1'"
        ).fetchone()
        altered = bytearray(stored)
        altered[-1] ^= 0x01
        connection.execute(
            "UPDATE events SET payload = ? WHERE event_id = 'e-1'", (bytes(altered),)
        )

    with Spool(path, max_events=10, cipher=_cipher()) as spool:
        events = await spool.peek(10)
        stats = await spool.stats()
        quarantined = await spool.quarantined(10)

    assert [event.event_id for event in events] == ["e-2"]
    assert (stats.queued, stats.quarantined) == (1, 1)
    assert quarantined == [("e-1", "spool record failed its integrity check")]
    assert json_logs.records()[-1]["action"] == "agent_spool_record_unreadable"


def test_the_spool_reports_its_encryption(tmp_path: Path) -> None:
    with Spool(tmp_path / "a.sqlite3", max_events=1, cipher=_cipher()) as encrypted:
        assert encrypted.encryption == "aes-256-gcm, key for tests"
    with Spool(tmp_path / "b.sqlite3", max_events=1) as plain:
        assert plain.encryption == "disabled"
