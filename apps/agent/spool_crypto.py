"""Encryption at rest for the agent spool.

Queued and quarantined events are sealed with **AES-256-GCM**. Each record gets its own
random 96-bit nonce, and its ``event_id`` is authenticated as associated data, so a
record cannot be moved to another row, altered or truncated without detection.

The key (32 random bytes) is created once, in ``<AGENT_DATA_DIR>/spool.key``:

- **Windows:** the file holds the key wrapped with DPAPI for the agent's account
  (``CryptProtectData``, with an ADIS-specific entropy). A copy of the data directory is
  useless on another machine or under another account.
- **POSIX:** the file holds the key, mode ``0600``, in the ``0700`` data directory.
- **Supplied key:** ``AGENT_SPOOL_KEY`` (32 bytes, base64url) replaces the file, for
  deployments that keep secrets in a secret store rather than beside the data.

Records written before encryption was enabled stay readable: stored values without the
``ADIS1`` header are plaintext.
"""

import base64
import binascii
import logging
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr

logger = logging.getLogger(__name__)

KEY_FILE: Final = "spool.key"
KEY_BYTES: Final = 32
HEADER: Final = b"ADIS\x01"
"""Marks a sealed record (format version 1): header, 12-byte nonce, ciphertext and tag."""
_NONCE_BYTES: Final = 12
_KEY_FILE_MODE: Final = 0o600
_DPAPI_ENTROPY: Final = b"adis-agent-spool-key-v1"


class SpoolKeyError(Exception):
    """The spool key is missing, unusable, or does not open the stored records."""


class PayloadCipher(Protocol):
    """Seals payloads before they are written to the spool and opens them on read."""

    @property
    def description(self) -> str:
        """Human-readable algorithm and key protection, for ``status``."""
        ...

    def seal(self, event_id: str, payload: bytes) -> bytes:
        """The stored form of ``payload``."""
        ...

    def open(self, event_id: str, stored: bytes) -> bytes:
        """The payload of a stored record.

        Raises:
            SpoolKeyError: If the record cannot be opened with this cipher.
        """
        ...


class NoEncryption:
    """Stores payloads as they are (``AGENT_SPOOL_ENCRYPTION=false``)."""

    description = "disabled"

    def seal(self, event_id: str, payload: bytes) -> bytes:
        """``payload`` unchanged."""
        return payload

    def open(self, event_id: str, stored: bytes) -> bytes:
        """``stored`` unchanged; a sealed record needs the key.

        Raises:
            SpoolKeyError: If the record was sealed.
        """
        if stored.startswith(HEADER):
            raise SpoolKeyError("the record is encrypted, but spool encryption is disabled")
        return stored


class AesGcmCipher:
    """AES-256-GCM with a random nonce per record and the event id as associated data."""

    def __init__(self, key: bytes, *, protection: str) -> None:
        if len(key) != KEY_BYTES:
            raise ValueError(f"the spool key must be {KEY_BYTES} bytes")
        self._aead = AESGCM(key)
        self.description = f"aes-256-gcm, key {protection}"

    def seal(self, event_id: str, payload: bytes) -> bytes:
        """``HEADER`` + nonce + ciphertext and tag."""
        nonce = os.urandom(_NONCE_BYTES)
        return HEADER + nonce + self._aead.encrypt(nonce, payload, event_id.encode())

    def open(self, event_id: str, stored: bytes) -> bytes:
        """Decrypt and authenticate a sealed record; plaintext records pass through.

        Raises:
            SpoolKeyError: If the record was sealed with another key, or altered.
        """
        if not stored.startswith(HEADER):
            return stored  # written before encryption was enabled
        body = stored[len(HEADER) :]
        nonce, ciphertext = body[:_NONCE_BYTES], body[_NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, ciphertext, event_id.encode())
        except (InvalidTag, ValueError):
            raise SpoolKeyError("the record does not open with this key") from None


@dataclass(frozen=True, slots=True)
class SpoolKey:
    """A usable key and how it is protected at rest."""

    key: bytes
    protection: str


def spool_cipher(
    data_dir: Path, *, enabled: bool, supplied_key: SecretStr | None = None
) -> PayloadCipher:
    """The cipher for the spool in ``data_dir`` (the key is created on first use).

    An unusable key file (unreadable, wrong length, or wrapped for another Windows
    account) is set aside as ``spool.key.unusable-<UTC time>`` and replaced: the records
    it sealed can then no longer be opened, and the spool sets them aside in turn
    (``Spool.open``), so the agent keeps collecting instead of failing to start.
    """
    if not enabled:
        return NoEncryption()
    if supplied_key is not None:
        return AesGcmCipher(decode_key(supplied_key), protection="supplied by AGENT_SPOOL_KEY")
    try:
        found = load_or_create_key(data_dir)
    except SpoolKeyError as error:
        preserved = _set_aside(data_dir / KEY_FILE)
        logger.error(
            "spool key is unusable; it was preserved and replaced",
            extra={
                "action": "agent_spool_key_unusable",
                "reason": str(error),
                "preserved_as": str(preserved),
            },
        )
        found = load_or_create_key(data_dir)
    return AesGcmCipher(found.key, protection=found.protection)


def decode_key(value: SecretStr) -> bytes:
    """Decode a base64url (or standard base64) 32-byte key.

    Raises:
        ValueError: If it is not base64 of exactly 32 bytes. The message never contains
            the value.
    """
    text = value.get_secret_value().strip()
    try:
        key = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError(f"must be {KEY_BYTES} bytes encoded as base64url") from None
    if len(key) != KEY_BYTES:
        raise ValueError(f"must be {KEY_BYTES} bytes encoded as base64url")
    return key


def load_or_create_key(data_dir: Path) -> SpoolKey:
    """The key in ``data_dir``, created on first use (exclusively, then synced to disk).

    Raises:
        SpoolKeyError: If the key file exists but cannot be used.
    """
    path = data_dir / KEY_FILE
    protection = "protected by DPAPI" if sys.platform == "win32" else "in a 0600 file"
    try:
        stored = path.read_bytes()
    except FileNotFoundError:
        key = os.urandom(KEY_BYTES)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _KEY_FILE_MODE)
        except FileExistsError:  # another process created it first
            return load_or_create_key(data_dir)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_protect(key))
            handle.flush()
            os.fsync(handle.fileno())
        return SpoolKey(key, protection)
    except OSError as error:
        raise SpoolKeyError(f"the key file cannot be read ({type(error).__name__})") from None
    key = _unprotect(stored)
    if len(key) != KEY_BYTES:
        raise SpoolKeyError("the key file does not hold a valid key")
    return SpoolKey(key, protection)


def _set_aside(path: Path) -> Path:
    preserved = path.with_name(f"{path.name}.unusable-{datetime.now(UTC):%Y%m%dT%H%M%SZ}")
    path.rename(preserved)
    return preserved


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = (
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        )

    _CRYPTPROTECT_UI_FORBIDDEN: Final = 0x1

    def _dpapi(data: bytes, *, protect: bool) -> bytes:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        source = ctypes.create_string_buffer(data, len(data))
        entropy = ctypes.create_string_buffer(_DPAPI_ENTROPY, len(_DPAPI_ENTROPY))
        blob_in = _Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_char)))
        blob_entropy = _Blob(
            len(_DPAPI_ENTROPY), ctypes.cast(entropy, ctypes.POINTER(ctypes.c_char))
        )
        blob_out = _Blob()
        function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        succeeded = function(
            ctypes.byref(blob_in),
            None,
            ctypes.byref(blob_entropy),
            None,
            None,
            _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        )
        if not succeeded:
            raise SpoolKeyError(f"DPAPI refused the key (Windows error {ctypes.get_last_error()})")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            kernel32.LocalFree(blob_out.pbData)

    def _protect(key: bytes) -> bytes:
        return _dpapi(key, protect=True)

    def _unprotect(stored: bytes) -> bytes:
        return _dpapi(stored, protect=False)

else:

    def _protect(key: bytes) -> bytes:
        return key

    def _unprotect(stored: bytes) -> bytes:
        return stored
