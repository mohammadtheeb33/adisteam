"""Guard: structured log fields must not collide with ``LogRecord`` attributes.

``logging`` raises ``KeyError`` for such an ``extra`` key, but only once the record is
built, that is when the level is enabled. The failure therefore hides in tests (INFO
disabled) and crashes production code paths (INFO enabled).
"""

import ast
import logging
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
RESERVED = frozenset(vars(logging.LogRecord("n", 0, "p", 0, "m", None, None))) | {
    "message",
    "asctime",
}
SOURCES = sorted(
    path
    for directory in ("apps", "packages", "scripts", "ml")
    for path in (ROOT / directory).rglob("*.py")
    if "migrations" not in path.parts
)


def _extra_keys(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        (key.lineno, key.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword)
        and node.arg == "extra"
        and isinstance(node.value, ast.Dict)
        for key in node.value.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]


def test_sources_are_scanned() -> None:
    assert len(SOURCES) > 50


@pytest.mark.parametrize("path", SOURCES, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_no_reserved_log_record_keys(path: Path) -> None:
    clashes = [f"line {line}: {key!r}" for line, key in _extra_keys(path) if key in RESERVED]

    assert clashes == []
