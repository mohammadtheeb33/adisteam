"""Capture structured log output for assertions."""

import io
import json


class JsonLogCapture:
    """Collects JSON lines written by a ``JsonFormatter`` handler."""

    def __init__(self) -> None:
        self.stream = io.StringIO()

    @property
    def text(self) -> str:
        """Everything written so far."""
        return self.stream.getvalue()

    def records(self) -> list[dict[str, object]]:
        """Every line, parsed."""
        return [json.loads(line) for line in self.text.splitlines() if line]

    def with_message(self, message: str) -> list[dict[str, object]]:
        """Parsed lines whose ``message`` equals ``message``."""
        return [record for record in self.records() if record["message"] == message]
