"""Access to the external services of integration and end-to-end tests.

Locally, a test whose service is not configured is **skipped**. With
``ADIS_REQUIRE_SERVICES=1`` (set in CI) it **fails** instead, so critical integration
tests can never pass by being silently skipped.
"""

import os
from typing import Final

import pytest

REQUIRE_SERVICES_VARIABLE: Final = "ADIS_REQUIRE_SERVICES"


def services_required() -> bool:
    """Whether a missing service must fail the test run."""
    return os.environ.get(REQUIRE_SERVICES_VARIABLE, "").strip() in {"1", "true", "yes"}


def require_variable(name: str, purpose: str = "see docs/DEVELOPMENT.md") -> str:
    """The value of ``name``; skips (or fails, when services are required) if it is unset."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    message = f"{name} is not set ({purpose})"
    if services_required():
        pytest.fail(f"{message}; {REQUIRE_SERVICES_VARIABLE}=1 forbids skipping", pytrace=False)
    pytest.skip(message)
