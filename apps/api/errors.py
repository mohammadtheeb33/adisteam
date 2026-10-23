"""Error responses of the ingestion API.

Every error uses one envelope, ``{"error": {"code", "message", "request_id", "details"}}``.
``code`` is stable and machine-readable; ``message`` is for humans. Messages and details
name fields but never echo submitted values.
"""

import json
from collections.abc import Mapping, Sequence
from enum import StrEnum
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from packages.observability import current_request_id


class ErrorCode(StrEnum):
    """Stable error codes."""

    INVALID_JSON = "invalid_json"
    VALIDATION_FAILED = "validation_failed"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    EMPTY_BATCH = "empty_batch"
    BATCH_TOO_LARGE = "batch_too_large"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    UNAUTHORIZED = "unauthorized"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    HTTP_ERROR = "http_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    AGENT_MISMATCH = "agent_mismatch"
    HOST_MISMATCH = "host_mismatch"
    INTERNAL_ERROR = "internal_error"


class EventError(BaseModel):
    """Why one event was rejected."""

    index: int | None = Field(default=None, description="Position in the batch, if any.")
    code: ErrorCode = Field(description="Machine-readable reason.")
    issues: list[str] = Field(default_factory=list, description="Failing fields, no values.")


class ErrorBody(BaseModel):
    """Error details."""

    code: ErrorCode = Field(description="Stable, machine-readable error code.")
    message: str = Field(description="Human-readable explanation.")
    request_id: str | None = Field(description="Correlates with logs and X-Request-ID.")
    details: list[EventError] = Field(default_factory=list, description="Per-event issues.")


class ErrorResponse(BaseModel):
    """Envelope of every error response."""

    error: ErrorBody


class ApiError(Exception):
    """An error with a defined HTTP status and error code."""

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        *,
        details: Sequence[EventError] = (),
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = list(details)
        self.headers = dict(headers or {})


def error_response(
    status_code: int,
    code: ErrorCode,
    message: str,
    *,
    details: Sequence[EventError] = (),
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """Render an error envelope."""
    body = ErrorResponse(
        error=ErrorBody(
            code=code, message=message, request_id=current_request_id(), details=list(details)
        )
    )
    return JSONResponse(
        status_code=status_code, content=body.model_dump(mode="json"), headers=dict(headers or {})
    )


def internal_error_body(request_id: str) -> bytes:
    """Body of the generic 500 sent by the request middleware for unhandled errors."""
    body = ErrorResponse(
        error=ErrorBody(
            code=ErrorCode.INTERNAL_ERROR,
            message="The server failed to process the request.",
            request_id=request_id,
        )
    )
    return json.dumps(body.model_dump(mode="json")).encode()


def install_error_handlers(app: FastAPI) -> None:
    """Render framework errors in the ADIS error envelope."""

    async def handle_api_error(request: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, ApiError)  # noqa: S101 - registered for ApiError only
        return error_response(
            error.status_code,
            error.code,
            error.message,
            details=error.details,
            headers=error.headers,
        )

    async def handle_http_error(request: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, StarletteHTTPException)  # noqa: S101 - registered type
        code = {
            HTTPStatus.NOT_FOUND: ErrorCode.NOT_FOUND,
            HTTPStatus.METHOD_NOT_ALLOWED: ErrorCode.METHOD_NOT_ALLOWED,
        }.get(HTTPStatus(error.status_code), ErrorCode.HTTP_ERROR)
        return error_response(
            error.status_code,
            code,
            HTTPStatus(error.status_code).phrase,
            headers=dict(error.headers or {}),
        )

    async def handle_request_validation(request: Request, error: Exception) -> JSONResponse:
        assert isinstance(error, RequestValidationError)  # noqa: S101 - registered type
        issues = [
            f"{'.'.join(str(part) for part in details['loc'])}: {details['msg']}"
            for details in error.errors()
        ]
        return error_response(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            ErrorCode.VALIDATION_FAILED,
            "The request is invalid.",
            details=[EventError(code=ErrorCode.VALIDATION_FAILED, issues=issues)],
        )

    app.add_exception_handler(ApiError, handle_api_error)
    app.add_exception_handler(StarletteHTTPException, handle_http_error)
    app.add_exception_handler(RequestValidationError, handle_request_validation)
