"""
app/api/errors.py

Structured error response model for all API error responses.
Ensures no traceback, SQL errors, or credentials are exposed to clients.
"""

from __future__ import annotations

from pydantic import BaseModel


class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorDetail

    @classmethod
    def make(
        cls,
        code: str,
        message: str,
        request_id: str | None = None,
    ) -> "ErrorResponse":
        return cls(error=ErrorDetail(code=code, message=message, request_id=request_id))
