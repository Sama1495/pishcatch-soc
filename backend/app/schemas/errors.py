"""Uniform error envelope returned by every failed request."""

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict | list | str | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody = Field(description="Controlled error. No stack traces or message content.")
