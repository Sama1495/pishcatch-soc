"""Extracted indicators. ``value`` is normalized; ``display_value`` is safe to show."""

from pydantic import BaseModel, Field

from app.schemas.common import IndicatorType


class Indicator(BaseModel):
    id: str
    type: IndicatorType
    value: str = Field(description="Normalized indicator. URLs are never fetched.")
    display_value: str = Field(description="Defanged form for URLs and hosts.")
    context: str | None = None
