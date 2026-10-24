"""AI explainer.

The explainer may add a note. It cannot change the risk label, invent rule ids,
or receive the raw message body. Disabled unless a provider is configured.
Any output that fails the schema, or that cites a rule the engine did not
produce, is discarded and the deterministic template is used instead.

Gemini is enabled only when ``AI_EXPLAINER_PROVIDER=gemini`` (or the
``PHISHCATCH_`` form) and ``GEMINI_API_KEY`` is set in the environment.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import Settings, get_settings
from app.integrations.timeouts import call_with_timeout


class ExplainerOutput(BaseModel):
    """Schema every model result must satisfy before it is stored or shown."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=2000)
    uncertainty: str = Field(min_length=1, max_length=2000)
    based_on_rule_ids: list[str]


@dataclass
class ExplainerOutcome:
    status: str
    summary: str | None = None
    uncertainty: str | None = None
    based_on_rule_ids: list[str] | None = None


class AiExplainer:
    def __init__(
        self,
        enabled: bool,
        timeout_seconds: float,
        api_key: str = "",
        model: str = "",
        runner: Callable[[dict], dict] | None = None,
    ) -> None:
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key
        self.model = model
        self.runner = runner
        self.provider = "stub" if enabled and (runner or api_key) else ("unconfigured" if enabled else "off")

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "AiExplainer":
        settings = settings or get_settings()
        provider = (
            os.environ.get("AI_EXPLAINER_PROVIDER")
            or os.environ.get("PHISHCATCH_AI_EXPLAINER_PROVIDER")
            or ""
        ).strip().lower()
        if provider == "gemini":
            from app.integrations.gemini import GeminiExplainer, gemini_api_key, gemini_model

            key = gemini_api_key()
            model = gemini_model()
            if not key:
                instance = cls(
                    enabled=True,
                    timeout_seconds=settings.ai_timeout_seconds,
                    api_key="",
                    model=model,
                    runner=None,
                )
                instance.provider = "unconfigured"
                return instance
            gemini = GeminiExplainer(
                api_key=key,
                model=model,
                timeout_seconds=settings.ai_timeout_seconds,
            )
            instance = cls(
                enabled=True,
                timeout_seconds=settings.ai_timeout_seconds,
                api_key="",
                model=model,
                runner=gemini.complete,
            )
            instance.provider = "gemini"
            return instance
        instance = cls(
            enabled=settings.ai_enabled,
            timeout_seconds=settings.ai_timeout_seconds,
            api_key=settings.ai_api_key,
            model=settings.ai_model,
        )
        return instance

    def explain(
        self,
        rule_ids: list[str],
        titles: list[str],
        risk_label: str,
        indicators: list[dict] | None = None,
    ) -> ExplainerOutcome:
        if not self.enabled:
            return ExplainerOutcome(status="disabled")
        if self.runner is None and not self.api_key:
            return ExplainerOutcome(status="unconfigured")
        payload = {
            "rule_ids": list(rule_ids),
            "titles": list(titles),
            "risk_label": risk_label,
            "indicators": _public_indicators(indicators),
            # The raw body, subject, and mailbox addresses are intentionally
            # absent. Email-derived strings that remain are data, not instructions.
        }
        runner = self.runner or _stub_runner
        try:
            raw = call_with_timeout(runner, self.timeout_seconds, payload)
        except TimeoutError:
            return ExplainerOutcome(status="fallback")
        except Exception:
            return ExplainerOutcome(status="fallback")
        try:
            parsed = ExplainerOutput.model_validate(raw)
        except ValidationError:
            return ExplainerOutcome(status="fallback")
        known = set(rule_ids)
        if not set(parsed.based_on_rule_ids).issubset(known):
            return ExplainerOutcome(status="fallback")
        return ExplainerOutcome(
            status="validated",
            summary=parsed.summary,
            uncertainty=parsed.uncertainty,
            based_on_rule_ids=parsed.based_on_rule_ids,
        )


def _public_indicators(indicators: list[dict] | None) -> list[dict]:
    public: list[dict] = []
    for item in indicators or []:
        kind = str(item.get("type") or "")
        if kind not in {"url", "domain", "ip", "attachment"}:
            continue
        defanged = str(item.get("defanged") or "")[:300]
        if not defanged:
            continue
        public.append({"type": kind, "defanged": defanged})
    return public[:20]


def _stub_runner(payload: dict) -> dict:
    """Local stand-in. It only restates rule ids that were handed to it."""
    rule_ids = payload.get("rule_ids") or []
    if rule_ids:
        summary = "Stub note based only on supplied rule ids: " + ", ".join(rule_ids)
    else:
        summary = "Stub note: no suspicious rule ids were supplied."
    return {
        "summary": summary[:2000],
        "uncertainty": "This note is a stub. It did not assign the risk label.",
        "based_on_rule_ids": list(rule_ids),
    }
