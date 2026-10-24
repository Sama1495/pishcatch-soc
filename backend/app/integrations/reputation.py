"""Reputation adapter.

VirusTotal and URLhaus are represented as stubs. With the default configuration
no network call is made. A disabled or failed lookup is not a benign signal,
and it never changes the deterministic score by itself.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from app.core.config import Settings, get_settings
from app.integrations.ssrf import is_disallowed_lookup_target
from app.integrations.timeouts import call_with_timeout
from app.services.indicators import IndicatorDraft


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ReputationHit:
    provider: str
    indicator: str
    status: str
    detail: str
    malicious: bool | None = None
    queried_at: datetime = field(default_factory=_now)


@dataclass
class ReputationBatch:
    status: str
    results: list[ReputationHit]
    provider_statuses: dict[str, str]


class ReputationProvider(Protocol):
    name: str

    def lookup(self, indicator: str) -> ReputationHit:
        """Return a hit. Implementations in this scaffold must not open a socket."""


class VirusTotalProvider:
    """Stub. A configured key still does not send mail or URLs anywhere."""

    name = "virustotal"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def lookup(self, indicator: str) -> ReputationHit:
        if is_disallowed_lookup_target(indicator):
            return ReputationHit(
                provider=self.name,
                indicator=indicator,
                status="blocked",
                detail="Host is not eligible for an outbound lookup. No request was sent.",
            )
        if not self.api_key:
            return ReputationHit(
                provider=self.name,
                indicator=indicator,
                status="unconfigured",
                detail="VIRUSTOTAL key is empty. No request was sent.",
            )
        return ReputationHit(
            provider=self.name,
            indicator=indicator,
            status="unavailable",
            detail="Live VirusTotal queries are not implemented. No request was sent.",
            malicious=None,
        )


class URLhausProvider:
    """Stub. A configured key still does not send indicators anywhere."""

    name = "urlhaus"

    def __init__(self, auth_key: str) -> None:
        self.auth_key = auth_key

    def lookup(self, indicator: str) -> ReputationHit:
        if is_disallowed_lookup_target(indicator):
            return ReputationHit(
                provider=self.name,
                indicator=indicator,
                status="blocked",
                detail="Host is not eligible for an outbound lookup. No request was sent.",
            )
        if not self.auth_key:
            return ReputationHit(
                provider=self.name,
                indicator=indicator,
                status="unconfigured",
                detail="URLhaus key is empty. No request was sent.",
            )
        return ReputationHit(
            provider=self.name,
            indicator=indicator,
            status="unavailable",
            detail="Live URLhaus queries are not implemented. No request was sent.",
            malicious=None,
        )


class ReputationAdapter:
    def __init__(
        self,
        enabled: bool,
        timeout_seconds: float,
        providers: list[ReputationProvider] | None = None,
    ) -> None:
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.providers = providers if providers is not None else []

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> "ReputationAdapter":
        settings = settings or get_settings()
        providers: list[ReputationProvider] = [
            VirusTotalProvider(settings.vt_api_key),
            URLhausProvider(settings.urlhaus_auth_key),
        ]
        return cls(settings.reputation_enabled, settings.reputation_timeout_seconds, providers)

    def lookup(self, indicators: list[IndicatorDraft]) -> ReputationBatch:
        if not self.enabled:
            results = [
                ReputationHit(
                    provider=provider.name,
                    indicator="*",
                    status="disabled",
                    detail=(
                        "Reputation lookups are disabled. No request was sent. "
                        "A skipped lookup is not evidence that an indicator is safe."
                    ),
                )
                for provider in self.providers
            ]
            return ReputationBatch(
                status="disabled",
                results=results,
                provider_statuses={provider.name: "disabled" for provider in self.providers},
            )

        targets = _targets(indicators)
        results: list[ReputationHit] = []
        for provider in self.providers:
            if not targets:
                results.append(
                    ReputationHit(
                        provider=provider.name,
                        indicator="*",
                        status="unavailable",
                        detail="No URL or domain indicator was available to look up.",
                    )
                )
                continue
            for target in targets:
                try:
                    hit = call_with_timeout(provider.lookup, self.timeout_seconds, target)
                except TimeoutError:
                    hit = ReputationHit(
                        provider=provider.name,
                        indicator=target,
                        status="timeout",
                        detail="The reputation lookup exceeded its timeout and was ignored.",
                    )
                except Exception:
                    hit = ReputationHit(
                        provider=provider.name,
                        indicator=target,
                        status="error",
                        detail="The reputation lookup failed and was ignored.",
                    )
                results.append(hit)
        statuses = {provider.name: _status_for(provider.name, results) for provider in self.providers}
        return ReputationBatch(status=_batch_status(results), results=results, provider_statuses=statuses)


def _targets(indicators: list[IndicatorDraft]) -> list[str]:
    values: list[str] = []
    for indicator in indicators:
        if indicator.type not in {"url", "domain"}:
            continue
        if indicator.value not in values:
            values.append(indicator.value)
        if len(values) >= 5:
            break
    return values


def _status_for(provider: str, results: list[ReputationHit]) -> str:
    own = [hit.status for hit in results if hit.provider == provider]
    return _batch_status_from(own)


def _batch_status(results: list[ReputationHit]) -> str:
    return _batch_status_from([hit.status for hit in results])


def _batch_status_from(statuses: list[str]) -> str:
    if not statuses:
        return "unavailable"
    if any(status == "timeout" for status in statuses):
        return "timeout"
    if any(status == "error" for status in statuses):
        return "error"
    if any(status == "blocked" for status in statuses):
        return "blocked"
    if any(status == "disabled" for status in statuses):
        return "disabled"
    if any(status == "unconfigured" for status in statuses):
        return "unconfigured"
    return "unavailable"
