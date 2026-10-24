import time

from app.integrations.explainer import AiExplainer
from app.integrations.reputation import ReputationAdapter, ReputationHit
from app.integrations.ssrf import is_disallowed_lookup_target
from app.integrations.timeouts import call_with_timeout
from app.services.indicators import IndicatorDraft


class BoomProvider:
    name = "virustotal"

    def lookup(self, indicator: str) -> ReputationHit:
        raise AssertionError(f"lookup should not run for {indicator}")


def test_disabled_reputation_does_not_call_providers():
    adapter = ReputationAdapter(
        enabled=False,
        timeout_seconds=1,
        providers=[BoomProvider()],
    )
    batch = adapter.lookup(
        [IndicatorDraft(type="url", value="http://evil.example/a", display_value="hxxp://evil[.]example/a")]
    )
    assert batch.status == "disabled"
    assert batch.results[0].status == "disabled"
    assert "not evidence" in batch.results[0].detail


def test_enabled_stub_blocks_metadata_and_does_not_require_network():
    class RecordingProvider:
        name = "urlhaus"

        def __init__(self):
            self.seen = []

        def lookup(self, indicator: str) -> ReputationHit:
            self.seen.append(indicator)
            if is_disallowed_lookup_target(indicator):
                return ReputationHit(
                    provider=self.name,
                    indicator=indicator,
                    status="blocked",
                    detail="blocked",
                )
            return ReputationHit(
                provider=self.name,
                indicator=indicator,
                status="unavailable",
                detail="stub",
            )

    provider = RecordingProvider()
    adapter = ReputationAdapter(enabled=True, timeout_seconds=1, providers=[provider])
    batch = adapter.lookup(
        [
            IndicatorDraft("url", "http://169.254.169.254/latest", "hxxp://169[.]254[.]169[.]254/latest"),
            IndicatorDraft("domain", "example.com", "example[.]com"),
        ]
    )
    assert "http://169.254.169.254/latest" in provider.seen
    assert any(hit.status == "blocked" for hit in batch.results)
    assert batch.status == "blocked"


def test_provider_timeout_is_a_fallback_status():
    class SlowProvider:
        name = "virustotal"

        def lookup(self, indicator: str) -> ReputationHit:
            time.sleep(0.4)
            return ReputationHit(provider=self.name, indicator=indicator, status="ok", detail="late")

    adapter = ReputationAdapter(enabled=True, timeout_seconds=0.05, providers=[SlowProvider()])
    batch = adapter.lookup([IndicatorDraft("domain", "example.com", "example[.]com")])
    assert batch.status == "timeout"
    assert batch.results[0].status == "timeout"


def test_call_with_timeout():
    def slow():
        time.sleep(0.4)
        return "done"

    try:
        call_with_timeout(slow, 0.05)
        raised = False
    except TimeoutError:
        raised = True
    assert raised


def test_ssrf_guard_covers_private_and_metadata_hosts():
    assert is_disallowed_lookup_target("http://169.254.169.254/latest/meta-data")
    assert is_disallowed_lookup_target("http://127.0.0.1/")
    assert is_disallowed_lookup_target("http://10.1.2.3/admin")
    assert is_disallowed_lookup_target("http://192.168.0.5/")
    assert is_disallowed_lookup_target("localhost")
    assert not is_disallowed_lookup_target("http://8.8.8.8/dns")
    assert not is_disallowed_lookup_target("example.com")


def test_explainer_disabled_and_validation():
    disabled = AiExplainer(enabled=False, timeout_seconds=1)
    assert disabled.explain(["spf_fail"], ["SPF failed"], "suspicious").status == "disabled"

    def invented(_payload):
        return {
            "summary": "Invented a domain that was not provided.",
            "uncertainty": "none",
            "based_on_rule_ids": ["made_up_rule"],
        }

    invalid = AiExplainer(enabled=True, timeout_seconds=1, api_key="test-key", runner=invented)
    outcome = invalid.explain(["spf_fail"], ["SPF failed"], "suspicious")
    assert outcome.status == "fallback"
    assert outcome.summary is None

    def extra_field(_payload):
        return {
            "summary": "ok",
            "uncertainty": "ok",
            "based_on_rule_ids": ["spf_fail"],
            "risk_label": "likely_malicious",
        }

    rejected = AiExplainer(enabled=True, timeout_seconds=1, api_key="test-key", runner=extra_field)
    assert rejected.explain(["spf_fail"], ["SPF failed"], "suspicious").status == "fallback"

    accepted = AiExplainer(enabled=True, timeout_seconds=1, api_key="test-key")
    ok = accepted.explain(["spf_fail"], ["SPF failed"], "suspicious")
    assert ok.status == "validated"
    assert ok.summary is not None
    assert "spf_fail" in ok.summary
    assert "body" not in ok.summary.lower()
