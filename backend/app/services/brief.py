"""Build the Incident Brief from evidence already in hand. No model is required."""

from app.schemas.brief import Assessment, IncidentBrief, SourceConsulted
from app.schemas.evidence import Evidence
from app.schemas.indicator import Indicator
from app.services.risk import Classification


def recommended_actions(label: str) -> list[str]:
    if label == "likely_malicious":
        return [
            "Do not click links or open attachments.",
            "Simulate quarantine and tell the reporting user. No mailbox is changed by this action.",
            "Ask an analyst to approve any real block of the listed domains or URLs.",
            "Search the local queue for the same sender domain or URL host.",
        ]
    if label == "suspicious":
        return [
            "An analyst should review the case before any response action.",
            "Compare the From domain, Reply-To, and visible links with the claimed organization.",
            "Treat a disabled reputation lookup as missing data, not as a clean result.",
        ]
    if label == "likely_benign":
        return [
            "No immediate containment is recommended from these rules.",
            "The analyst may close the case when the message matches expected mail.",
            "Do not treat this label as a guarantee that the message is safe.",
        ]
    return [
        "Do not treat this message as safe.",
        "Review the sender and the business context manually, or collect more signals.",
        "A disabled reputation provider was not consulted. That is not a clean verdict.",
    ]


def build_brief(
    *,
    sender: str | None,
    subject: str | None,
    classification: Classification,
    indicators: list[Indicator],
    evidence: list[Evidence],
    enrichment_status: str,
    provider_statuses: dict[str, str],
    explainer_status: str,
    body_truncated: bool,
    parser_warnings: list[str],
) -> IncidentBrief:
    top = [item.title for item in evidence if item.polarity == "suspicious"][:3]
    subject_text = (subject or "(no subject)").replace("\n", " ")[:120]
    sender_text = sender or "an unknown sender"
    if top:
        signal_text = " Top signals: " + "; ".join(top) + "."
    elif classification.label == "likely_benign":
        signal_text = " No suspicious rule fired. Aligning signals were recorded with an explicit caveat."
    else:
        signal_text = " No suspicious rule fired. The message is not declared safe."
    summary = (
        f"PhishCatch classified mail from {sender_text} with subject \"{subject_text}\" "
        f"as {classification.label} (score {classification.score})."
        f"{signal_text}"
    )
    limitations = [
        "Deterministic rules do not cover every phishing technique and can be wrong.",
        "Extracted URLs were not opened, expanded, or fetched.",
        "Attachments were not executed, detonated, or scanned with an antivirus.",
        "A missing reputation result is not evidence that an indicator is safe.",
        "The AI explainer does not assign or override the risk label.",
        classification.caveat,
    ]
    if enrichment_status == "disabled":
        limitations.append("VirusTotal and URLhaus were disabled. No reputation query was sent.")
    elif enrichment_status in {"unavailable", "timeout", "error", "unconfigured"}:
        limitations.append(
            f"Reputation enrichment ended as {enrichment_status}. The deterministic result still stands."
        )
    if explainer_status == "disabled":
        limitations.append("The AI explainer was disabled. This brief is a template over the evidence.")
    elif explainer_status != "validated":
        limitations.append(
            "The AI explainer did not return a schema-valid result. Any model text was discarded."
        )
    if body_truncated:
        limitations.append("The stored body text was truncated to the configured maximum.")
    for warning in parser_warnings:
        limitations.append(warning)

    sources = [
        SourceConsulted(
            name="local_eml_parser",
            status="used",
            detail="Headers, body text, URL strings, and attachment metadata. No URL was fetched.",
        ),
        SourceConsulted(
            name="deterministic_rules",
            status="used",
            detail="Ruleset 1.0.0 produced the risk label.",
        ),
        SourceConsulted(
            name="local_indicator_correlation",
            status="used",
            detail="Indicators were compared with incidents already stored locally.",
        ),
        SourceConsulted(
            name="virustotal",
            status=provider_statuses.get("virustotal", enrichment_status),
            detail=_provider_detail(provider_statuses.get("virustotal", enrichment_status)),
        ),
        SourceConsulted(
            name="urlhaus",
            status=provider_statuses.get("urlhaus", enrichment_status),
            detail=_provider_detail(provider_statuses.get("urlhaus", enrichment_status)),
        ),
        SourceConsulted(
            name="ai_explainer",
            status=explainer_status,
            detail="Optional note only. The risk label comes from the rules engine.",
        ),
    ]
    return IncidentBrief(
        summary=summary,
        indicators=indicators,
        evidence=evidence,
        assessment=Assessment(
            risk_label=classification.label,  # type: ignore[arg-type]
            risk_score=classification.score,
            origin="deterministic_rules",
            rationale=classification.rationale,
            caveat=classification.caveat,
        ),
        recommended_actions=recommended_actions(classification.label),
        sources_consulted=sources,
        limitations=limitations,
    )


def _provider_detail(status: str) -> str:
    if status == "disabled":
        return "Disabled by default. No query was sent. A skip is not a clean result."
    if status == "blocked":
        return "The host is not eligible for an outbound lookup (private, link-local, or metadata)."
    if status in {"unavailable", "unconfigured"}:
        return "The adapter is a stub. No live query was sent."
    if status == "timeout":
        return "The lookup exceeded its timeout and was ignored."
    if status == "error":
        return "The lookup failed and was ignored."
    return "Lookup status recorded with the case."
