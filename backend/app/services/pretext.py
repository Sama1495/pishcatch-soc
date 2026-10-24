"""Pretext and lightweight OSINT checks. They add rule hits; they do not label.

Phrases are stored without accents. Matching uses the folded body and subject.
A denial such as "we never charge" suppresses payment and credential hits.
"""

import re
from datetime import datetime, timedelta, timezone

from app.services.parsed import ParsedEmail
from app.services.rules import RuleSpec

PRETEXT_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec(
        "code_execution_request",
        "Request to run code or enable active content",
        "The message asks the reader to enable macros or run a downloaded file.",
        "high",
        35,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "credential_or_sso_request",
        "Request for a password or corporate sign-in",
        "The message asks the reader to sign in with a corporate or SSO account.",
        "high",
        25,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "payment_for_credential_or_job",
        "Payment requested for a credential or job step",
        "The message asks for a fee, transfer, or gift card. A denial of payment does not match.",
        "high",
        25,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "certification_badge_lure",
        "Certification or badge claim from a non-issuer",
        "The message talks about a badge or certification, and From is not an issuer domain.",
        "high",
        20,
        "suspicious",
        ("body", "from"),
    ),
    RuleSpec(
        "recruiter_job_lure",
        "Unsolicited job or recruiter lure",
        "The message uses hiring language that is common in recruitment lures.",
        "medium",
        20,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "brand_in_body_unaligned",
        "Protected brand in the body does not match From",
        "A protected brand is named beside a call to act, and From is not that brand's domain.",
        "high",
        20,
        "suspicious",
        ("body", "from"),
    ),
    RuleSpec(
        "freemail_corporate_claim",
        "Freemail mailbox claims a corporate process",
        "A freemail From or Reply-To is paired with a corporate sign-in or department claim.",
        "high",
        20,
        "suspicious",
        ("from", "reply-to", "body"),
    ),
    RuleSpec(
        "osint_personalization",
        "Message cites a public profile or post",
        "The message says it saw a LinkedIn post or profile. That is personalization, not proof.",
        "medium",
        15,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "off_platform_move",
        "Asks to continue off the original platform",
        "The message pushes the conversation to chat, phone, or another channel.",
        "medium",
        15,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "deadline_pressure",
        "Short deadline attached to the request",
        "The message gives a short clock, such as 24 hours, for the requested action.",
        "low",
        10,
        "suspicious",
        ("body",),
    ),
    RuleSpec(
        "newly_registered_domain",
        "From domain was registered recently",
        "An opt-in RDAP lookup reported a registration date inside the last 30 days.",
        "high",
        20,
        "suspicious",
        ("from",),
    ),
)

_DENIALS = (
    "nunca te pedira",
    "nunca te pediremos",
    "no te pediremos",
    "nunca pedira pagos",
    "we never charge",
    "will never ask you for",
    "never ask for your password",
    "never ask you for your password",
)
_CREDENTIALS = (
    "iniciando sesion",
    "inicia sesion",
    "iniciar sesion",
    "sign in with",
    "cuenta corporativa",
    "corporate login",
    "corporate account",
    "single sign-on",
    "single sign on",
)
_PAYMENTS = (
    "pagando",
    "paga la",
    "pague",
    "tarifa de",
    "tarifa unica",
    "verification fee",
    "pay the",
    "wire transfer",
    "gift card",
    "usd ",
)
_CERTS = ("insignia", "badge", "certificacion", "certification", "credencial")
_RECRUITER = (
    "oferta de empleo",
    "oportunidad laboral",
    "we are hiring",
    "posicion abierta",
    "job offer",
    "reclutador",
)
_OSINT = (
    "vimos en linkedin",
    "vimos tu publicacion",
    "tu publicacion en linkedin",
    "we saw on linkedin",
    "we noticed your linkedin",
    "vi en tu perfil",
)
_OFF_PLATFORM = (
    "whatsapp",
    "telegram",
    "fuera de la plataforma",
    "move this conversation",
    "text me at",
    "escribeme por whatsapp",
)
_DEADLINES = (
    "24 horas",
    "within 24 hours",
    "tienes 24",
    "en las proximas 24",
    "ultimas 24",
    "expira hoy",
    "last chance",
)
_CODE = (
    "enable macros",
    "habilite las macros",
    "habilita las macros",
    "download and run",
    "descargue y ejecute",
    "run the attached",
    "ejecute el archivo",
    "enable content",
)
_CORPORATE = (
    "cuenta corporativa",
    "departamento de ti",
    "recursos humanos",
    "payroll",
    "equipo de seguridad",
    "microsoft 365",
)
_ACTION = _CREDENTIALS + _PAYMENTS + _CERTS + (
    "reclama",
    "claim your",
    "verifique",
    "verify your",
)


def pretext_hits(parsed: ParsedEmail) -> list:
    from app.services.rules import (
        BRAND_LABELS,
        DISPLAY_BRAND_DOMAINS,
        FREEMAIL_DOMAINS,
        ISSUER_DOMAINS,
        _fold,
        make_hit,
        same_org,
    )

    text = _fold(f"{parsed.subject or ''}\n{parsed.body_text}")
    hits = []
    denial = _any(text, _DENIALS)
    if _any(text, _CODE):
        hits.append(make_hit("code_execution_request", "The text asks the reader to run content."))
    if not denial and _any(text, _CREDENTIALS):
        hits.append(
            make_hit(
                "credential_or_sso_request",
                "The text asks for a corporate or SSO sign-in.",
            )
        )
    if not denial and _any(text, _PAYMENTS):
        hits.append(
            make_hit(
                "payment_for_credential_or_job",
                "The text asks the reader to pay a fee or send value.",
            )
        )
    sender = parsed.sender_domain or ""
    if _any(text, _CERTS) and not _is_issuer(sender, ISSUER_DOMAINS, same_org):
        hits.append(
            make_hit(
                "certification_badge_lure",
                "A badge or certification is mentioned, and From is not an issuer domain.",
                sender or None,
            )
        )
    if _any(text, _RECRUITER):
        hits.append(make_hit("recruiter_job_lure", "The text uses hiring or recruiter language."))
    brands = _unaligned_brands(text, sender, BRAND_LABELS, DISPLAY_BRAND_DOMAINS, same_org)
    if brands and _any(text, _ACTION):
        shown = ", ".join(brands[:3])
        hits.append(
            make_hit(
                "brand_in_body_unaligned",
                f"Brand mention is not aligned with From: {shown}.",
                shown,
            )
        )
    if _freemail_claim(parsed, text, FREEMAIL_DOMAINS, same_org):
        hits.append(
            make_hit(
                "freemail_corporate_claim",
                "A freemail mailbox is paired with a corporate-process claim.",
            )
        )
    if _any(text, _OSINT):
        hits.append(make_hit("osint_personalization", "The text cites a public profile or post."))
    if _any(text, _OFF_PLATFORM):
        hits.append(make_hit("off_platform_move", "The text asks to continue on another channel."))
    if _any(text, _DEADLINES):
        hits.append(make_hit("deadline_pressure", "The text sets a short deadline for the request."))
    hits.extend(_newly_registered(parsed))
    return hits


def _any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", text) for phrase in phrases)


def _is_issuer(domain: str, issuers: set[str], same_org) -> bool:
    if not domain:
        return False
    return any(same_org(domain, issuer) for issuer in issuers)


def _unaligned_brands(text, sender, brands, display_domains, same_org) -> list[str]:
    found: list[str] = []
    for token, name in brands.items():
        if not re.search(rf"(?<!\w){re.escape(token)}(?!\w)", text):
            continue
        official = display_domains.get(token, set())
        if sender and any(same_org(sender, domain) for domain in official):
            continue
        if name not in found:
            found.append(name)
    return found


def _freemail_claim(parsed: ParsedEmail, text: str, freemail: set[str], same_org) -> bool:
    domains = [parsed.sender_domain or "", *parsed.reply_to_domains]
    if not any(domain and _is_freemail(domain, freemail, same_org) for domain in domains):
        return False
    return _any(text, _CORPORATE)


def _is_freemail(domain: str, freemail: set[str], same_org) -> bool:
    return any(same_org(domain, item) for item in freemail)


def _newly_registered(parsed: ParsedEmail) -> list:
    from app.core.config import get_settings
    from app.integrations.rdap import registration_date
    from app.integrations.ssrf import is_disallowed_lookup_target
    from app.services.rules import make_hit

    settings = get_settings()
    if not settings.rdap_enabled:
        return []
    domain = (parsed.sender_domain or "").lower().rstrip(".")
    if not domain or domain.endswith((".test", ".example", ".invalid", ".localhost", ".local")):
        return []
    if is_disallowed_lookup_target(domain):
        return []
    try:
        created = registration_date(domain, timeout=min(settings.reputation_timeout_seconds, 3.0))
    except Exception:
        return []
    if created is None:
        return []
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - created <= timedelta(days=30):
        return [
            make_hit(
                "newly_registered_domain",
                "RDAP reports the From domain was registered within 30 days.",
                domain,
            )
        ]
    return []
