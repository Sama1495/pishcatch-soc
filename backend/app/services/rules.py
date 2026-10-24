"""Deterministic, explainable phishing rules.

Each suspicious hit carries a stable id, a human reason, and the fields it
looked at. The risk label is computed separately from these hits. A message
with no hits is not a pass; the classifier treats that as inconclusive.

Ruleset version: 1.1.0
"""

from dataclasses import dataclass
import re
import unicodedata

from app.services.parsed import ParsedEmail

RULESET_VERSION = "1.1.0"
PRODUCER = "phishcatch-rules"

# Edit distance and brand-affix checks compare registrable-looking labels to
# these names. Official hosts are excluded before the comparison.
BRAND_LABELS: dict[str, str] = {
    "paypal": "PayPal",
    "microsoft": "Microsoft",
    "office365": "Microsoft 365",
    "microsoftonline": "Microsoft",
    "outlook": "Outlook",
    "google": "Google",
    "gmail": "Gmail",
    "apple": "Apple",
    "icloud": "Apple",
    "amazon": "Amazon",
    "docusign": "DocuSign",
    "dropbox": "Dropbox",
    "linkedin": "LinkedIn",
    "credly": "Credly",
    "youracclaim": "Credly",
    "coursera": "Coursera",
    "aws": "AWS",
    "isc2": "ISC2",
    "comptia": "CompTIA",
}

OFFICIAL_DOMAINS = {
    "paypal.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "outlook.com",
    "live.com",
    "microsoftonline.com",
    "google.com",
    "gmail.com",
    "googlemail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "docusign.com",
    "docusign.net",
    "dropbox.com",
    "linkedin.com",
    "credly.com",
    "youracclaim.com",
    "coursera.org",
    "aws.amazon.com",
    "amazonaws.com",
    "isc2.org",
    "comptia.org",
}

# Domains that may legitimately talk about a badge or certification they issued.
ISSUER_DOMAINS = {
    "linkedin.com",
    "credly.com",
    "youracclaim.com",
    "coursera.org",
    "amazon.com",
    "aws.amazon.com",
    "amazonaws.com",
    "isc2.org",
    "comptia.org",
}

FREEMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    # Reserved name used by the synthetic certification lure.
    "freemail.example",
}

DISPLAY_BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {
        "microsoft.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "microsoftonline.com",
    },
    "office365": {"office365.com", "office.com", "microsoft.com", "microsoftonline.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "gmail": {"gmail.com", "google.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com"},
    "linkedin": {"linkedin.com"},
    "credly": {"credly.com"},
    "youracclaim": {"youracclaim.com", "credly.com"},
    "coursera": {"coursera.org"},
    "aws": {"aws.amazon.com", "amazonaws.com", "amazon.com"},
    "isc2": {"isc2.org"},
    "comptia": {"comptia.org"},
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "buff.ly",
    "rb.gy",
    "shorturl.at",
    "goo.gl",
    "bit.do",
    "t.ly",
    "lnkd.in",
    "aka.ms",
}

RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".iso",
    ".img",
    ".lnk",
    ".msi",
    ".jar",
    ".html",
    ".htm",
    ".svg",
    ".wsf",
    ".cpl",
    ".msc",
    ".reg",
    ".dll",
    ".com",
    ".pif",
    ".application",
    ".aspx",
    ".php",
}

# Phrases, not single common words. Stored without accents; matching is folded.
LURE_PHRASES = (
    "verify your account",
    "verify your password",
    "password expires",
    "password expired",
    "reset your password",
    "urgent action",
    "action required",
    "account will be suspended",
    "account has been suspended",
    "unusual sign-in",
    "unusual activity",
    "update your payment",
    "confirm your identity",
    "wire transfer",
    "gift card",
    "mailbox is full",
    "click here to log in",
    "click here to login",
    "failure to comply",
    "act now",
    "limited time",
    "verifique su cuenta",
    "verifique su contrasena",
    "su contrasena expira",
    "restablezca su contrasena",
    "accion urgente",
    "se requiere accion",
    "su cuenta sera suspendida",
    "su cuenta ha sido suspendida",
    "actividad inusual",
    "actualice su pago",
    "confirme su identidad",
    "transferencia bancaria",
    "su buzon esta lleno",
)

_SKIP_LABELS = {
    "www",
    "mail",
    "smtp",
    "mx",
    "ns",
    "ns1",
    "autodiscover",
    "intranet",
    "localhost",
    "invalid",
    "test",
    "example",
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "info",
    "io",
    "co",
    "uk",
    "br",
    "es",
}
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
    }
)
_EMAIL_RE = re.compile(r"(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})")


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    title: str
    description: str
    severity: str
    weight: int
    polarity: str
    observed_fields: tuple[str, ...]


@dataclass
class RuleHit:
    rule_id: str
    title: str
    description: str
    reason: str
    severity: str
    weight: int
    polarity: str
    indicator_value: str | None
    observed_fields: list[str]


CATALOG: dict[str, RuleSpec] = {
    spec.rule_id: spec
    for spec in (
        RuleSpec(
            "display_name_domain_mismatch",
            "Display name does not match the From domain",
            "The visible display name contains another mailbox or a protected brand, "
            "and that identity is not the domain in the From address.",
            "high",
            25,
            "suspicious",
            ("from",),
        ),
        RuleSpec(
            "reply_to_mismatch",
            "Reply-To domain differs from From",
            "A reply would go to a different organization than the one shown in From.",
            "medium",
            15,
            "suspicious",
            ("from", "reply-to"),
        ),
        RuleSpec(
            "return_path_mismatch",
            "Return-Path domain differs from From",
            "The envelope return path is a different domain than the From address.",
            "medium",
            10,
            "suspicious",
            ("from", "return-path"),
        ),
        RuleSpec(
            "spf_fail",
            "SPF failed",
            "Authentication-Results or Received-SPF reports spf=fail or spf=permerror.",
            "high",
            20,
            "suspicious",
            ("authentication-results", "received-spf"),
        ),
        RuleSpec(
            "spf_softfail",
            "SPF softfail",
            "SPF softfail means the domain does not strongly authorize the sending host.",
            "medium",
            10,
            "suspicious",
            ("authentication-results", "received-spf"),
        ),
        RuleSpec(
            "dkim_fail",
            "DKIM failed",
            "Authentication-Results reports dkim=fail or dkim=permerror.",
            "high",
            20,
            "suspicious",
            ("authentication-results",),
        ),
        RuleSpec(
            "dmarc_fail",
            "DMARC failed",
            "Authentication-Results reports dmarc=fail or dmarc=permerror.",
            "high",
            25,
            "suspicious",
            ("authentication-results",),
        ),
        RuleSpec(
            "lookalike_domain",
            "Lookalike domain",
            "A From domain or URL host resembles a protected brand but is not that brand's domain. "
            "Comparison uses confusable characters, a small edit distance, and hyphenated affixes.",
            "high",
            30,
            "suspicious",
            ("from", "url"),
        ),
        RuleSpec(
            "url_text_href_mismatch",
            "Visible link text does not match the href",
            "The anchor text looks like a URL whose host is a different organization than the href.",
            "high",
            35,
            "suspicious",
            ("html_anchor",),
        ),
        RuleSpec(
            "ip_literal_url",
            "URL host is an IP address",
            "The URL uses a numeric host instead of a domain name. The URL was not opened.",
            "high",
            30,
            "suspicious",
            ("url",),
        ),
        RuleSpec(
            "url_shortener",
            "URL shortener",
            "The URL host is a known shortener, which hides the destination. The URL was not expanded.",
            "medium",
            15,
            "suspicious",
            ("url",),
        ),
        RuleSpec(
            "urgency_credential_lure",
            "Urgency or credential lure",
            "The subject or body matches a documented English or Spanish lure phrase. "
            "Single common words are not enough.",
            "medium",
            20,
            "suspicious",
            ("subject", "body"),
        ),
        RuleSpec(
            "risky_attachment_extension",
            "Risky attachment extension",
            "An attachment name ends with an executable, script, disk-image, or HTML extension, "
            "or hides one behind another suffix. The file was not opened or executed.",
            "high",
            35,
            "suspicious",
            ("attachment",),
        ),
        RuleSpec(
            "punycode_domain",
            "Punycode domain",
            "A host contains xn--, which can hide a homoglyph domain.",
            "medium",
            20,
            "suspicious",
            ("url", "from"),
        ),
        RuleSpec(
            "dangerous_url_scheme",
            "Dangerous URL scheme",
            "A URL uses javascript, data, vbscript, or file. It was not executed.",
            "high",
            40,
            "suspicious",
            ("url",),
        ),
        RuleSpec(
            "url_embedded_credentials",
            "URL contains embedded userinfo",
            "A URL contained userinfo. The userinfo was stripped and was not stored.",
            "high",
            25,
            "suspicious",
            ("url",),
        ),
        RuleSpec(
            "spf_pass",
            "SPF passed",
            "SPF passed for this message. A pass supports alignment; it does not prove safety.",
            "info",
            0,
            "benign_support",
            ("authentication-results",),
        ),
        RuleSpec(
            "dkim_pass",
            "DKIM passed",
            "DKIM passed for this message. A pass supports alignment; it does not prove safety.",
            "info",
            0,
            "benign_support",
            ("authentication-results",),
        ),
        RuleSpec(
            "dmarc_pass",
            "DMARC passed",
            "DMARC passed for this message. A pass supports alignment; it does not prove safety.",
            "info",
            0,
            "benign_support",
            ("authentication-results",),
        ),
        RuleSpec(
            "reply_to_aligned",
            "Reply-To aligns with From",
            "Every Reply-To domain belongs to the same organization as From.",
            "info",
            0,
            "benign_support",
            ("from", "reply-to"),
        ),
        RuleSpec(
            "no_suspicious_signals",
            "No suspicious signals",
            "The ruleset found no suspicious signal. That absence is not a declaration of safety.",
            "info",
            0,
            "info",
            (),
        ),
        RuleSpec(
            "related_indicator_in_prior_case",
            "Indicator seen in a prior suspicious case",
            "A URL, domain, IP, or mailbox also appears on a stored incident that was "
            "suspicious or likely malicious.",
            "medium",
            10,
            "suspicious",
            ("indicator",),
        ),
        RuleSpec(
            "related_indicator_seen_before",
            "Indicator seen in a prior case",
            "A URL, domain, IP, or mailbox also appears on a stored incident that was not "
            "classified as suspicious. This is context, not a new suspicious signal.",
            "info",
            0,
            "info",
            ("indicator",),
        ),
    )
}


def evaluate(parsed: ParsedEmail) -> list[RuleHit]:
    """Run every structural rule. Correlation is applied later by the orchestrator."""
    hits: list[RuleHit] = []
    hits.extend(_display_name(parsed))
    hits.extend(_reply_to(parsed))
    hits.extend(_return_path(parsed))
    hits.extend(_auth(parsed))
    hits.extend(_hosts(parsed))
    hits.extend(_link_mismatches(parsed))
    hits.extend(_schemes_and_userinfo(parsed))
    hits.extend(_lure(parsed))
    hits.extend(_attachments(parsed))
    hits.extend(_pretext(parsed))
    return hits[:64]


def _pretext(parsed: ParsedEmail) -> list[RuleHit]:
    from app.services.pretext import pretext_hits

    return pretext_hits(parsed)


def make_hit(
    rule_id: str,
    reason: str,
    indicator: str | None = None,
    observed: list[str] | None = None,
) -> RuleHit:
    spec = CATALOG[rule_id]
    return RuleHit(
        rule_id=spec.rule_id,
        title=spec.title,
        description=spec.description,
        reason=reason,
        severity=spec.severity,
        weight=spec.weight,
        polarity=spec.polarity,
        indicator_value=indicator,
        observed_fields=list(observed or spec.observed_fields),
    )


def _display_name(parsed: ParsedEmail) -> list[RuleHit]:
    display = parsed.sender_display or ""
    from_domain = parsed.sender_domain
    if not display or not from_domain:
        return []
    reasons: list[str] = []
    embedded = None
    for mailbox in _EMAIL_RE.findall(display):
        domain = mailbox.split("@", 1)[1].lower().rstrip(".")
        if not same_org(domain, from_domain):
            embedded = mailbox.lower()
            reasons.append(
                f"Display name contains {mailbox.lower()}, whose domain does not match "
                f"the From domain {from_domain}."
            )
            break
    folded = display.casefold()
    for brand, domains in DISPLAY_BRAND_DOMAINS.items():
        if not re.search(rf"(?<![a-z0-9]){re.escape(brand)}(?![a-z0-9])", folded):
            continue
        if any(same_org(from_domain, official) for official in domains):
            continue
        reasons.append(
            f"Display name mentions {brand}, but From uses {from_domain}, "
            "which is not an official domain for that brand."
        )
        break
    if not reasons:
        return []
    return [make_hit("display_name_domain_mismatch", " ".join(reasons), embedded or from_domain)]


def _reply_to(parsed: ParsedEmail) -> list[RuleHit]:
    if not parsed.sender_domain or not parsed.reply_to_domains:
        return []
    foreign = [domain for domain in parsed.reply_to_domains if not same_org(domain, parsed.sender_domain)]
    if foreign:
        if parsed.mailing_list:
            return []
        return [
            make_hit(
                "reply_to_mismatch",
                f"Reply-To domain {foreign[0]} does not match From domain {parsed.sender_domain}.",
                foreign[0],
            )
        ]
    return [
        make_hit(
            "reply_to_aligned",
            f"Reply-To stays inside {parsed.sender_domain}.",
            parsed.sender_domain,
        )
    ]


def _return_path(parsed: ParsedEmail) -> list[RuleHit]:
    if not parsed.sender_domain or not parsed.return_path_domain:
        return []
    if same_org(parsed.return_path_domain, parsed.sender_domain):
        return []
    if parsed.mailing_list:
        return []
    return [
        make_hit(
            "return_path_mismatch",
            f"Return-Path domain {parsed.return_path_domain} does not match "
            f"From domain {parsed.sender_domain}.",
            parsed.return_path_domain,
        )
    ]


def _auth(parsed: ParsedEmail) -> list[RuleHit]:
    hits: list[RuleHit] = []
    mapping = (
        ("spf", parsed.spf, "spf_fail", "spf_softfail", "spf_pass"),
        ("dkim", parsed.dkim, "dkim_fail", None, "dkim_pass"),
        ("dmarc", parsed.dmarc, "dmarc_fail", None, "dmarc_pass"),
    )
    for name, result, fail_id, soft_id, pass_id in mapping:
        if result in {"fail", "permerror"}:
            hits.append(
                make_hit(
                    fail_id,
                    f"{name.upper()} result is {result}.",
                    f"{name}:{result}",
                )
            )
        elif result == "softfail" and soft_id:
            hits.append(make_hit(soft_id, f"{name.upper()} result is softfail.", f"{name}:softfail"))
        elif result == "pass":
            hits.append(
                make_hit(
                    pass_id,
                    f"{name.upper()} result is pass. This is alignment, not a safety proof.",
                    f"{name}:pass",
                )
            )
    return hits


def _hosts(parsed: ParsedEmail) -> list[RuleHit]:
    hits: list[RuleHit] = []
    hosts: list[tuple[str, str]] = []
    if parsed.sender_domain:
        hosts.append((parsed.sender_domain, "from"))
    for url in parsed.urls:
        if url.host:
            hosts.append((url.host, url.source))
    lookalikes: list[str] = []
    punycode: list[str] = []
    shorteners: list[str] = []
    ip_hosts: list[str] = []
    seen_look: set[str] = set()
    seen_puny: set[str] = set()
    seen_short: set[str] = set()
    seen_ip: set[str] = set()
    for host, _source in hosts:
        if _is_ip(host):
            if host not in seen_ip:
                seen_ip.add(host)
                ip_hosts.append(host)
            continue
        if "xn--" in host and host not in seen_puny:
            seen_puny.add(host)
            punycode.append(host)
        if _is_shortener(host) and host not in seen_short:
            seen_short.add(host)
            shorteners.append(host)
        brand = lookalike_brand(host)
        if brand and host not in seen_look:
            seen_look.add(host)
            lookalikes.append(f"{host} resembles {brand}")
    if lookalikes:
        hits.append(
            make_hit(
                "lookalike_domain",
                "Lookalike host: " + "; ".join(lookalikes[:5]) + ".",
                lookalikes[0].split(" ", 1)[0],
            )
        )
    if punycode:
        hits.append(
            make_hit(
                "punycode_domain",
                "Punycode host present: " + ", ".join(punycode[:5]) + ".",
                punycode[0],
            )
        )
    if shorteners:
        hits.append(
            make_hit(
                "url_shortener",
                "Shortener host present: " + ", ".join(shorteners[:5]) + ". The URL was not expanded.",
                shorteners[0],
            )
        )
    if ip_hosts:
        hits.append(
            make_hit(
                "ip_literal_url",
                "URL host is an IP address: " + ", ".join(ip_hosts[:5]) + ". The URL was not opened.",
                ip_hosts[0],
            )
        )
    return hits


def _link_mismatches(parsed: ParsedEmail) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for link in parsed.links:
        if link.href is None or link.text_url is None:
            continue
        if not link.href.host or not link.text_url.host:
            continue
        if same_org(link.href.host, link.text_url.host):
            continue
        hits.append(
            make_hit(
                "url_text_href_mismatch",
                f"Anchor text host {link.text_url.host} does not match href host {link.href.host}.",
                link.href.defanged,
            )
        )
        if len(hits) >= 5:
            break
    return hits


def _schemes_and_userinfo(parsed: ParsedEmail) -> list[RuleHit]:
    hits: list[RuleHit] = []
    dangerous = [url for url in parsed.urls if url.scheme in {"javascript", "data", "vbscript", "file"}]
    if dangerous:
        hits.append(
            make_hit(
                "dangerous_url_scheme",
                f"URL scheme {dangerous[0].scheme} is not fetched or executed.",
                dangerous[0].scheme,
            )
        )
    if any(url.had_userinfo for url in parsed.urls):
        hits.append(
            make_hit(
                "url_embedded_credentials",
                "A URL contained embedded userinfo. The userinfo was removed and was not stored.",
            )
        )
    return hits


def _lure(parsed: ParsedEmail) -> list[RuleHit]:
    haystack = _fold(f"{parsed.subject or ''}\n{parsed.body_text}")
    found: list[str] = []
    for phrase in LURE_PHRASES:
        if re.search(rf"(?<!\w){re.escape(phrase)}(?!\w)", haystack):
            found.append(phrase)
    if not found:
        return []
    shown = ", ".join(found[:8])
    return [
        make_hit(
            "urgency_credential_lure",
            f"Matched lure phrase(s): {shown}.",
            found[0],
        )
    ]


def _attachments(parsed: ParsedEmail) -> list[RuleHit]:
    risky: list[str] = []
    for attachment in parsed.attachments:
        if not attachment.filename:
            continue
        suffixes = [suffix.lower() for suffix in _suffixes(attachment.filename)]
        if not suffixes:
            continue
        if suffixes[-1] in RISKY_EXTENSIONS or any(suffix in RISKY_EXTENSIONS for suffix in suffixes):
            risky.append(attachment.filename)
    if not risky:
        return []
    return [
        make_hit(
            "risky_attachment_extension",
            "Risky attachment name(s): "
            + ", ".join(risky[:5])
            + ". The attachment was not executed.",
            risky[0],
        )
    ]


def same_org(left: str, right: str) -> bool:
    a = left.lower().rstrip(".")
    b = right.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def is_official_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in OFFICIAL_DOMAINS)


def lookalike_brand(host: str) -> str | None:
    host = host.lower().rstrip(".")
    if not host or is_official_host(host) or _is_ip(host):
        return None
    for label in host.split("."):
        if label in _SKIP_LABELS or len(label) < 4:
            continue
        for token in re.split(r"[-_]", label):
            if len(token) < 4:
                continue
            normalized = token.translate(_CONFUSABLES)
            for brand_label, brand_name in BRAND_LABELS.items():
                if _brand_affix(normalized, brand_label) or _close(normalized, brand_label):
                    return brand_name
    return None


def _brand_affix(token: str, brand: str) -> bool:
    if token == brand:
        return True
    if token.startswith(brand) and len(token) - len(brand) >= 3:
        return True
    if token.endswith(brand) and len(token) - len(brand) >= 3:
        return True
    return False


def _close(token: str, brand: str) -> bool:
    if token == brand:
        return False
    distance = _levenshtein(token, brand)
    if len(brand) >= 7 and distance <= 2:
        return True
    return len(brand) >= 5 and distance <= 1


def _is_shortener(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == name or host.endswith("." + name) for name in SHORTENERS)


def _is_ip(host: str) -> bool:
    try:
        import ipaddress

        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _fold(text: str) -> str:
    folded = unicodedata.normalize("NFKD", text)
    stripped = "".join(char for char in folded if not unicodedata.combining(char))
    return stripped.casefold()


def _suffixes(filename: str) -> list[str]:
    from pathlib import Path

    return Path(filename.lower()).suffixes


def _install_pretext_catalog() -> None:
    from app.services.pretext import PRETEXT_SPECS

    for spec in PRETEXT_SPECS:
        CATALOG[spec.rule_id] = spec


_install_pretext_catalog()


def _levenshtein(left: str, right: str) -> int:
    if abs(len(left) - len(right)) > 2:
        return 3
    previous = list(range(len(right) + 1))
    for i, ca in enumerate(left, start=1):
        current = [i]
        for j, cb in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (ca != cb)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]
