"""Optional RDAP age lookup for a domain name. Never called for a URL from mail."""

from datetime import datetime

import httpx

from app.integrations.ssrf import is_disallowed_lookup_target

_LOOKUP = None


def registration_date(domain: str, timeout: float) -> datetime | None:
    """Return the registration timestamp, or None when RDAP has no usable date.

    Tests replace ``set_lookup`` so the suite does not open a socket.
    """
    if _LOOKUP is not None:
        return _LOOKUP(domain, timeout)
    if is_disallowed_lookup_target(domain):
        return None
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    for event in payload.get("events") or []:
        if not isinstance(event, dict):
            continue
        if str(event.get("eventAction") or "").lower() != "registration":
            continue
        raw = str(event.get("eventDate") or "")
        if not raw:
            continue
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def set_lookup(func) -> None:
    global _LOOKUP
    _LOOKUP = func
