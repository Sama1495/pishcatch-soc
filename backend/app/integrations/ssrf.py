"""Hosts that must never be contacted if a live reputation client is added later.

The current build does not open connections to extracted URLs. This guard is
here so a future client has one place that blocks loopback, private, link-local,
and cloud metadata addresses.
"""

import ipaddress
from urllib.parse import urlsplit

_BLOCKED_NAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata",
}
_BLOCKED_SUFFIXES = (".local", ".internal", ".localhost")
_METADATA_HOSTS = {"169.254.169.254", "fd00:ec2::254"}


def is_disallowed_lookup_target(value: str) -> bool:
    """True when an outbound lookup of ``value`` would be unsafe."""
    host = _host_of(value)
    if not host:
        return True
    lowered = host.lower().rstrip(".")
    if lowered in _BLOCKED_NAMES or lowered.endswith(_BLOCKED_SUFFIXES):
        return True
    if lowered in _METADATA_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    )


def _host_of(value: str) -> str | None:
    candidate = value.strip()
    if "://" in candidate:
        host = urlsplit(candidate).hostname
        return host.lower().rstrip(".") if host else None
    return candidate.lower().rstrip(".") or None
