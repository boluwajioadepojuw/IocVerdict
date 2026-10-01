"""IOC type detection - decide what kind of indicator we are looking at."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_DOMAIN_RE = re.compile(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")
_URL_RE = re.compile(r"^https?://[^\s]+$")


def _ip_version(value: str) -> Optional[int]:
    try:
        return ipaddress.ip_address(value.strip()).version
    except ValueError:
        return None


def kind_of(value: str) -> str:
    if not value or not isinstance(value, str):
        return "unknown"
    v = value.strip()
    if not v:
        return "unknown"
    if _URL_RE.match(v.lower()):
        return "url"
    ver = _ip_version(v)
    if ver == 4:
        return "ipv4"
    if ver == 6:
        return "ipv6"
    if _DOMAIN_RE.match(v.lower()):
        return "domain"
    low = v.lower()
    if len(low) in _HASH_LENGTHS and all(c in "0123456789abcdef" for c in low):
        return _HASH_LENGTHS[len(low)]
    return "unknown"
