"""Source lookups - ask six free threat-intel services about one IOC."""

from __future__ import annotations

import csv
import io
import os
import tempfile
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
CACHE_TTL = 3600


def _get(url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> Optional[Dict[str, Any]]:
    try:
        r = requests.get(url, headers=headers or {}, timeout=timeout)
        if r.status_code == 429:
            time.sleep(2)
            r = requests.get(url, headers=headers or {}, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None


def virus_total(value: str, kind: str) -> Dict[str, Any]:
    key = os.environ.get("VT_API_KEY", "")
    if not key:
        return {}
    if kind == "ipv4":
        r = _get(f"https://www.virustotal.com/api/v3/ip_addresses/{value}", {"x-apikey": key})
    elif kind == "domain":
        r = _get(f"https://www.virustotal.com/api/v3/domains/{value}", {"x-apikey": key})
    elif kind in ("md5", "sha1", "sha256"):
        r = _get(f"https://www.virustotal.com/api/v3/files/{value}", {"x-apikey": key})
    else:
        return {}
    if not r:
        return {}
    attrs = r.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {"vt_positives": stats.get("malicious", 0), "vt_suspicious": stats.get("suspicious", 0)}


def abuse_ipdb(value: str) -> Dict[str, Any]:
    key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return {}
    r = _get("https://api.abuseipdb.com/api/v2/check",
             {"Key": key, "Accept": "application/json"},
             )
    # abuseipdb check endpoint needs params; call with params via _get is not supported here,
    # so fall back to a direct call with the IP in the query.
    try:
        r = _get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90",
                 {"Key": key, "Accept": "application/json"})
    except Exception:
        return {}
    if not r:
        return {}
    d = r.get("data", {})
    return {"abuse_confidence": d.get("abuseConfidenceScore", 0), "total_reports": d.get("totalReports", 0)}


def feodo(value: str) -> Dict[str, Any]:
    try:
        r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=15)
        listed = r.json()
        return {"feodo_listed": any(entry.get("ip_address") == value for entry in listed)}
    except Exception:
        return {}


def urlhaus_host(value: str, kind: str) -> str:
    """The host URLhaus tracks: domains pass through, URLs reduce to hostname."""
    if kind == "domain":
        return value.lower()
    if kind == "url":
        try:
            return (urlparse(value).hostname or "").lower()
        except ValueError:
            return ""
    return ""


def _csv_listed(host: str, csv_text: str) -> bool:
    """True when any cell of the URLhaus recent-URLs CSV mentions the host."""
    for row in csv.reader(io.StringIO(csv_text)):
        if any(host in cell for cell in row):
            return True
    return False


def _cache_path() -> str:
    d = os.path.join(tempfile.gettempdir(), "iocverdict")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "urlhaus_recent.csv")


def _cache_fresh(path: str, ttl: int = CACHE_TTL) -> bool:
    return os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl


def _read_cached_csv(url: str, ttl: int = CACHE_TTL) -> Optional[str]:
    """URLhaus CSV with a 1-hour file cache: one download per session."""
    path = _cache_path()
    if _cache_fresh(path, ttl):
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    r = requests.get(url, timeout=30)
    if r.status_code != 200:
        return None
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(r.text)
    return r.text


def urlhaus(value: str, kind: str) -> Dict[str, Any]:
    host = urlhaus_host(value, kind)
    if not host:
        return {}
    key = os.environ.get("URLHAUS_API_KEY", "")
    try:
        if key:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                              data={"host": host},
                              headers={"Auth-Key": key},
                              timeout=15)
            d = r.json()
            return {"urlhaus_listed": d.get("query_status") == "ok" and bool(d.get("urls"))}
        # No key: the public CSV of recent entries works without auth.
        csv_text = _read_cached_csv(URLHAUS_CSV_URL)
        if csv_text is None:
            return {}
        return {"urlhaus_listed": _csv_listed(host, csv_text)}
    except Exception:
        return {}


def malware_bazaar(value: str, kind: str) -> Dict[str, Any]:
    """MalwareBazaar hash lookup - free API key required (abuse.ch signup)."""
    key = os.environ.get("MALWAREBAZAAR_API_KEY", "")
    if not key or kind not in ("md5", "sha1", "sha256"):
        return {}
    try:
        r = requests.post(MALWAREBAZAAR_URL,
                          data={"query": "get_info", "hash": value},
                          headers={"Auth-Key": key},
                          timeout=15)
        d = r.json()
        if d.get("query_status") != "ok":
            return {}
        info = d.get("data") or []
        if not info:
            return {}
        first = info[0]
        return {
            "mb_listed": True,
            "mb_signature": first.get("signature") or first.get("file_name", ""),
        }
    except Exception:
        return {}


def otx(value: str, kind: str) -> Dict[str, Any]:
    key = os.environ.get("OTX_API_KEY", "")
    if not key or kind not in ("ipv4", "domain"):
        return {}
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/{kind.replace('ipv4', 'IPv4')}/{value}/general",
             {"X-OTX-API-KEY": key})
    if not r:
        return {}
    return {"otx_pulse_count": r.get("pulse_info", {}).get("count", 0)}


def shodan(value: str) -> Dict[str, Any]:
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return {}
    r = _get(f"https://api.shodan.io/shodan/host/{value}?key={key}")
    if not r:
        return {}
    return {"shodan_vulnerabilities": r.get("vulns", [])}


def run_all(value: str, kind: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    for fn in (virus_total, abuse_ipdb, feodo, urlhaus, otx, shodan, malware_bazaar):
        try:
            if fn in (virus_total, urlhaus, otx, malware_bazaar):
                data.update(fn(value, kind))
            else:
                data.update(fn(value))
        except Exception:
            continue
    return data
