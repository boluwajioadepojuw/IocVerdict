"""Source lookups - ask five free threat-intel services about one IOC."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import requests


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


def urlhaus(value: str, kind: str) -> Dict[str, Any]:
    if kind not in ("domain", "url"):
        return {}
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": value}, timeout=15)
        d = r.json()
        return {"urlhaus_listed": d.get("query_status") == "ok"}
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
    for fn in (virus_total, abuse_ipdb, feodo, urlhaus, otx, shodan):
        try:
            if fn is virus_total or fn is urlhaus or fn is otx:
                data.update(fn(value, kind))
            else:
                data.update(fn(value))
        except Exception:
            continue
    return data
