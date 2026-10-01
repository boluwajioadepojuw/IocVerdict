"""MITRE ATT&CK mapping - turn what the sources said into techniques."""

from __future__ import annotations

from typing import Any, Dict, List

_MAP: Dict[str, Dict[str, str]] = {
    "c2":       {"id": "T1071",     "name": "Application Layer Protocol",  "tactic": "Command and Control"},
    "c2_web":   {"id": "T1071.001", "name": "Web Protocols",               "tactic": "Command and Control"},
    "c2_dns":   {"id": "T1071.004", "name": "DNS",                         "tactic": "Command and Control"},
    "proxy":    {"id": "T1090",     "name": "Proxy",                       "tactic": "Command and Control"},
    "malware":  {"id": "T1204.002", "name": "Malicious File",              "tactic": "Execution"},
    "phish":    {"id": "T1566.001", "name": "Spearphishing Attachment",    "tactic": "Initial Access"},
    "exploit":  {"id": "T1190",     "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "scan":     {"id": "T1595.001", "name": "Scanning IP Blocks",          "tactic": "Reconnaissance"},
    "botnet":   {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development"},
    "exfil":    {"id": "T1041",     "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
}


def map_findings(data: Dict[str, Any]) -> List[Dict[str, str]]:
    tags: set = set()
    if data.get("feodo_listed"):
        tags.add("botnet")
    if data.get("urlhaus_listed"):
        tags.add("malware")
    if data.get("vt_positives", 0) >= 3:
        tags.add("c2")
    if data.get("otx_pulse_count", 0) >= 3:
        tags.add("malware")
    if data.get("shodan_vulnerabilities"):
        tags.add("exploit")
    out: List[Dict[str, str]] = []
    for tag in sorted(tags):
        if tag in _MAP:
            out.append(dict(_MAP[tag]))
    return out
