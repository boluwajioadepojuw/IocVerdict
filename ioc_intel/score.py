"""Risk scoring - combine source verdicts into one 0-100 number."""

from __future__ import annotations

from typing import Any, Dict


def verdict_score(data: Dict[str, Any]) -> int:
    total = 0

    positives = data.get("vt_positives", 0)
    if positives >= 5:
        total += 75
    elif positives >= 3:
        total += 55
    elif positives >= 1:
        total += 25

    total += min(data.get("vt_suspicious", 0) * 2, 15)
    total += int(data.get("abuse_confidence", 0) * 0.7)
    total += min(data.get("total_reports", 0) * 0.4, 15)
    total += 25 if data.get("feodo_listed") else 0
    total += 20 if data.get("urlhaus_listed") else 0
    total += 40 if data.get("mb_listed") else 0
    total += min(data.get("otx_pulse_count", 0) * 4, 25)
    total += min(len(data.get("shodan_vulnerabilities", [])) * 8, 20)

    return min(100, int(total))
