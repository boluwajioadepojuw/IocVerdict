"""Report output - human and machine readable verdicts."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def to_text(ioc: str, kind: str, score: int, techniques: List[Dict[str, str]]) -> str:
    lines = [
        "IocVerdict",
        "=" * 40,
        f"indicator : {ioc}",
        f"type      : {kind}",
        f"score     : {score}/100",
    ]
    if techniques:
        lines.append("MITRE ATT&CK:")
        for t in techniques:
            lines.append(f"  {t['id']} {t['name']} [{t['tactic']}]")
    return "\n".join(lines)


def to_json(ioc: str, kind: str, score: int, techniques: List[Dict[str, str]],
            raw: Dict[str, Any]) -> str:
    return json.dumps({
        "indicator": ioc,
        "type": kind,
        "score": score,
        "mitre": techniques,
        "sources": raw,
    }, indent=2)
