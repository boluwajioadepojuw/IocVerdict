"""IocVerdict command line."""

from __future__ import annotations

import argparse
import sys

from .attck import map_findings
from .classify import kind_of
from .enrich import run_all
from .report import to_json, to_text
from .score import verdict_score


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="ioc-verdict",
        description="Look up an indicator against free threat-intel sources, score it, map it to MITRE ATT&CK.")
    p.add_argument("ioc", nargs="+", help="IP, domain, URL or hash (one or more).")
    p.add_argument("--json", action="store_true", help="Machine-readable output.")
    args = p.parse_args(argv)

    rc = 0
    for value in args.ioc:
        kind = kind_of(value)
        if kind == "unknown":
            print(f"{value}: could not classify indicator type", file=sys.stderr)
            rc = 1
            continue
        data = run_all(value, kind)
        sc = verdict_score(data)
        techniques = map_findings(data)
        if args.json:
            print(to_json(value, kind, sc, techniques, data))
        else:
            print(to_text(value, kind, sc, techniques))
        print()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
