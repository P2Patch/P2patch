#!/usr/bin/env python3
"""Record a human triage verdict for one or more residual POVs.

Verdicts live in ``residual_povs/triage/verdicts.json`` and are merged into the
generated ``TRIAGE.json`` by ``sweep_upstream.py``. This helper exists so the
delta is a reviewable command rather than a hand-edit of a big JSON blob, and so
``delta_days`` is always computed rather than typed.

    python3 residual_povs/triage/add_verdict.py \
        --slug dromara__hutool_CVE-2018-17297_4.1.11 \
        --pov residual_unzip_sibling_prefix --pov residual_fileapi_sibling_prefix \
        --status fixed-later --claim-class in-scope --confidence medium \
        --official-fix 8d7d0b7f --official-fix-date 2018-09-13 \
        --later-fix-date 2023-01-01 --later-fix-release "between 5.8.11 and 5.8.20" \
        --corroboration "unread" --notes "..." --url https://github.com/...

``--pov all`` applies to every POV in the suite.
"""
from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES_DIR = ROOT / "residual_povs"
VERDICTS_PATH = RES_DIR / "triage" / "verdicts.json"

STATUSES = ("fixed-later", "open-at-head", "superseded-in-release",
            "unsound", "disputed", "needs-manual", "untriaged")
CONFIDENCE = ("high", "medium", "low")


def delta_days(a: str, b: str):
    if not a or not b:
        return None
    try:
        fmt = "%Y-%m-%d"
        return (datetime.datetime.strptime(b[:10], fmt)
                - datetime.datetime.strptime(a[:10], fmt)).days
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slug", required=True)
    ap.add_argument("--pov", action="append", required=True,
                    help="POV id; repeatable; 'all' for every POV in the suite")
    ap.add_argument("--status", required=True, choices=STATUSES)
    ap.add_argument("--claim-class", default="", choices=["", "in-scope", "adjacent"])
    ap.add_argument("--confidence", default="medium", choices=CONFIDENCE)
    ap.add_argument("--official-fix", default="")
    ap.add_argument("--official-fix-date", default="")
    ap.add_argument("--later-fix", default="")
    ap.add_argument("--later-fix-date", default="")
    ap.add_argument("--later-fix-release", default="")
    ap.add_argument("--releases-exposed", default="")
    ap.add_argument("--corroboration", default="")
    ap.add_argument(
        "--reachability", default="",
        choices=["", "reportable", "code-quality-only", "by-design", "needs-more-work"],
        help=(
            "Whether an attacker can actually reach the sink through a public product "
            "entry point. Separate from status on purpose: 'the defect is still in the "
            "code' and 'someone can exploit it' are different claims, and only the "
            "second justifies a disclosure."
        ),
    )
    ap.add_argument("--reachability-notes", default="",
                    help="the call chain, preconditions and impact ceiling")
    ap.add_argument("--notes", default="")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--verified-by", default="")
    args = ap.parse_args()

    manifest_path = RES_DIR / args.slug / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"no manifest for {args.slug}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    all_ids = [p["id"] for p in manifest.get("povs", [])]
    pov_ids = all_ids if args.pov == ["all"] else args.pov
    unknown = [p for p in pov_ids if p not in all_ids]
    if unknown:
        raise SystemExit(f"unknown POV id(s) for {args.slug}: {unknown}\nknown: {all_ids}")

    data = (json.loads(VERDICTS_PATH.read_text(encoding="utf-8"))
            if VERDICTS_PATH.exists() else {"verdicts": {}})
    today = datetime.date.today().isoformat()
    for pov_id in pov_ids:
        data["verdicts"][f"{args.slug}::{pov_id}"] = {
            "status": args.status,
            "claim_class": args.claim_class,
            "confidence": args.confidence,
            "official_fix_commit": args.official_fix,
            "official_fix_date": args.official_fix_date,
            "later_fix_commit": args.later_fix,
            "later_fix_date": args.later_fix_date,
            "later_fix_release": args.later_fix_release,
            "delta_days": delta_days(args.official_fix_date, args.later_fix_date),
            "releases_exposed": args.releases_exposed,
            "corroboration": args.corroboration,
            "notes": args.notes,
            "reachability": args.reachability,
            "reachability_notes": args.reachability_notes,
            "evidence_urls": args.url,
            "verified_by": args.verified_by or f"human {today}",
        }
    VERDICTS_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"recorded {args.status} for {len(pov_ids)} POV(s) in {args.slug}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
