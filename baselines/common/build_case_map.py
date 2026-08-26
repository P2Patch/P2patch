#!/usr/bin/env python3
"""Emit ``baselines/cases.json`` — the join between our dataset and each baseline's benchmark.

One row per case we could run a baseline on, carrying: our slug and alert path, which
baselines' benchmarks contain it (and therefore which published per-case numbers exist for
it), whether we have a certified fixPOV, and whether we currently have a real
functional test command.

This is the file every adapter and every results table keys off. Regenerate it whenever the
dataset or the transcribed tables change:

    python3 baselines/common/build_case_map.py            # writes baselines/cases.json
    python3 baselines/common/build_case_map.py --check    # non-zero exit if stale

Stdlib only, same rule as ``security_pipeline/``. Reads ``vendor/san2patch-benchmark`` if it
has been cloned (for the VulnLoc metadata, including the functional-test scripts we are
missing); falls back to a checked-in case list otherwise, so this works before setup.sh runs.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from security_pipeline import paths as _paths  # noqa: E402
BASELINES = ROOT / "baselines"
OUT = BASELINES / "cases.json"

sys.path.insert(0, str(ROOT))
from baselines import patch_source  # noqa: E402

# C/C++ projects in our dataset. Kept as a list rather than derived from build_info because
# `detect_build_defaults` reports "unknown" for all of them (no pom.xml/gradlew), which is not
# the same question as "what language is this".
CPP_PROJECT_KEYS = (
    "binutils", "libtiff", "libxml2", "jasper", "libjpeg",
    "libming", "zziplib", "coreutils", "potrace", "libarchive",
)

# VulnLoc bug ids, as shipped in san2patch-benchmark/vulnloc-meta-data.json. Checked in so this
# script works before `setup.sh` has cloned anything; the cloned copy wins when present.
VULNLOC_FALLBACK = [
    "CVE-2017-14745", "CVE-2017-15020", "CVE-2017-15025", "CVE-2017-6965",
    "gnubug-19784", "gnubug-25003", "gnubug-25023", "gnubug-26545",
    "CVE-2017-9992", "bugchrom-1404",
    "CVE-2016-8691", "CVE-2016-9557", "CVE-2016-5844",
    "CVE-2012-2806", "CVE-2017-15232", "CVE-2018-14498", "CVE-2018-19664",
    "CVE-2016-9264", "CVE-2018-8806", "CVE-2018-8964",
    "bugzilla-2610", "bugzilla-2611", "bugzilla-2633",
    "CVE-2016-10092", "CVE-2016-10094", "CVE-2016-10272", "CVE-2016-3186",
    "CVE-2016-5314", "CVE-2016-5321", "CVE-2016-9273", "CVE-2016-9532",
    "CVE-2017-5225", "CVE-2017-7595", "CVE-2017-7599", "CVE-2017-7600", "CVE-2017-7601",
    "CVE-2012-5134", "CVE-2016-1838", "CVE-2016-1839", "CVE-2017-5969",
    "CVE-2013-7437",
    "CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976",
]

# The 12 CrashRepair additions that make VulnLoc+ (LoopRepair's "RED-TEAM-*" rows). Only the
# ones that exist in our dataset are listed; the rest are irrelevant to the join.
VULNLOC_PLUS_EXTRA = [
    "CVE-2020-27828", "CVE-2021-3272",          # jasper
    "CVE-2018-18557", "CVE-2022-4645", "CVE-2022-48281",  # libtiff
    "CVE-2016-1833",                             # libxml2
]

# Cases San2Patch dropped from VulnLoc because they would not reproduce under sanitizer
# instrumentation (their §4.1). Recorded so a missing per-case number reads as "excluded by
# the authors", not "we failed to transcribe it".
SAN2PATCH_EXCLUDED = ["bugchrom-1404", "CVE-2017-9992", "CVE-2016-3186", "CVE-2016-5314"]


def is_cpp(slug: str) -> bool:
    return any(key in slug.lower() for key in CPP_PROJECT_KEYS)


def load_vulnloc_ids() -> tuple[list[str], str]:
    """Prefer the cloned benchmark's metadata; fall back to the checked-in list."""
    meta = BASELINES / "vendor" / "san2patch-benchmark" / "vulnloc-meta-data.json"
    if meta.exists():
        entries = json.loads(meta.read_text(encoding="utf-8"))
        return [e["bug_id"] for e in entries], "vendor/san2patch-benchmark"
    return list(VULNLOC_FALLBACK), "checked-in fallback (run setup.sh for the real thing)"


def load_paper_results() -> dict:
    """case_id -> {baseline: verdict} from the transcribed tables."""
    out: dict[str, dict] = {}
    pa = json.loads((BASELINES / "paper_reported" / "patchagent_table2.json").read_text())
    for case in pa["cases"]:
        out.setdefault(case["case_id"], {})["patchagent"] = {
            "patchagent": case["patchagent"],
            "extractfix": case["extractfix"],
            "zeroshot": case["zeroshot"],
        }
    s2p = json.loads((BASELINES / "paper_reported" / "san2patch_table1.json").read_text())
    for case in s2p["cases"]:
        automated, manual = case["san2patch"]
        out.setdefault(case["case_id"], {})["san2patch"] = {
            "automated": automated, "manual": manual, "bug_type": case["bug_type"],
        }
    # looprepair per-case is deliberately not transcribed — see its paper_reported file.
    return out


def build() -> dict:
    info_path = _paths.project_info_csv(ROOT)
    build_path = _paths.build_info_csv(ROOT)
    alerts_dir = ROOT / "finder_results_filtered"
    fixpov_dir = _paths.fix_povs_dir(ROOT)
    respov_dir = _paths.residual_povs_dir(ROOT)

    with info_path.open(newline="", encoding="utf-8-sig") as handle:
        info = list(csv.DictReader(handle))
    with build_path.open(newline="", encoding="utf-8-sig") as handle:
        build_rows = {r["project_slug"]: r for r in csv.DictReader(handle)}

    alert_by_cve: dict[str, str] = {}
    for path in sorted(alerts_dir.glob("*.json")):
        try:
            cve = json.loads(path.read_text(encoding="utf-8")).get("cve_id", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if cve:
            alert_by_cve.setdefault(cve, str(path.relative_to(ROOT)))

    fixpov = {p.name for p in fixpov_dir.iterdir() if p.is_dir()} if fixpov_dir.exists() else set()
    respov = {p.name for p in respov_dir.iterdir() if p.is_dir()} if respov_dir.exists() else set()

    vulnloc, vulnloc_source = load_vulnloc_ids()
    vulnloc_set = set(vulnloc)
    vulnloc_plus = (vulnloc_set - {"bugchrom-1404", "CVE-2017-9992"}) | set(VULNLOC_PLUS_EXTRA)
    paper = load_paper_results()

    # bug_id -> the commit san2patch-benchmark checks out. The join is on case id,
    # which says the two benchmarks mean the same *vulnerability* — it does not say
    # they pin the same *commit*, and for zziplib they demonstrably do not. Recording
    # it here makes a future divergence show up as a `--check` failure instead of as a
    # patch that mysteriously will not apply. See patch_source.base_plan.
    s2p_bases = {}
    for case in patch_source.iter_cases("san2patch", ROOT):
        s2p_bases[case.case_id] = case

    cases = []
    for row in info:
        slug, cve = row["project_slug"], row["cve_id"]
        if not is_cpp(slug):
            continue
        brow = build_rows.get(slug, {})
        test_cmd = (brow.get("test_command") or "").strip()
        s2p_case = s2p_bases.get(cve)
        base = (
            patch_source.base_plan(
                "san2patch", ROOT, s2p_case, row["buggy_commit_id"],
                source_path=_paths.project_sources_dir(ROOT) / slug,
            )
            if s2p_case is not None else None
        )
        cases.append({
            "case_id": cve,
            "project_slug": slug,
            "project": row["github_repository_name"],
            "cwe_id": row["cwe_id"],
            "buggy_commit_id": row["buggy_commit_id"],
            "baseline_base": {"san2patch": base} if base else None,
            "alert_path": alert_by_cve.get(cve),
            "has_alert": cve in alert_by_cve,
            "has_fixpov": slug in fixpov,
            "has_respov": slug in respov,
            # `true` is a literal no-op that the pipeline accepts as a passing regression gate.
            # Treating it as "we have tests" is how a functionality-destroying patch scores.
            "has_functional_test": bool(test_cmd) and test_cmd != "true",
            "test_command": test_cmd or None,
            "in_benchmark": {
                "vulnloc": cve in vulnloc_set,
                "vulnloc_plus": cve in vulnloc_plus,
                "san2patch_evaluated": cve in vulnloc_set and cve not in SAN2PATCH_EXCLUDED,
                "patchagent_table2": "patchagent" in paper.get(cve, {}),
            },
            "paper_reported": paper.get(cve, {}) or None,
        })

    cases.sort(key=lambda c: (c["project"], c["case_id"]))
    covered = [c for c in cases if any(c["in_benchmark"].values())]
    return {
        "_generated_by": "baselines/common/build_case_map.py",
        "_vulnloc_source": vulnloc_source,
        "_note": (
            "Join key is `case_id` == our project_info.csv `cve_id`, which is also the "
            "benchmarks' `bug_id`. Regenerate after changing the dataset or the transcribed "
            "tables; do not hand-edit."
        ),
        "summary": {
            "cpp_cases_in_our_dataset": len(cases),
            "with_alert": sum(1 for c in cases if c["has_alert"]),
            "with_certified_fixpov": sum(1 for c in cases if c["has_fixpov"]),
            "with_functional_test": sum(1 for c in cases if c["has_functional_test"]),
            "covered_by_some_baseline_benchmark": len(covered),
            "in_vulnloc": sum(1 for c in cases if c["in_benchmark"]["vulnloc"]),
            "in_vulnloc_plus": sum(1 for c in cases if c["in_benchmark"]["vulnloc_plus"]),
            "in_patchagent_table2": sum(1 for c in cases if c["in_benchmark"]["patchagent_table2"]),
            "san2patch_base_differs": sum(
                1 for c in cases
                if ((c["baseline_base"] or {}).get("san2patch") or {}).get("state") == "differs"
            ),
            "san2patch_base_unresolved": sum(
                1 for c in cases
                if ((c["baseline_base"] or {}).get("san2patch") or {}).get("state") == "unresolved"
            ),
        },
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit non-zero if cases.json is stale")
    args = parser.parse_args()

    payload = json.dumps(build(), indent=2) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != payload:
            print(f"{OUT.relative_to(ROOT)} is stale — rerun without --check", file=sys.stderr)
            return 1
        print(f"{OUT.relative_to(ROOT)} is up to date")
        return 0

    OUT.write_text(payload, encoding="utf-8")
    summary = json.loads(payload)["summary"]
    print(f"wrote {OUT.relative_to(ROOT)}")
    for key, value in summary.items():
        print(f"  {key:38} {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
