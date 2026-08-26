"""Reference-Patch agent (deterministic).

Finds the most relevant official-fix code to compare our patch against: fetches
the fix-commit diffs, keeps the production (non-test) files, and cross-references
the exact localization from fix_info.csv. No LLM — fast, free, reproducible.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import groundtruth
from . import base, diffutil

AGENT = "reference_patch"


def build(run_id: str, run_dir: Path, gt: dict) -> dict:
    commits = []
    production_diff_parts = []
    production_files: set = set()

    for sha in gt.get("fix_commit_ids", []):
        res = groundtruth.fetch_fix_diff(gt.get("github_url", ""), sha)
        if res.get("error"):
            commits.append({"sha": sha, "url": res.get("url"), "error": res["error"]})
            continue
        files = diffutil.parse_diff(res.get("diff", ""))
        commits.append(
            {
                "sha": sha,
                "url": res.get("url"),
                "files": [f.to_json() for f in files],
            }
        )
        for f in files:
            if not f.is_test:
                production_files.add(f.path)
                production_diff_parts.append(f"# {sha[:10]}  {f.path}\n{f.text()}")

    localizations = [l for l in gt.get("fix_localizations", []) if not l.get("is_test")]

    return {
        "cve_id": gt.get("cve_id"),
        "cwe_id": gt.get("cwe_id"),
        "repo": gt.get("repo"),
        "commits": commits,
        "production_files": sorted(production_files),
        "localizations": localizations,
        # Production-only official fix — the reference our patch is judged against.
        "reference_diff": "\n\n".join(production_diff_parts),
    }


def get_or_build(run_id: str, run_dir: Path, gt: dict, *, force: bool = False) -> dict:
    """Cache the reference bundle to analysis/reference_patch/result.json."""
    cached = base.get_result(run_dir, AGENT)
    if cached is not None and not force:
        return cached
    out = base.analysis_dir(run_dir, AGENT)
    bundle = build(run_id, run_dir, gt)
    (out / "result.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return bundle
