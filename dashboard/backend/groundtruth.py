"""Ground-truth resolution: map a pipeline run back to its CVE and official fix.

Runs are named ``{timestamp}_finding-{hash}`` where the hash is
``sha256(alert_name:project_slug:cve_id)[:12]`` (see
``security_pipeline.pipeline.finding_id_from_parts``). The pipeline redacts the
CVE from its own artifacts, so we recover it by recomputing that hash for every
alert in ``finder_results_filtered`` and matching. Once we have the CVE we can
attach the official fix commits, the exact fix localization from
``fix_info.csv``, and (on demand) the real fix-commit diffs from GitHub.
"""
from __future__ import annotations

import csv
import functools
import json
import re
from pathlib import Path
from typing import Optional

import httpx

import config
from security_pipeline.pipeline import finding_id_from_parts

FINDING_RE = re.compile(r"(finding-[0-9a-f]{12})")


@functools.lru_cache(maxsize=1)
def project_rows() -> dict:
    """cve_id -> project_info.csv row."""
    rows: dict = {}
    if config.PROJECT_INFO_CSV.exists():
        with config.PROJECT_INFO_CSV.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                rows[row["cve_id"]] = row
    return rows


@functools.lru_cache(maxsize=1)
def fix_info() -> dict:
    """cve_id -> [fix_info.csv rows] (exact file/class/method/line of the official fix)."""
    out: dict = {}
    if config.FIX_INFO_CSV.exists():
        with config.FIX_INFO_CSV.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                out.setdefault(row["cve_id"], []).append(row)
    return out


@functools.lru_cache(maxsize=1)
def finding_index() -> dict:
    """finding_id -> {cve_id, project_slug, alert_file, row}."""
    idx: dict = {}
    rows = project_rows()
    if not config.ALERTS_DIR.exists():
        return idx
    for alert_path in sorted(config.ALERTS_DIR.glob("*.json")):
        try:
            alert = json.loads(alert_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        cve = alert.get("cve_id")
        row = rows.get(cve) if cve else None
        if not row:
            continue
        fid = finding_id_from_parts(alert_path.name, row["project_slug"], cve)
        idx[fid] = {
            "cve_id": cve,
            "project_slug": row["project_slug"],
            "alert_file": alert_path.name,
            "row": row,
        }
    return idx


def finding_id_for_run(run_id: str) -> Optional[str]:
    match = FINDING_RE.search(run_id)
    return match.group(1) if match else None


def _split_commits(raw: str) -> list:
    return [c.strip() for c in (raw or "").split(";") if c.strip()]


def _repo_path(github_url: str) -> Optional[str]:
    """https://github.com/perwendel/spark -> perwendel/spark."""
    if not github_url:
        return None
    match = re.search(r"github\.com[/:]+([^/]+/[^/.]+)", github_url)
    return match.group(1) if match else None


def _localizations(cve_id: str) -> list:
    out = []
    for row in fix_info().get(cve_id, []):
        out.append(
            {
                "commit": row.get("commit", ""),
                "file": row.get("file", ""),
                "class": row.get("class", ""),
                "class_start": row.get("class_start", ""),
                "class_end": row.get("class_end", ""),
                "method": row.get("method", ""),
                "method_start": row.get("method_start", ""),
                "method_end": row.get("method_end", ""),
                "signature": row.get("signature", ""),
                "is_test": "test" in (row.get("file", "").lower()),
            }
        )
    return out


def ground_truth_for_run(run_id: str) -> Optional[dict]:
    """Everything we know about the real-world vulnerability behind a run."""
    fid = finding_id_for_run(run_id)
    info = finding_index().get(fid) if fid else None
    if not info:
        return None

    row = info["row"]
    cve = info["cve_id"]
    advisory = (row.get("advisory_id") or "").strip()
    github_url = row.get("github_url", "")
    repo = _repo_path(github_url)
    localizations = _localizations(cve)
    prod_files = sorted({l["file"] for l in localizations if not l["is_test"]})

    return {
        "finding_id": fid,
        "cve_id": cve,
        "cwe_id": row.get("cwe_id", ""),
        "cwe_name": row.get("cwe_name", ""),
        "project_slug": info["project_slug"],
        "alert_file": info["alert_file"],
        "github_url": github_url,
        "repo": repo,
        "github_tag": row.get("github_tag", ""),
        "advisory_id": advisory,
        "buggy_commit_id": row.get("buggy_commit_id", ""),
        "fix_commit_ids": _split_commits(row.get("fix_commit_ids", "")),
        "fix_localizations": localizations,
        "fix_files": prod_files,
        "links": {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None,
            "advisory": f"https://github.com/advisories/{advisory}" if advisory else None,
            "repo": github_url or None,
            "buggy_commit": f"{github_url}/commit/{row.get('buggy_commit_id')}"
            if github_url and row.get("buggy_commit_id")
            else None,
        },
    }


def fetch_fix_diff(github_url: str, sha: str, timeout: float = 20.0) -> dict:
    """Fetch (and cache) the official fix-commit diff from GitHub."""
    repo = _repo_path(github_url)
    if not repo or not sha:
        return {"sha": sha, "error": "missing repo url or commit sha"}

    cache_path = config.CACHE_DIR / "fix_diffs" / repo.replace("/", "__") / f"{sha}.diff"
    url = f"https://github.com/{repo}/commit/{sha}.diff"
    if cache_path.exists():
        return {"sha": sha, "url": url, "diff": cache_path.read_text(encoding="utf-8"), "cached": True}

    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        return {"sha": sha, "url": url, "error": f"fetch failed: {exc}"}

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(resp.text, encoding="utf-8")
    return {"sha": sha, "url": url, "diff": resp.text, "cached": False}
