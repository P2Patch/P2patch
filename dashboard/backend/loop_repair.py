"""Read-only view over the LoopRepair baseline-tool benchmark results.

``baselines/runs/loop_repair/merged/`` is produced entirely out-of-band by
``run_looprepair_standalone.sh`` (run on one or more hosts, then hand-merged
into ``merged/`` — see that directory's own history) — this module only reads
it, it never runs or modifies anything. ``summary.csv`` is the index, one row
per CVE; ``cves/<project>__<cve>/`` holds each CVE's full artifact bundle
(``patch.diff``, ``bug.json``, ``reference_fix.patch``, ``verification.json``,
logs, ``pov_input/``).
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import runs

SUMMARY_CSV = config.LOOP_REPAIR_DIR / "summary.csv"
CVES_DIR = config.LOOP_REPAIR_DIR / "cves"

# "<project>__<cve>" -- letters, digits, underscore, dot, hyphen only. Also the
# path-traversal guard: no "/" means no escaping CVES_DIR (same convention as
# sources.py's SLUG_RE / runs.py's RUN_RE).
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")

LOG_FILES = ["orchestrator.log", "docker_stdout.log", "docker_stderr.log"]
DIFF_KINDS = {"patch": "patch.diff", "reference": "reference_fix.patch"}


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _int_or_none(v: str) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _float_or_none(v: str) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _cve_dir(key: str) -> Optional[Path]:
    if not KEY_RE.match(key):
        return None
    d = (CVES_DIR / key).resolve()
    if d.parent != CVES_DIR.resolve() or not d.is_dir():
        return None
    return d


def _pov_headline(cve_dir: Path, subdir: str) -> Optional[Dict[str, Any]]:
    """Score + pass/fail headline only (no per-POV detail) — cheap enough to
    compute for every row of the list page."""
    summary = _read_json(runs.eval_results_path(cve_dir, subdir))
    if not summary:
        return None
    return {
        "score": summary.get("score"),
        "total": summary.get("total"),
        "all_blocked": summary.get("all_blocked"),
        "all_hardened": summary.get("all_hardened"),
    }


def list_results() -> List[Dict[str, Any]]:
    """Every row of summary.csv, sorted by project then CVE."""
    if not SUMMARY_CSV.is_file():
        return []
    out: List[Dict[str, Any]] = []
    with open(SUMMARY_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = f"{row['project']}__{row['cve']}"
            cve_dir = _cve_dir(key)
            out.append(
                {
                    "key": key,
                    "project": row["project"],
                    "cve": row["cve"],
                    "vul_id": row["vul_id"],
                    "status": row["status"],
                    "elapsed_seconds": _int_or_none(row["elapsed_seconds"]),
                    "num_patches_evaluated": _int_or_none(row["num_patches_evaluated"]),
                    "num_repairs_found": _int_or_none(row["num_repairs_found"]),
                    "patch_found": row["patch_found"] == "true",
                    "prompt_tokens": _int_or_none(row["prompt_tokens"]),
                    "completion_tokens": _int_or_none(row["completion_tokens"]),
                    "total_tokens": _int_or_none(row["total_tokens"]),
                    "cost_usd": _float_or_none(row["cost_usd"]),
                    "message": row.get("message") or "",
                    "fix_pov": _pov_headline(cve_dir, "fix_pov") if cve_dir else None,
                    "residual": _pov_headline(cve_dir, "residual") if cve_dir else None,
                }
            )
    def sort_key(r: Dict[str, Any]) -> tuple:
        # Failed LoopRepair runs first (LoopRepairTable.tsx's own pass/fail
        # mapping: only "patched" reads as a pass, everything else -- just
        # "no_patch" today -- reads as a fail). Within each group, weakest
        # fixPOV coverage first: a row with no score yet (never
        # replayed, or errored) sorts as if it were the worst, since it needs
        # attention the same way a low score does.
        failed_first = 0 if r["status"] != "patched" else 1
        gt_score = r["fix_pov"]["score"] if r["fix_pov"] else None
        gt_sort = gt_score if gt_score is not None else -1.0
        return (failed_first, gt_sort, r["project"], r["cve"])

    out.sort(key=sort_key)
    return out


def stats() -> Dict[str, Any]:
    """Headline counts for the list page — mirrors runs.stats()'s shape loosely."""
    rows = list_results()
    patched = sum(1 for r in rows if r["status"] == "patched")
    total_cost = sum(r["cost_usd"] or 0.0 for r in rows)
    total_tokens = sum(r["total_tokens"] or 0 for r in rows)
    return {
        "total": len(rows),
        "patched": patched,
        "failed": len(rows) - patched,
        "success_rate": (patched / len(rows)) if rows else 0.0,
        "total_cost_usd": total_cost,
        "total_tokens": total_tokens,
    }


def get_result(key: str) -> Optional[Dict[str, Any]]:
    """One CVE's full bundle: summary row + bug.json + verification.json + what's available."""
    rows = {r["key"]: r for r in list_results()}
    summary = rows.get(key)
    if summary is None:
        return None
    d = _cve_dir(key)
    if d is None:
        # Row exists in the CSV but the artifact directory is missing — still
        # return the summary rather than 404, the caller can render "no bundle".
        return {**summary, "bug": None, "verification": None, "has_patch": False,
                 "has_reference_fix": False, "pov_input_files": [], "logs_available": []}
    pov_dir = d / "pov_input"
    pov_files = sorted(p.name for p in pov_dir.iterdir() if p.is_file()) if pov_dir.is_dir() else []
    patch_text = _read_text(d / "patch.diff")
    return {
        **summary,
        "bug": _read_json(d / "bug.json"),
        "verification": _read_json(d / "verification.json"),
        "has_patch": bool(patch_text and patch_text.strip()),
        "has_reference_fix": (d / "reference_fix.patch").is_file(),
        # Full per-POV detail (list_results()'s "fix_pov"/"residual" keys
        # are score-only headlines, cheap enough to compute for every row).
        "fix_pov_eval": runs._fix_pov_eval(d),
        "residual_eval": runs._residual_eval(d),
        "pov_input_files": pov_files,
        "logs_available": [name for name in LOG_FILES if (d / name).is_file()],
    }


def get_diff(key: str, kind: str) -> Optional[str]:
    d = _cve_dir(key)
    if d is None or kind not in DIFF_KINDS:
        return None
    return _read_text(d / DIFF_KINDS[kind])


def get_log(key: str, name: str) -> Optional[str]:
    if name not in LOG_FILES:
        return None
    d = _cve_dir(key)
    if d is None:
        return None
    return _read_text(d / name)


def get_pov_input(key: str, filename: str) -> Optional[bytes]:
    d = _cve_dir(key)
    if d is None:
        return None
    pov_dir = (d / "pov_input").resolve()
    target = (pov_dir / filename).resolve()
    if target.parent != pov_dir or not target.is_file():
        return None
    try:
        return target.read_bytes()
    except OSError:
        return None
