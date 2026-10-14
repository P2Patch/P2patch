"""Freeze the read-only P2Patch Lab API to a static file tree for public hosting.

The live dashboard is a FastAPI server that reads local run artifacts and spawns
Docker/Claude — none of which runs on a static host. But ~everything a teammate
needs to *analyze* the experiments is read-only and already sits on disk. This
script walks every run and writes each read-only endpoint's response to a tree
that mirrors the API URL layout, so a frontend built with ``VITE_STATIC=1`` can
fetch flat files instead of a server. The control surfaces (Live, launch,
delete, re-run analysis) are hidden in that build.

URL → file mapping (the frontend's static fetch appends ``.json`` / ``.txt``):

    GET /api/stats                         -> stats.json
    GET /api/runs                          -> runs.json
    GET /api/runs/{id}                     -> runs/{id}.json
    GET /api/runs/{id}/agents/{name}       -> runs/{id}/agents/{name}.json
    GET /api/runs/{id}/diff/{kind}         -> runs/{id}/diff/{kind}.txt
    GET /api/runs/{id}/log/{name}          -> runs/{id}/log/{name}.txt
    GET /api/runs/{id}/ground-truth        -> runs/{id}/ground-truth.json  (with diffs)
    GET /api/runs/{id}/analysis/{agent}    -> runs/{id}/analysis/{agent}.json
    (plus meta.json — snapshot freshness for the "published" banner)

Usage (from the repo root, with the backend venv active so httpx imports):

    python dashboard/export_static.py                 # -> dashboard/frontend/public/api
    python dashboard/export_static.py --out DIR       # custom output dir
    python dashboard/export_static.py --no-diffs       # skip GitHub fix-diff fetch

Re-run it after new pipeline runs, commit the regenerated tree, and push — the
static host redeploys and teammates see exactly what you see.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent
BACKEND_DIR = DASHBOARD_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import config  # noqa: E402  (side effect: puts REPO_ROOT on sys.path)
import groundtruth  # noqa: E402
import runs  # noqa: E402
from analysis import base as analysis_base  # noqa: E402
from analysis import cve_research, exploit_eval, patch_eval  # noqa: E402

DEFAULT_OUT = DASHBOARD_DIR / "frontend" / "public" / "api"

# URL-slug → on-disk analysis agent dir. The frontend fetches by the hyphenated
# slug it uses in the live API; the cache dir uses underscores.
ANALYSIS_AGENTS = {
    "patch-eval": patch_eval.AGENT,
    "exploit-eval": exploit_eval.AGENT,
    "cve-research": cve_research.AGENT,
}


def _write_json(path: Path, obj) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, ensure_ascii=False)
    path.write_text(data, encoding="utf-8")
    return len(data.encode("utf-8"))


def _write_text(path: Path, text: str) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return len(text.encode("utf-8"))


def _ground_truth(run_id: str, *, with_diffs: bool) -> dict | None:
    """Mirror GET /runs/{id}/ground-truth?diffs=true — the panel reads one file."""
    gt = groundtruth.ground_truth_for_run(run_id)
    if gt is None:
        return None
    gt = dict(gt)
    if with_diffs and gt.get("github_url"):
        diffs = []
        for sha in gt.get("fix_commit_ids", []):
            try:
                diffs.append(groundtruth.fetch_fix_diff(gt["github_url"], sha))
            except Exception as exc:  # noqa: BLE001 — one bad fetch shouldn't abort
                diffs.append({"sha": sha, "url": None, "diff": None, "error": f"{type(exc).__name__}: {exc}"})
        gt["official_fix_diffs"] = diffs
    return gt


def export(out_dir: Path, *, with_diffs: bool) -> None:
    if not config.RUNS_DIR.is_dir():
        raise SystemExit(f"runs dir not found: {config.RUNS_DIR}")

    # Start clean so a deleted run leaves no stale file behind. Only the api/
    # subtree is touched — sibling public/ assets are left alone.
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    run_list = runs.list_runs()
    bytes_written = 0
    files = 0

    def put_json(rel: str, obj) -> None:
        nonlocal bytes_written, files
        bytes_written += _write_json(out_dir / rel, obj)
        files += 1

    def put_text(rel: str, text: str) -> None:
        nonlocal bytes_written, files
        bytes_written += _write_text(out_dir / rel, text)
        files += 1

    put_json("stats.json", runs.stats())
    put_json("runs.json", run_list)
    put_json(
        "meta.json",
        {
            "published": True,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_count": len(run_list),
            "profiles": sorted({r["profile"] for r in run_list if r.get("profile")}),
            "distinct_cves": len({r["cve_id"] for r in run_list if r.get("cve_id")}),
        },
    )

    for i, summary in enumerate(run_list, 1):
        rid = summary["run_id"]
        detail = runs.get_run(rid)
        if detail is None:
            print(f"  ! skip {rid} (no detail)")
            continue
        put_json(f"runs/{rid}.json", detail)

        # Hardening runs add labeled per-round agents (for example
        # exploiter_harden_r2); export every agent the detail API exposes.
        for name in [a.get("name") for a in detail.get("agents", []) if a.get("name")]:
            io = runs.get_agent_io(rid, name)
            if io is not None:
                put_json(f"runs/{rid}/agents/{name}.json", io)

        for kind, present in detail["artifacts"]["diffs"].items():
            if present:
                diff = runs.get_diff(rid, kind)
                if diff is not None:
                    put_text(f"runs/{rid}/diff/{kind}.txt", diff)

        for log_name in detail["artifacts"]["logs"]:
            log = runs.get_log(rid, log_name)
            if log is not None:
                # getText requests /log/{name} and appends .txt → {name}.txt,
                # where {name} already carries the .log extension.
                put_text(f"runs/{rid}/log/{log_name}.txt", log)

        gt = _ground_truth(rid, with_diffs=with_diffs)
        if gt is not None:
            put_json(f"runs/{rid}/ground-truth.json", gt)

        run_dir = runs.resolve_run_dir(rid)
        for slug, agent in ANALYSIS_AGENTS.items():
            put_json(
                f"runs/{rid}/analysis/{slug}.json",
                {
                    "status": analysis_base.get_status(run_dir, agent),
                    "result": analysis_base.get_result(run_dir, agent),
                },
            )

        print(f"  [{i}/{len(run_list)}] {rid}  {summary.get('cve_id') or '—'}  ({summary['profile']})")

    print(f"\n✓ exported {files} files ({bytes_written / 1024:.0f} KB) → {out_dir}")
    print(f"  {len(run_list)} runs · diffs {'fetched' if with_diffs else 'skipped'}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Export the read-only dashboard API to a static file tree.")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output dir (default: {DEFAULT_OUT})")
    ap.add_argument("--no-diffs", action="store_true", help="skip fetching official fix diffs from GitHub")
    args = ap.parse_args()
    export(args.out.resolve(), with_diffs=not args.no_diffs)


if __name__ == "__main__":
    main()
