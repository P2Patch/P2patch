"""Dashboard-triggered replay of the curated fixPOVs for one run.

All the background-job bookkeeping — the on-disk lock, dead-holder reclamation,
job-tagged status writes, deleted-run protection — lives in ``run_jobs``, which
the retrofit job shares. This module is only the parts that are specific to a
fixPOV replay: what makes a run eligible, and the CLI command to run.

The evaluation itself stays in the pipeline CLI (``fixpov replay``) so a
dashboard-triggered replay and a terminal-triggered one are the same code path.

The public surface (``status``, ``start``, ``is_replay_active``, ``ReplayError``)
is unchanged from when this module owned the bookkeeping itself.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import config
import groundtruth
import run_jobs
import runs

# Kept as module-level names because they also name files already on disk in
# every run directory recorded so far (under the legacy ``ground_truth/``
# subdir for runs recorded before the fixPOV rename).
STATUS_NAME = "replay_status.json"
LOG_NAME = "replay.log"
LOCK_NAME = "replay.lock"

# Back-compat alias: callers (and tests) raise/catch this name.
ReplayError = run_jobs.JobError


def _mapping(run_id: str) -> Dict[str, Any]:
    mapping = groundtruth.ground_truth_for_run(run_id)
    if mapping is None or not mapping.get("project_slug"):
        raise ReplayError(f"no project mapping for run: {run_id}")
    return mapping


def _manifest(project_slug: str) -> Path:
    return config.fix_povs_dir() / project_slug / "manifest.json"


def _availability(run_id: str) -> Dict[str, Any]:
    run_dir = runs.resolve_run_dir(run_id)
    if run_dir is None:
        raise ReplayError(f"run not found: {run_id}")
    mapping = _mapping(run_id)
    manifest = _manifest(mapping["project_slug"])
    detail = runs.get_run(run_id) or {}
    reason = None
    if detail.get("status") != "accepted":
        reason = "Only accepted runs can be replayed."
    elif not (run_dir / "worktree").is_dir():
        reason = "The run's patched worktree is missing."
    elif not manifest.is_file():
        reason = "No curated fixPOV manifest exists for this project yet."
    return {
        "available": reason is None,
        "unavailable_reason": reason,
        "project_slug": mapping["project_slug"],
        "has_manifest": manifest.is_file(),
    }


def _command(run_id: str, availability: Dict[str, Any]) -> list:
    return [
        sys.executable, "-m", "security_pipeline", "fixpov", "replay",
        "--project", availability["project_slug"],
        "--run", run_id,
        "--workspace-root", str(config.REPO_ROOT),
        "--alerts-dir", str(config.ALERTS_DIR),
        "--runs-dir", str(config.RUNS_DIR),
    ]


FIXPOV_REPLAY = run_jobs.JobKind(
    label="fixPOV replay",
    subdir="fix_pov",
    status_name=STATUS_NAME,
    log_name=LOG_NAME,
    lock_name=LOCK_NAME,
    thread_prefix="fixpov-replay",
    availability=_availability,
    command=_command,
    # New writes always land here; a legacy run's ``ground_truth/results.json``
    # is a read-side fallback only (see ``runs.fix_pov_results_path``).
    result_path=lambda run_dir: run_dir / "fix_pov" / "results.json",
    result_key="fix_pov_eval",
    # Exit 1 means one or more POVs were inconclusive; the refreshed result is
    # still useful and should be displayed with its errored count.
    ok_returncodes=(0, 1),
)


def is_replay_active(run_id: str) -> bool:
    return run_jobs.is_active(FIXPOV_REPLAY, run_id)


def status(run_id: str) -> Dict[str, Any]:
    return run_jobs.status(FIXPOV_REPLAY, run_id)


def start(run_id: str) -> Dict[str, Any]:
    return run_jobs.start(FIXPOV_REPLAY, run_id)
