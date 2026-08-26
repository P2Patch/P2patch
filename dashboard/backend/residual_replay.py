"""Dashboard-triggered replay of curated residual POVs for one run.

Residual replay is the sibling of fixPOV replay: it shells out to the
pipeline's ``respov replay`` command and lets ``run_jobs`` own the background
worker, on-disk lock, status reporting, and refreshed-artifact checks.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import config
import groundtruth
import run_jobs
import runs

STATUS_NAME = "replay_status.json"
LOG_NAME = "replay.log"
LOCK_NAME = "replay.lock"

ReplayError = run_jobs.JobError


def _mapping(run_id: str) -> Dict[str, Any]:
    mapping = groundtruth.ground_truth_for_run(run_id)
    if mapping is None or not mapping.get("project_slug"):
        raise ReplayError(f"no project mapping for run: {run_id}")
    return mapping


def _manifest(project_slug: str) -> Path:
    return config.residual_povs_dir() / project_slug / "manifest.json"


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
        reason = "No curated residual POV manifest exists for this project yet."
    return {
        "available": reason is None,
        "unavailable_reason": reason,
        "project_slug": mapping["project_slug"],
        "has_manifest": manifest.is_file(),
    }


def _command(run_id: str, availability: Dict[str, Any]) -> list:
    return [
        sys.executable, "-m", "security_pipeline", "respov", "replay",
        "--project", availability["project_slug"],
        "--run", run_id,
        "--workspace-root", str(config.REPO_ROOT),
        "--alerts-dir", str(config.ALERTS_DIR),
        "--runs-dir", str(config.RUNS_DIR),
    ]


RESPOV_REPLAY = run_jobs.JobKind(
    label="residual replay",
    subdir="residual",
    status_name=STATUS_NAME,
    log_name=LOG_NAME,
    lock_name=LOCK_NAME,
    thread_prefix="respov-replay",
    availability=_availability,
    command=_command,
    result_path=lambda run_dir: run_dir / "residual" / "results.json",
    result_key="residual_eval",
    # Exit 1 means one or more POVs were inconclusive; the refreshed result is
    # still useful and should be displayed with its errored count.
    ok_returncodes=(0, 1),
)


def is_replay_active(run_id: str) -> bool:
    return run_jobs.is_active(RESPOV_REPLAY, run_id)


def status(run_id: str) -> Dict[str, Any]:
    return run_jobs.status(RESPOV_REPLAY, run_id)


def start(run_id: str) -> Dict[str, Any]:
    return run_jobs.start(RESPOV_REPLAY, run_id)
