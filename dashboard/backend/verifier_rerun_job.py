"""Dashboard-triggered re-run of the verifier for one run whose verifier crashed.

Some runs get rejected not because the verifier judged the patch bad, but because
the verifier *agent* crashed and produced no verdict at all — an expired OAuth
session, ``error_max_structured_output_retries`` (a small model failing to format
the structured verdict on a large review), or a transient API error. Every
objective gate (POV-after, hardening, regression) had already passed. A crashed
agent is infrastructure, not a rejection.

This button re-runs the verifier on the run's saved review task via
``security-pipeline rerun-verifier`` and, ONLY if the fresh verifier accepts,
flips the run to accepted. A genuine ``rejected`` verdict is left as a rejection,
so this never launders a real rejection into a pass.

Unlike ``retrofit`` (assess-only, eligible only for accepted runs that never ran
the verifier), this is exactly for a *rejected* run whose verifier crashed.

All background-job bookkeeping is shared with the other jobs via ``run_jobs``;
only eligibility and the argv live here.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict

import config
import run_jobs
import runs

STATUS_NAME = "verifier_rerun_status.json"
LOG_NAME = "verifier_rerun.log"
LOCK_NAME = "verifier_rerun.lock"

VerifierRerunError = run_jobs.JobError


def _verifier_crashed(run_dir) -> bool:
    """True iff the recorded verifier agent failed to produce a verdict.

    Duplicated from ``security_pipeline.verifier_rerun.verifier_crashed`` rather
    than imported — the dashboard backend is a loose module tree (see
    retrofit_job.py). The CLI stays the single source of truth for what actually
    runs; this only gates the button.
    """
    try:
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if state.get("status") == "accepted":
        return False
    for agent in state.get("agents", []):
        if agent.get("agent_name") != "verifier":
            continue
        if agent.get("refused"):
            return False  # a policy refusal is not a re-runnable crash
        if agent.get("parse_error") or int(agent.get("exit_code") or 0) != 0:
            return True
    return False


def _availability(run_id: str) -> Dict[str, Any]:
    run_dir = runs.resolve_run_dir(run_id)
    if run_dir is None:
        raise VerifierRerunError(f"run not found: {run_id}")

    detail = runs.get_run(run_id) or {}
    reason = None
    if detail.get("status") == "accepted":
        reason = "This run is already accepted."
    elif not _verifier_crashed(run_dir):
        reason = "Only runs whose verifier crashed (no verdict) can be re-verified here."
    return {
        "available": reason is None,
        "unavailable_reason": reason,
    }


def _command(run_id: str, availability: Dict[str, Any]) -> list:
    return [
        sys.executable, "-m", "security_pipeline", "rerun-verifier",
        "--run", run_id,
        # Model omitted on purpose -> the pipeline default (a capable model),
        # since a small model failing the structured verdict is a common cause.
        "--workspace-root", str(config.REPO_ROOT),
        "--alerts-dir", str(config.ALERTS_DIR),
        "--runs-dir", str(config.RUNS_DIR),
    ]


VERIFIER_RERUN = run_jobs.JobKind(
    label="verifier re-run",
    subdir="verifier_rerun",
    status_name=STATUS_NAME,
    log_name=LOG_NAME,
    lock_name=LOCK_NAME,
    thread_prefix="verifier-rerun",
    availability=_availability,
    command=_command,
    result_path=lambda run_dir: run_dir / "verifier_rerun" / "results.json",
    result_key="verifier_rerun",
    # Exit 1 = the fresh verifier rejected or errored — a real, displayable
    # outcome, not a broken job. Exit 2 (could-not-attempt) is a job error.
    ok_returncodes=(0, 1),
)


def is_active(run_id: str) -> bool:
    return run_jobs.is_active(VERIFIER_RERUN, run_id)


def status(run_id: str) -> Dict[str, Any]:
    return run_jobs.status(VERIFIER_RERUN, run_id)


def start(run_id: str) -> Dict[str, Any]:
    return run_jobs.start(VERIFIER_RERUN, run_id)
