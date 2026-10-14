"""Dashboard-triggered retrofit of the verifier onto one finished run.

`baseline` gained the verifier after a batch of runs had already been recorded
without it. This runs `security-pipeline retrofit` for a single run so the
button beside that run brings it up to the current profile's standard.

It is **assess-only**, and the UI must not imply otherwise: the verifier reviews
the patch already on disk and its verdict is recorded, but the patch is never
rewritten and the run's own `status` never changes. A rejected verdict on an
accepted run is therefore information, not a contradiction — see
`security_pipeline/retrofit.py` for why re-patching is off the table (the run's
fixPOV and residual scores were computed against the diff as it stands).

All background-job bookkeeping is shared with the fixPOV replay via
`run_jobs`; only eligibility and the argv live here.
"""
from __future__ import annotations

import sys
from typing import Any, Dict

import config
import groundtruth
import run_jobs
import runs

STATUS_NAME = "retrofit_status.json"
LOG_NAME = "retrofit.log"
LOCK_NAME = "retrofit.lock"

RetrofitError = run_jobs.JobError

# Kept in step with security_pipeline.retrofit.RETROFIT_GATES. Duplicated rather
# than imported because the dashboard backend runs as a loose module tree and
# does not import the pipeline package; the CLI is still the single source of
# truth for what actually runs — this only drives the availability message.
DEFAULT_GATES = ("verifier",)


def _availability(run_id: str) -> Dict[str, Any]:
    run_dir = runs.resolve_run_dir(run_id)
    if run_dir is None:
        raise RetrofitError(f"run not found: {run_id}")
    mapping = groundtruth.ground_truth_for_run(run_id)
    if mapping is None or not mapping.get("project_slug"):
        raise RetrofitError(f"no project mapping for run: {run_id}")

    detail = runs.get_run(run_id) or {}
    # Read the raw stage names off the artifacts: get_run's `stages` is the
    # rendered rail (a list of dicts), not the recorded stage list.
    stages = set(_recorded_stages(run_dir))
    prior = detail.get("retrofit_gates") or {}
    errored = set(prior.get("errored") or ())
    # A gate already in the run's stage list has been assessed — unless the
    # retrofit itself errored on it, in which case it never really ran and the
    # CLI will retry it. Mirrors _retrofit_targets in the pipeline CLI.
    missing = [gate for gate in DEFAULT_GATES if gate not in stages or gate in errored]

    reason = None
    if detail.get("status") != "accepted":
        reason = "Only accepted runs can be retrofitted."
    elif not missing:
        reason = "This run already ran the verifier."
    return {
        "available": reason is None,
        "unavailable_reason": reason,
        "project_slug": mapping["project_slug"],
        "gates": missing or list(DEFAULT_GATES),
    }


def _recorded_stages(run_dir) -> list:
    import json

    for name in ("state.json", "verdict.json"):
        try:
            document = json.loads((run_dir / name).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(document, dict) and isinstance(document.get("stages"), list):
            return document["stages"]
    return []


def _command(run_id: str, availability: Dict[str, Any]) -> list:
    return [
        sys.executable, "-m", "security_pipeline", "retrofit",
        "--project", availability["project_slug"],
        "--run", run_id,
        # The run's own profile decides nothing here: the user asked for this
        # specific run, so profile filtering would only be able to refuse it.
        "--profile", "any",
        "--gates", ",".join(availability.get("gates") or DEFAULT_GATES),
        "--workspace-root", str(config.REPO_ROOT),
        "--alerts-dir", str(config.ALERTS_DIR),
        "--runs-dir", str(config.RUNS_DIR),
    ]


RETROFIT = run_jobs.JobKind(
    label="retrofit",
    subdir="gates",
    status_name=STATUS_NAME,
    log_name=LOG_NAME,
    lock_name=LOCK_NAME,
    thread_prefix="retrofit",
    availability=_availability,
    command=_command,
    result_path=lambda run_dir: run_dir / "gates" / "results.json",
    result_key="retrofit_gates",
    # Exit 1 means a gate failed or errored. That is a real, displayable result —
    # "this patch would not have cleared the verifier" is exactly what the button
    # is for — so it must not be reported to the UI as a broken job.
    ok_returncodes=(0, 1),
)


def is_retrofit_active(run_id: str) -> bool:
    return run_jobs.is_active(RETROFIT, run_id)


def status(run_id: str) -> Dict[str, Any]:
    return run_jobs.status(RETROFIT, run_id)


def start(run_id: str) -> Dict[str, Any]:
    return run_jobs.start(RETROFIT, run_id)
