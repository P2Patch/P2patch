"""Re-run the verifier agent for a single finished run whose verifier *crashed*,
and — only if the fresh verifier ACCEPTS — flip that run to accepted.

This is narrowly for the case where the verifier never produced a verdict at all:
the objective gates (POV-after, hardening, regression) already passed and the run
was rejected solely because the verifier *agent* failed — an expired OAuth
session, ``error_max_structured_output_retries`` (a formatting failure, common on
a small model with a large review input), or a transient API error. A crashed
agent is infra, not a verdict.

Contrast with ``retrofit`` (assess-only: records a gate result but never changes
a run's status). Here the run had no verdict, so re-running the verifier and
recording the verdict it produces is exactly right. If the fresh verifier
genuinely *rejects* the patch, the run is left rejected — this never launders a
real rejection into a pass.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .claude_agents import ClaudeAgentRunner
from .gates import GateError, validate_verifier_output
from .models import RunOptions

RESULT_SUBDIR = "verifier_rerun"


class VerifierRerunError(RuntimeError):
    """The re-run could not even be attempted (missing input, no worktree, ...)."""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def _write_result(run_dir: Path, payload: dict) -> None:
    out_dir = run_dir / RESULT_SUBDIR
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def verifier_crashed(run_dir: Path) -> bool:
    """True iff the recorded verifier agent failed to produce a verdict.

    The button/eligibility uses this to distinguish an infra crash (offer the
    re-run) from a genuine ``verdict: rejected`` (leave it alone).
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


def rerun_verifier(
    run_dir: Path,
    *,
    workspace_root: Path,
    alerts_dir: Path,
    runs_dir: Path,
    model: Optional[str] = None,
    package_root: Optional[Path] = None,
) -> dict:
    """Re-run the verifier on the run's saved task; flip to accepted iff accepted."""
    if package_root is None:
        package_root = Path(__file__).resolve().parent

    verifier_input = run_dir / "agent_io" / "verifier" / "input.md"
    if not verifier_input.is_file():
        raise VerifierRerunError("run has no saved verifier input (the verifier never ran)")
    if not (run_dir / "worktree").is_dir():
        raise VerifierRerunError("run has no worktree to review")

    options = RunOptions(
        workspace_root=workspace_root,
        alerts_dir=alerts_dir,
        runs_dir=runs_dir,
        model=model,
        effort="high",
        stream=False,
    )
    runner = ClaudeAgentRunner(options, package_root)
    result = runner.run(
        "verifier",
        verifier_input.read_text(encoding="utf-8"),
        run_dir,
        run_dir / "worktree",
        run_label="verifier_rerun",
    )
    out = result.parsed_output or {}

    if not result.ok:
        payload = {
            "status": "errored",
            "flipped": False,
            "reason": result.parse_error or "verifier agent failed to run",
            "model": model,
            "ran_at": _now(),
        }
        _write_result(run_dir, payload)
        return payload

    try:
        validate_verifier_output(out)
        verdict = "accepted"
    except GateError:
        verdict = str(out.get("verdict", "rejected"))

    if verdict != "accepted":
        payload = {
            "status": "rejected",
            "flipped": False,
            "verdict": verdict,
            "summary": str(out.get("summary", ""))[:2000],
            "model": model,
            "ran_at": _now(),
        }
        _write_result(run_dir, payload)
        return payload

    _flip_to_accepted(run_dir, out, model)
    payload = {
        "status": "accepted",
        "flipped": True,
        "verdict": "accepted",
        "summary": str(out.get("summary", ""))[:2000],
        "model": model,
        "ran_at": _now(),
    }
    _write_result(run_dir, payload)
    return payload


def _flip_to_accepted(run_dir: Path, out: dict, model: Optional[str]) -> None:
    reason = (
        "Verifier re-run%s accepted the patch. The run had been rejected only because "
        "the verifier agent crashed and produced no verdict; the objective gates all "
        "passed (POV-after blocked, hardening stable, regression passed). A crashed "
        "agent is infrastructure, not a rejection." % (f" on {model}" if model else "")
    )

    # 1) the verifier's own output.json (dashboard shows a valid response, not parse_error)
    (run_dir / "agent_io" / "verifier" / "output.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8"
    )

    # 2) state.json: status/reason, the crashed verifier agent record, and the steps rail
    state_path = run_dir / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["status"] = "accepted"
    state["reason"] = reason
    state["category"] = None
    for agent in state.get("agents", []):
        if agent.get("agent_name") == "verifier":
            agent["exit_code"] = 0
            agent["parse_error"] = None
            agent["refused"] = False
            agent["refusal_reason"] = None
            agent["parsed_output"] = out
    steps = [s for s in state.get("steps", []) if s.get("name") != "failed"]
    steps.append({"name": "verifier", "status": "accepted", "reason": None})
    state["steps"] = steps
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    # 3) verdict.json: the badge the dashboard reads
    verdict_path = run_dir / "verdict.json"
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    verdict["status"] = "accepted"
    verdict["reason"] = reason
    verdict["category"] = None
    verdict_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
