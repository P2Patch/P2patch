"""Read and normalize pipeline run artifacts into API-friendly shapes.

Everything here is defensive: rejected runs are partial (missing agents, logs,
diffs), and ``state.json`` embeds full raw agent stdout that we must strip from
list/detail payloads and serve separately.
"""
from __future__ import annotations

import contextlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

import config
import groundtruth
from security_pipeline.stages import PROFILES

RUN_RE = re.compile(r"^\d{8}_\d{6}_finding-[0-9a-f]{12}(?:_\d+)?$")

# Canonical pipeline stage order for the workflow rail. Each stage maps to a
# step name in state.json and/or an agent; the UI renders them as a signal chain.
STAGE_ORDER = [
    ("metadata", "step", "Metadata"),
    ("worktree", "step", "Worktree"),
    ("docker_build", "step", "Docker build"),
    ("exploiter", "agent", "Exploiter"),
    ("pov_before_patch", "step", "POV before"),
    ("patcher", "agent", "Patcher"),
    ("pov_after_patch", "command", "POV after"),
    ("harden", "step", "Hardening loop"),
    ("patch_and_regression", "step", "Regression"),
    ("verifier", "agent", "Verifier"),
    ("fix_pov_eval", "step", "fixPOVs"),
    ("residual_eval", "step", "Residual gaps"),
]

# Which pipeline stage must be in the run's stage list for each rail item to
# apply. "metadata" is orchestrator setup (always shown); "POV before" is
# produced inside the exploiter stage; "Regression" is the regression stage's
# terminal step. Keeps the rail in sync with the experiment profile so a
# baseline (patcher-only) run doesn't show exploiter/verifier stages.
_RAIL_GATE = {
    "metadata": None,
    "worktree": "worktree",
    "docker_build": "docker_build",
    "exploiter": "exploiter",
    "pov_before_patch": "exploiter",
    "patcher": "patcher",
    "pov_after_patch": "pov_after",
    "harden": "harden",
    "patch_and_regression": "regression",
    "verifier": "verifier",
    "fix_pov_eval": "fix_pov_eval",
    "residual_eval": "residual_eval",
}

# The curated-POV family was renamed from "ground truth" to "fixPOV" after
# hundreds of runs had already been recorded. Run artifacts are read-only
# history, so every reader here accepts the legacy names as a fallback (never
# a preference): stage/step name, results subdir, and docker command prefix.
LEGACY_STAGE_NAMES = {"ground_truth_eval": "fix_pov_eval"}
LEGACY_STEP_NAMES = {"fix_pov_eval": "ground_truth_eval"}
_FAMILY_RESULTS_DIRS = {
    "fix_pov": ("fix_pov", "ground_truth"),
    "residual": ("residual",),
}


def eval_results_path(base_dir: Path, family: str) -> Path:
    """``<base>/<family>/results.json``, falling back to the legacy subdir for
    a run/case recorded before the fixPOV rename. The *new* path is returned
    when neither exists, so writers and freshness checks always name it."""
    candidates = _FAMILY_RESULTS_DIRS.get(family, (family,))
    for name in candidates:
        path = base_dir / name / "results.json"
        if path.is_file():
            return path
    return base_dir / candidates[0] / "results.json"


def fix_pov_results_path(base_dir: Path) -> Path:
    return eval_results_path(base_dir, "fix_pov")


def rail_stages(profile, stages):
    """The STAGE_ORDER items that apply to a run's profile / stage list.

    Prefers the run's recorded ``stages`` (exact, even for --stages overrides),
    falls back to the named profile, then to the full pipeline for legacy runs
    that recorded neither.
    """
    active = None
    if stages:
        active = {LEGACY_STAGE_NAMES.get(s, s) for s in stages}
    elif profile and profile in PROFILES:
        active = set(PROFILES[profile])
    if active is None:
        return list(STAGE_ORDER)
    # The `converge` stage runs the POV-after and regression gates together (as a
    # self-correction fix-point), emitting the same "pov_after_patch" command and
    # "patch_and_regression" step, so it lights up both of their rail items.
    if "converge" in active:
        active |= {"pov_after", "regression"}
    return [
        entry for entry in STAGE_ORDER
        if _RAIL_GATE.get(entry[0]) is None or _RAIL_GATE[entry[0]] in active
    ]

AGENT_NAMES = ("exploiter", "patcher", "verifier")
HARDENING_AGENT_RE = re.compile(r"^(exploiter|patcher)_harden_r([1-9][0-9]*)$")
# Retry agents: a patcher sent back to fix its own patch after an objective gate
# failed (optionally tagged with the gate: pov_after / regression / harden_rN),
# and an exploiter sent back after its POV did not reproduce.
RETRY_AGENT_RE = re.compile(
    r"^(?:patcher_correction(?:_[a-z0-9_]+)?|exploiter_retry)_a[1-9][0-9]*$"
)
DIFF_KINDS = {"full": "full.diff", "patch_only": "patch_only.diff", "pov": "pov.diff"}
LOG_RE = re.compile(r"^[A-Za-z0-9_]+\.log$")
# The finding hash groups every run of the same alert+project (across profiles
# and re-runs), regardless of the timestamp prefix or collision suffix.
FINDING_RE = re.compile(r"finding-[0-9a-f]{12}")
AGENT_ARTIFACT_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_state(path: Path) -> dict:
    """``state.json``, with null ``steps``/``commands`` rows dropped.

    Runs recorded before the fixPOV stage learned to guard
    ``pov["command_result"]`` (``stages.py``) wrote a literal ``null`` for every
    POV that was never executed. Run artifacts are read-only history, so those
    rows cannot be repaired in place — and every consumer here does ``c.get(...)``
    on them, which turns one legacy null into a 500 for the whole run. Filtering
    once at read time keeps that knowledge in a single place instead of asking
    each of the ten iteration sites to remember it.
    """
    state = _read_json(path) or {}
    for key in ("steps", "commands"):
        rows = state.get(key)
        if isinstance(rows, list):
            state[key] = [row for row in rows if isinstance(row, dict)]
    return state


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _valid_run_dir(run_id: str) -> Optional[Path]:
    if not RUN_RE.match(run_id):
        return None
    run_dir = (config.RUNS_DIR / run_id).resolve()
    if run_dir.parent != config.RUNS_DIR.resolve() or not run_dir.is_dir():
        return None
    return run_dir


def resolve_run_dir(run_id: str) -> Optional[Path]:
    """Public, path-safe run directory lookup for the analysis endpoints."""
    return _valid_run_dir(run_id)


class RunExportError(ValueError):
    """A requested run archive could not be created safely."""


# Chunk size for streaming a run artifact into the archive.
_EXPORT_CHUNK = 1 << 20


def _archive_regular_file(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    """Add ``path`` to the archive, reading only what the lstat check approved.

    ``zipfile.write()`` re-opens by path, so the earlier ``lstat`` and the read
    were two separate resolutions of the same name: anything that could replace
    the file with a symlink in between (a live agent still writing into the run
    directory) would have had the link followed and an arbitrary host file
    archived. Opening with ``O_NOFOLLOW`` and re-checking the descriptor closes
    that window — the bytes archived come from the object that was verified, not
    from whatever the name resolves to a moment later.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        # Vanished, rotated, or turned into a symlink since the lstat. Either way
        # it is not exportable; keep the rest of the archive useful.
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        with os.fdopen(fd, "rb", closefd=False) as source:
            with archive.open(arcname, "w") as target:
                shutil.copyfileobj(source, target, _EXPORT_CHUNK)
    except OSError:
        return
    finally:
        os.close(fd)


def export_runs(run_ids: Iterable[str]) -> tuple[Path, str]:
    """Build a portable ZIP containing one or more run directories.

    Archive members are rooted at each run ID, rather than the absolute runs
    directory. Extracting the result inside ``security_pipeline_runs/``
    therefore restores the selected runs directly. Symlinks are deliberately
    omitted: run worktrees can contain links outside the artifact directory and
    an export must never disclose or recreate files outside the selected run.

    The caller owns the returned temporary file and must remove it after it has
    been sent to the client.
    """
    unique_ids = list(dict.fromkeys(run_ids))
    if not unique_ids:
        raise RunExportError("select at least one run to export")

    run_dirs: list[Path] = []
    for run_id in unique_ids:
        run_dir = _valid_run_dir(run_id)
        if run_dir is None:
            raise RunExportError(f"run not found: {run_id}")
        run_dirs.append(run_dir)

    prefix = "p2patch-run-" if len(run_dirs) == 1 else "p2patch-runs-"
    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=".zip", delete=False) as tmp:
        archive_path = Path(tmp.name)

    try:
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for run_dir in run_dirs:
                # Retain an otherwise-empty run directory, and make the archive
                # layout explicit even when all descendants are skipped links.
                archive.writestr(f"{run_dir.name}/", "")
                for path in sorted(run_dir.rglob("*")):
                    try:
                        mode = path.lstat().st_mode
                    except OSError:
                        # A live run can remove or rotate an artifact while it is
                        # being archived. Keep the rest of the export useful.
                        continue
                    relative = path.relative_to(run_dir).as_posix()
                    arcname = f"{run_dir.name}/{relative}"
                    if stat.S_ISDIR(mode):
                        archive.writestr(f"{arcname}/", "")
                    elif stat.S_ISREG(mode):
                        _archive_regular_file(archive, path, arcname)
                    # Skip symlinks, sockets, devices, and FIFOs. See above.
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise

    filename = f"{prefix}{run_dirs[0].name if len(run_dirs) == 1 else 'selected'}.zip"
    return archive_path, filename


def remove_export(path: Path) -> None:
    """Best-effort cleanup for a temporary archive returned by ``export_runs``."""
    path.unlink(missing_ok=True)


def _timestamp(run_id: str) -> Optional[str]:
    try:
        return datetime.strptime(run_id[:15], "%Y%m%d_%H%M%S").isoformat()
    except ValueError:
        return None


def _primary_model(model_usage: dict) -> Optional[str]:
    """The main working model for an agent run.

    Claude Code's result JSON reports ``modelUsage`` for *every* model it touched,
    which always includes a small internal helper (e.g. haiku for summaries)
    alongside the real worker. Picking the first key showed haiku for every run;
    the primary model is the one with the most spend/output, so rank by that.
    """
    if not model_usage:
        return None

    def weight(item):
        v = item[1] if isinstance(item[1], dict) else {}
        return (v.get("costUSD") or 0, v.get("outputTokens") or 0)

    return max(model_usage.items(), key=weight)[0]


def _billed_provider_cost(run_dir: Optional[Path], agent_name: str) -> Optional[dict]:
    """A complete, validated provider-cost artifact for one agent, if present."""
    if run_dir is None or not AGENT_ARTIFACT_RE.fullmatch(agent_name or ""):
        return None
    payload = _read_json(run_dir / "agent_io" / agent_name / "provider_cost.json")
    if (
        not isinstance(payload, dict)
        or payload.get("provider") != "openrouter"
        or payload.get("source") != "openrouter_generation_api"
        or payload.get("complete") is not True
    ):
        return None
    cost = payload.get("cost_usd")
    if isinstance(cost, bool) or not isinstance(cost, (int, float)):
        return None
    cost = float(cost)
    if not math.isfinite(cost) or cost < 0:
        return None
    return {
        "cost_usd": cost,
        "source": str(payload.get("source") or "provider_billed"),
    }


def _claude_meta(raw_stdout: str, provider_cost: Optional[dict] = None) -> dict:
    """Pull cost / token / turn metadata out of an agent's Claude result JSON."""
    if not raw_stdout:
        return {}
    try:
        data = json.loads(raw_stdout.strip())
    except (json.JSONDecodeError, AttributeError):
        return {}
    usage = data.get("usage") or {}
    claude_cost = data.get("total_cost_usd")
    billed_cost = (provider_cost or {}).get("cost_usd")
    return {
        "duration_ms": data.get("duration_ms"),
        "duration_api_ms": data.get("duration_api_ms"),
        "num_turns": data.get("num_turns"),
        "cost_usd": billed_cost if billed_cost is not None else claude_cost,
        "cost_source": (
            (provider_cost or {}).get("source")
            if billed_cost is not None
            else "claude_cli"
        ),
        "estimated_cost_usd": claude_cost if billed_cost is not None else None,
        "stop_reason": data.get("stop_reason"),
        "is_error": data.get("is_error"),
        "model": _primary_model(data.get("modelUsage") or {}),
        "tokens": {
            "input": usage.get("input_tokens"),
            "output": usage.get("output_tokens"),
            "cache_read": usage.get("cache_read_input_tokens"),
            "cache_creation": usage.get("cache_creation_input_tokens"),
        },
    }


def _agent_summaries(state: dict, run_dir: Optional[Path] = None) -> list:
    agents = []
    for agent in state.get("agents", []):
        name = str(agent.get("agent_name") or "")
        meta = _claude_meta(
            agent.get("raw_stdout", ""),
            _billed_provider_cost(run_dir, name),
        )
        exit_code = agent.get("exit_code")
        parse_error = agent.get("parse_error")
        agents.append(
            {
                "name": agent.get("agent_name"),
                "exit_code": exit_code,
                "parse_error": None if parse_error in (None, "None") else parse_error,
                "ok": exit_code == 0 and parse_error in (None, "None"),
                "status_field": (agent.get("parsed_output") or {}).get("status")
                or (agent.get("parsed_output") or {}).get("verdict"),
                "meta": meta,
            }
        )
    return agents


def _hardening_summary(state: dict) -> Optional[dict]:
    """Compact, UI-ready account of an iterative hardening loop.

    The pipeline records every round agent/command independently and appends a
    ``harden`` step when a round settles.  Folding those records here keeps the
    live view, completed-run view, and static export on the same interpretation.
    """
    profile = state.get("profile")
    configured_stages = state.get("stages") or []
    if profile != "hardening" and "harden" not in configured_stages:
        return None

    try:
        max_rounds = int(state.get("max_hardening_rounds", 4))
    except (TypeError, ValueError):
        max_rounds = 4

    round_agents: dict[int, dict[str, str]] = {}
    for agent in state.get("agents", []):
        name = str(agent.get("agent_name") or "")
        match = HARDENING_AGENT_RE.match(name)
        if not match:
            continue
        role, round_text = match.groups()
        round_agents.setdefault(int(round_text), {})[role] = name

    command_re = re.compile(
        r"^harden_(variant_before|variant_after|original_recheck)_r([1-9][0-9]*)$"
    )
    round_commands: dict[int, dict[str, dict]] = {}
    for command in state.get("commands", []):
        name = str(command.get("name") or "")
        match = command_re.match(name)
        if not match:
            continue
        check, round_text = match.groups()
        round_commands.setdefault(int(round_text), {})[check] = {
            "name": name,
            "exit_code": command.get("exit_code"),
            "timed_out": command.get("timed_out") in (True, "True"),
        }

    harden_steps = [s for s in state.get("steps", []) if s.get("name") == "harden"]
    round_steps = {
        int(s["round"]): s
        for s in harden_steps
        if isinstance(s.get("round"), int) and s.get("round", 0) > 0
    }
    round_numbers = sorted(set(round_agents) | set(round_commands) | set(round_steps))
    failed = next((s for s in reversed(state.get("steps", [])) if s.get("name") == "failed"), None)
    touched_loop = bool(round_numbers)

    rounds = []
    for number in round_numbers:
        step = round_steps.get(number)
        if step:
            round_status = step.get("status") or "pending"
            reason = step.get("reason")
        elif failed and touched_loop and number == round_numbers[-1]:
            round_status = "failed"
            reason = failed.get("reason")
        else:
            round_status = "pending"
            reason = None
        rounds.append(
            {
                "round": number,
                "status": round_status,
                "reason": reason,
                "agents": round_agents.get(number, {}),
                "commands": round_commands.get(number, {}),
            }
        )

    terminal_step = harden_steps[-1] if harden_steps else None
    loop_status = (terminal_step or {}).get("status") or "pending"
    loop_reason = (terminal_step or {}).get("reason")
    if failed and touched_loop and loop_status not in ("stable", "max_rounds_reached"):
        loop_status = "failed"
        loop_reason = failed.get("reason")

    return {
        "max_rounds": max_rounds,
        "status": loop_status,
        "reason": loop_reason,
        "rounds_attempted": len(round_numbers),
        "rounds_hardened": sum(1 for r in rounds if r["status"] == "hardened"),
        "rounds": rounds,
    }


def _int_field(state: dict, key: str, fallback: int) -> int:
    try:
        return int(state.get(key, fallback))
    except (TypeError, ValueError):
        return fallback


def _retry_summary(state: dict) -> dict:
    """Every time the pipeline handed work back to an agent instead of rejecting.

    Two loops feed this: the patcher self-correction fix-point at each objective
    gate (``correction`` steps, tagged with the gate that failed) and the
    exploiter's POV-before retries (``exploit_retry`` steps). Both record the
    failure verbatim, and each retry has its own agent-IO folder, so the UI can
    link straight to the attempt that fixed it (or the one that ran out of budget).
    """
    steps = [s for s in state.get("steps", []) if isinstance(s, dict)]

    corrections = []
    for step in steps:
        if step.get("name") != "correction" or step.get("status") != "retry":
            continue
        stage = str(step.get("stage") or "converge")
        attempt = _int_field(step, "attempt", 1)
        corrections.append(
            {
                "gate": stage,
                "attempt": attempt,
                "failing": step.get("failing"),
                "detail": step.get("detail"),
                "agent": (
                    f"patcher_correction_a{attempt + 1}"
                    if stage == "converge"
                    else f"patcher_correction_{stage}_a{attempt + 1}"
                ),
            }
        )

    exploit_retries = []
    for step in steps:
        if step.get("name") != "exploit_retry":
            continue
        attempt = _int_field(step, "attempt", 1)
        exploit_retries.append(
            {
                "attempt": attempt,
                "failing": step.get("failing"),
                "detail": step.get("detail"),
                "agent": f"exploiter_retry_a{attempt + 1}",
            }
        )

    # Transient-API-error re-rolls (content-filter false positive, dropped
    # connection). Unlike the two loops above these are recorded on the agent
    # entry, not as steps, since they happen inside the agent runner: each agent
    # carries ``api_error_attempts`` (one message per re-roll it performed).
    api_error_retries = []
    for agent in state.get("agents", []):
        if not isinstance(agent, dict):
            continue
        messages = agent.get("api_error_attempts") or []
        if not messages:
            continue
        content_filter = any("content filter" in str(m).lower() for m in messages)
        api_error_retries.append(
            {
                "agent": agent.get("agent_name"),
                "attempts": len(messages),
                "kind": "content_filter" if content_filter else "connection",
                "detail": str(messages[-1]),
                # Whether the run went on past this agent — the retry recovered iff
                # the final attempt parsed (no parse_error / not refused).
                "recovered": not agent.get("parse_error") and not agent.get("refused"),
            }
        )

    converged = [s for s in steps if s.get("name") == "correction" and s.get("status") == "converged"]
    return {
        "max_correction_attempts": _int_field(state, "max_correction_attempts", 1),
        "max_exploit_attempts": _int_field(state, "max_exploit_attempts", 1),
        "max_api_error_attempts": _int_field(state, "max_api_error_attempts", 1),
        "patch_corrections": corrections,
        "exploit_retries": exploit_retries,
        "api_error_retries": api_error_retries,
        # Gates that reached a passing patch (each converge/pov_after/regression/
        # hardening-round loop records one), useful to distinguish "retried and
        # recovered" from "retried and ran out of budget".
        "gates_converged": [str(s.get("stage") or "converge") for s in converged],
    }


def _stage_states(state: dict, agents: list, terminal: bool, order=None) -> list:
    """Compute pass/fail/skipped/pending for each rail stage.

    ``terminal`` is True once the run has finished (accepted/rejected): any stage
    still ``pending`` at that point was never reached, so it becomes ``skipped``.
    ``order`` is the rail stage list for this run (defaults to the full pipeline).
    """
    order = order if order is not None else STAGE_ORDER
    steps = {s.get("name"): s for s in state.get("steps", [])}
    commands = {c.get("name"): c for c in state.get("commands", [])}
    agent_by_name = {a["name"]: a for a in agents}
    failed_step = steps.get("failed")
    hardening = _hardening_summary(state)

    stages = []
    for key, kind, label in order:
        status = "pending"
        detail = None
        if kind == "step":
            step = steps.get(key)
            if step is None and key in LEGACY_STEP_NAMES:
                step = steps.get(LEGACY_STEP_NAMES[key])
            if key == "harden" and hardening:
                harden_status = hardening["status"]
                if harden_status in ("stable", "max_rounds_reached"):
                    status = "pass"
                elif harden_status == "failed":
                    status = "fail"
                else:
                    # A successfully strengthened round is not the end of the
                    # loop; another bypass hunt begins until stable or capped.
                    status = "pending"
                detail = hardening.get("reason") or (
                    f"{hardening['rounds_hardened']} hardened / {hardening['max_rounds']} max"
                )
            elif step:
                step_status = step.get("status")
                if step_status in ("ok", "accepted"):
                    status = "pass"
                elif step_status in ("skipped", "errored"):
                    # Non-gating outcomes (e.g. fix_pov_eval with no manifest,
                    # or an inconclusive eval) are neutral, not pipeline failures —
                    # rendering them red would falsely flag an accepted run.
                    status = "skipped"
                else:
                    status = "fail"
                detail = step.get("reason") or step.get("command")
        elif kind == "agent":
            agent = agent_by_name.get(key)
            if agent:
                status = "pass" if agent["ok"] else "fail"
                detail = agent.get("status_field")
        elif kind == "command":
            cmd = commands.get(key)
            if cmd is not None:
                # POV-after is expected to FAIL (non-zero) once patched.
                status = "pass" if cmd.get("exit_code") != 0 and not cmd.get("timed_out") else "fail"
                detail = f"exit {cmd.get('exit_code')}"
        stages.append({"key": key, "label": label, "kind": kind, "status": status, "detail": detail})

    # On a finished run, any stage never reached is "skipped", not "pending".
    if terminal or failed_step:
        for stage in stages:
            if stage["status"] == "pending":
                stage["status"] = "skipped"
    return stages


def _artifacts(run_dir: Path) -> dict:
    diffs = {kind: (run_dir / "git" / name).exists() for kind, name in DIFF_KINDS.items()}
    logs = []
    docker_dir = run_dir / "docker"
    if docker_dir.is_dir():
        logs = sorted(p.name for p in docker_dir.glob("*.log"))
    return {"diffs": diffs, "logs": logs}


# fixPOV staging commands run to *succeed* (exit 0) — they are the build,
# not the exploit — so they must not inherit the "non-zero is good" convention.
# `gtpov_build` was missing from this set, which rendered every successful
# fixPOV build as a failed command. Runs recorded before the rename used the
# ``gtpov_`` prefix; both are accepted.
FIXPOV_COMMAND_PREFIXES = ("fixpov_", "gtpov_")
FIXPOV_STAGING_COMMANDS = frozenset(
    f"{prefix}{step}" for prefix in FIXPOV_COMMAND_PREFIXES for step in ("setup", "build")
)


def _command_expected_failure(name: str) -> bool:
    """Commands whose success condition is a non-zero exit (exploit blocked).

    fixPOV runs (``fixpov_<id>``, legacy ``gtpov_<id>``) share the exploit exit convention: a
    non-zero exit means the patch blocked that exploit path (good). Staging
    commands are excluded — they are expected to exit 0.
    """
    if name == "pov_after_patch":
        return True
    if (name or "").startswith(FIXPOV_COMMAND_PREFIXES) and name not in FIXPOV_STAGING_COMMANDS:
        return True
    return bool(
        re.match(r"^harden_(variant_after|original_recheck|final_replay)_r[1-9][0-9]*$", name or "")
    )


def _fix_pov_outcomes(run_dir: Path) -> dict:
    """``fixpov_<id>`` command name -> the evaluator's own verdict for that POV.

    "Non-zero == blocked" is only the *default* reading of a POV exit code; the
    evaluator additionally treats a timeout and the reserved harness-error exit
    code as inconclusive. Without this the command list painted an exit 2
    (build/harness error) or exit 124 (timeout) green as a blocked exploit, while
    the coverage panel right beside it correctly called the same run errored.
    """
    summary = _read_json(fix_pov_results_path(run_dir)) or {}
    # Legacy runs named the command ``gtpov_<id>``; register both spellings so
    # the outcome attaches whichever prefix the recorded command carries.
    outcomes = {
        f"{prefix}{pov.get('id')}": pov.get("outcome")
        for pov in summary.get("povs", [])
        if pov.get("id")
        for prefix in FIXPOV_COMMAND_PREFIXES
    }
    residual = _read_json(run_dir / "residual" / "results.json") or {}
    outcomes.update({
        f"respov_{pov.get('id')}": pov.get("outcome")
        for pov in residual.get("povs", [])
        if pov.get("id")
    })
    return outcomes


def _totals(agents: list) -> dict:
    cost = sum((a["meta"].get("cost_usd") or 0) for a in agents)
    turns = sum((a["meta"].get("num_turns") or 0) for a in agents)
    duration = sum((a["meta"].get("duration_ms") or 0) for a in agents)
    sources = {
        a["meta"].get("cost_source")
        for a in agents
        if a["meta"].get("cost_usd") is not None
    }
    source = next(iter(sources)) if len(sources) == 1 else ("mixed" if sources else None)
    return {
        "cost_usd": round(cost, 4),
        "cost_source": source,
        "num_turns": turns,
        "agent_duration_ms": duration,
    }


def _finding_id(run_id: str) -> Optional[str]:
    m = FINDING_RE.search(run_id)
    return m.group(0) if m else None


def _run_model(agents: list, *sources: dict) -> Optional[str]:
    """The model this run used.

    Preferred source is what the Claude CLI reported back per agent: it names
    the model that actually served the turns, resolving an alias ("sonnet") to
    the concrete id. But nothing reports it until an agent finishes, so a queued
    run, one still building its Docker image, and one whose agents all crashed
    have no such report — and rendering those as the literal word "default"
    said the opposite of the truth about a run launched on a pinned model. Fall
    back to the model the run recorded at launch (`state`/`verdict`); only a run
    predating that field, from before it was written, is genuinely unknown.
    """
    for a in agents:
        model = a.get("meta", {}).get("model")
        if model:
            return model
    for source in sources:
        requested = (source or {}).get("model")
        if requested:
            return str(requested)
    return None


def _cached_patch_eval(run_dir: Path) -> Optional[dict]:
    """Compact patch-quality score if the judge has already been run (cheap read
    of the cached result; never triggers computation). Prefers the ensemble
    median when present, else the single-sample score."""
    res = _read_json(run_dir / "analysis" / "patch_eval" / "result.json")
    if not res:
        return None
    overall = res.get("overall") or {}
    ensemble = res.get("ensemble") or {}
    ens_overall = ensemble.get("overall") or {}
    score = ens_overall.get("score_median")
    if score is None:
        score = overall.get("score")
    if score is None:
        return None
    return {
        "score": score,
        "band": overall.get("band"),
        "gates_passed": overall.get("gates_passed"),
        "samples": ensemble.get("samples"),
    }


def _eval_score(run_dir: Path, family: str):
    """Compact score for the run list payload: ``fix_pov`` or ``residual``.

    Both artifacts share a ``score`` field but mean opposite things — coverage of
    the official fix vs. hardening beyond it — so callers keep them in separate
    columns (see ``_residual_eval``).
    """
    result = _read_json(eval_results_path(run_dir, family))
    if not result:
        return None
    score = result.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return score


def _cached_fix_pov_score(run_dir: Path):
    """Compact fixPOV coverage score for the run list payload."""
    return _eval_score(run_dir, "fix_pov")


def list_runs() -> list:
    runs = []
    if not config.RUNS_DIR.is_dir():
        return runs
    for run_dir in sorted(config.RUNS_DIR.glob("*_finding-*")):
        if not run_dir.is_dir() or not RUN_RE.match(run_dir.name):
            continue
        state = _read_state(run_dir / "state.json")
        verdict = _read_json(run_dir / "verdict.json") or {}
        status = verdict.get("status") or state.get("status") or "unknown"
        # Dry runs do no real work (context/metadata only). They're launchable
        # from the Live page for plumbing checks, but they don't belong in the
        # experiment metrics — skip them so accept-rate/CWE stats stay honest.
        if status == "dry_run":
            continue
        gt = groundtruth.ground_truth_for_run(run_dir.name) or {}
        agents = _agent_summaries(state, run_dir)
        runs.append(
            {
                "run_id": run_dir.name,
                "finding_id": _finding_id(run_dir.name),
                "timestamp": _timestamp(run_dir.name),
                "status": status,
                "profile": verdict.get("profile") or state.get("profile") or "full",
                "label": verdict.get("label") or state.get("label") or "",
                "model": _run_model(agents, verdict, state),
                "reason": verdict.get("reason") or state.get("reason") or "",
                "cve_id": gt.get("cve_id"),
                "cwe_id": gt.get("cwe_id") or (state.get("project") or {}).get("cwe_id"),
                "cwe_name": gt.get("cwe_name"),
                "project_slug": gt.get("project_slug"),
                "build_system": (state.get("project") or {}).get("build_system"),
                "agents": [{"name": a["name"], "ok": a["ok"]} for a in agents],
                "totals": _totals(agents),
                "patch_eval": _cached_patch_eval(run_dir),
                "coverage_score": _cached_fix_pov_score(run_dir),
                "residual_score": _eval_score(run_dir, "residual"),
                "has_ground_truth": bool(gt),
                "official_fix_commits": len(gt.get("fix_commit_ids", [])),
                "hardening": _hardening_summary(state),
                "retrofit_gates": _retrofit_gates(run_dir, state, verdict),
            }
        )
    runs.sort(key=lambda r: r["run_id"], reverse=True)
    return runs


def _alert_trace(run_dir: Path) -> Optional[dict]:
    """The finder taint trace (source -> sink) from context.json."""
    context = _read_json(run_dir / "context.json") or {}
    alert = context.get("alert") or {}
    if not alert:
        return None
    return {"cwe_id": alert.get("cwe_id"), "vulnerabilities": alert.get("vulnerabilities", [])}


def _fix_pov_eval(run_dir: Path) -> Optional[dict]:
    """The non-gating fixPOV coverage summary for this run, if it ran.

    Returns a trimmed view of ``fix_pov/results.json`` (per-POV outcomes plus
    the aggregate score) — the raw command stdout is left in the artifact/log and
    stripped here to keep the run payload small.
    """
    summary = _read_json(fix_pov_results_path(run_dir))
    if not summary:
        return None
    povs = [
        {
            "id": pov.get("id"),
            "description": pov.get("description", ""),
            "exploit_path": pov.get("exploit_path", ""),
            "outcome": pov.get("outcome"),
            "exit_code": pov.get("exit_code"),
        }
        for pov in summary.get("povs", [])
    ]
    return {
        "total": summary.get("total"),
        "blocked": summary.get("blocked"),
        "reproduced": summary.get("reproduced"),
        "errored": summary.get("errored"),
        "score": summary.get("score"),
        "all_blocked": summary.get("all_blocked"),
        "povs": povs,
    }


def _residual_eval(run_dir: Path) -> Optional[dict]:
    """The non-gating residual-gap summary for this run, if it ran.

    Read this as a **bonus**, not a coverage gate — the opposite of
    ``_fix_pov_eval``. ``hardened_beyond_fix`` counts exploits the patch
    blocked that the *official upstream fix* leaves open (better than upstream);
    ``matches_official_fix`` counts the ones it left open exactly as upstream
    does, which is the expected, neutral result and never a failure. Field names
    are deliberately not ``blocked``/``reproduced`` so no consumer renders a high
    "reproduced" count as a red flag.
    """
    summary = _read_json(eval_results_path(run_dir, "residual"))
    if not summary:
        return None
    povs = [
        {
            "id": pov.get("id"),
            "description": pov.get("description", ""),
            "gap_summary": pov.get("gap_summary", ""),
            "exploit_path": pov.get("exploit_path", ""),
            "outcome": pov.get("outcome"),
            "exit_code": pov.get("exit_code"),
        }
        for pov in summary.get("povs", [])
    ]
    return {
        "total": summary.get("total"),
        "hardened_beyond_fix": summary.get("hardened_beyond_fix"),
        "matches_official_fix": summary.get("matches_official_fix"),
        "errored": summary.get("errored"),
        "score": summary.get("score"),
        "all_hardened": summary.get("all_hardened"),
        "residual_of": summary.get("residual_of", ""),
        "povs": povs,
    }


def _retrofit_gates(run_dir: Path, state: dict, verdict: dict) -> Optional[dict]:
    """Gates replayed against this run's patch *after* it finished, if any.

    Written by ``python -m security_pipeline retrofit`` for runs whose profile did
    not include the regression gate or the verifier when they ran. It is an
    assess-only measurement: the patch and the run's ``status`` are untouched, so
    ``gates_failed`` being non-empty on an ``accepted`` run is expected and is not
    a contradiction — it means the patch would not have cleared a gate it never
    faced. Rendered separately from the verdict for exactly that reason.
    """
    headline = verdict.get("retrofit_gates") or state.get("retrofit_gates")
    if not isinstance(headline, dict) or not headline.get("gates"):
        return None
    detail = (_read_json(run_dir / "gates" / "results.json") or {}).get("gates")
    return {
        "gates": headline.get("gates", []),
        "passed": headline.get("gates_passed", []),
        "failed": headline.get("gates_failed", []),
        "errored": headline.get("gates_errored", []),
        "all_passed": headline.get("all_gates_passed"),
        "evaluation_mode": headline.get("evaluation_mode", ""),
        "detail": detail if isinstance(detail, dict) else {},
    }


def get_run(run_id: str) -> Optional[dict]:
    run_dir = _valid_run_dir(run_id)
    if run_dir is None:
        return None
    state = _read_state(run_dir / "state.json")
    verdict = _read_json(run_dir / "verdict.json") or {}
    agents = _agent_summaries(state, run_dir)
    status = verdict.get("status") or state.get("status") or "unknown"
    terminal = status in ("accepted", "rejected", "dry_run")
    order = rail_stages(
        state.get("profile") or verdict.get("profile") or "full",
        state.get("stages") or verdict.get("stages"),
    )

    # Full parsed outputs for the detail view (raw stdout served separately).
    parsed_by_agent = {a.get("agent_name"): a.get("parsed_output") for a in state.get("agents", [])}
    for agent in agents:
        agent["parsed_output"] = parsed_by_agent.get(agent["name"])

    gt_outcomes = _fix_pov_outcomes(run_dir)
    commands = [
        {
            "name": c.get("name"),
            "command": c.get("command"),
            "exit_code": c.get("exit_code"),
            "timed_out": c.get("timed_out") in (True, "True"),
            "log": f"{c.get('name')}.log" if (run_dir / "docker" / f"{c.get('name')}.log").exists() else None,
            "expected_failure": _command_expected_failure(str(c.get("name") or "")),
            # blocked | reproduced | errored for a fixPOV run; None for
            # every other command, which keeps the plain exit-code reading.
            "outcome": gt_outcomes.get(str(c.get("name") or "")),
        }
        for c in state.get("commands", [])
    ]

    return {
        "run_id": run_id,
        "finding_id": _finding_id(run_id),
        "timestamp": _timestamp(run_id),
        "status": status,
        "profile": verdict.get("profile") or state.get("profile") or "full",
        "label": verdict.get("label") or state.get("label") or "",
        "model": _run_model(agents, verdict, state),
        "reason": verdict.get("reason") or state.get("reason") or "",
        "project": state.get("project"),
        "ground_truth": groundtruth.ground_truth_for_run(run_id),
        "fix_pov_eval": _fix_pov_eval(run_dir),
        "residual_eval": _residual_eval(run_dir),
        "retrofit_gates": _retrofit_gates(run_dir, state, verdict),
        "alert_trace": _alert_trace(run_dir),
        "stages": _stage_states(state, agents, terminal, order),
        "steps": state.get("steps", []),
        "commands": commands,
        "agents": agents,
        "totals": _totals(agents),
        "artifacts": _artifacts(run_dir),
        "hardening": _hardening_summary(state),
        "retries": _retry_summary(state),
    }


def get_agent_io(run_id: str, agent_name: str) -> Optional[dict]:
    run_dir = _valid_run_dir(run_id)
    if run_dir is None or not (
        agent_name in AGENT_NAMES
        or HARDENING_AGENT_RE.match(agent_name or "")
        or RETRY_AGENT_RE.match(agent_name or "")
    ):
        return None
    agent_dir = run_dir / "agent_io" / agent_name
    if not agent_dir.is_dir():
        return None
    raw_stdout = _read_text(agent_dir / "raw_stdout.txt") or ""
    return {
        "run_id": run_id,
        "agent": agent_name,
        "input_md": _read_text(agent_dir / "input.md"),
        "output_json": _read_json(agent_dir / "output.json"),
        "raw_stderr": _read_text(agent_dir / "raw_stderr.txt"),
        "meta": _claude_meta(raw_stdout, _billed_provider_cost(run_dir, agent_name)),
    }


def get_diff(run_id: str, kind: str) -> Optional[str]:
    run_dir = _valid_run_dir(run_id)
    if run_dir is None or kind not in DIFF_KINDS:
        return None
    return _read_text(run_dir / "git" / DIFF_KINDS[kind])


def get_log(run_id: str, name: str) -> Optional[str]:
    run_dir = _valid_run_dir(run_id)
    if run_dir is None or not LOG_RE.match(name):
        return None
    return _read_text(run_dir / "docker" / name)


class RunDeleteError(RuntimeError):
    """A run directory exists but could not be fully removed."""


def _docker_image_for_run(run_dir: Path) -> Optional[str]:
    """The image the run itself was built with, so a helper container can act
    inside the same bind mount as the same (root) user the build ran as."""
    context = _read_json(run_dir / "context.json") or {}
    tag = (context.get("docker") or {}).get("image_tag")
    if tag:
        return tag
    # Runs that crashed before context.json was written (e.g. mid-worktree-setup)
    # still have their image, named deterministically from the run dir's own
    # finding id — any image the pipeline built works equally well here, since
    # this container only ever runs `find -delete`, nothing project-specific.
    try:
        completed = subprocess.run(
            [
                "docker", "images", "-q",
                "--filter", "reference=p2patch-*",
                # Images built before the P2Patch rename still count: this
                # container only runs `find -delete`, so any pipeline image
                # works, and a host mid-migration has only the old ones.
                "--filter", "reference=simpleautosec-*",
            ],
            capture_output=True, text=True, errors="replace", timeout=10, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    image_ids = [line.strip() for line in (completed.stdout or "").splitlines() if line.strip()]
    return image_ids[0] if image_ids else None


def _force_remove_via_docker(run_dir: Path) -> None:
    """Best-effort removal of files a build container left root-owned in the
    run directory. This (dashboard backend) process is deliberately
    unprivileged (see p2patch-dashboard.service, formerly
    autosec-dashboard.service) and can never `rm` those
    directly — but it is in the `docker` group, so a throwaway container,
    running as the same root the build did, can remove them from inside the
    same bind mount that container wrote them through."""
    image = _docker_image_for_run(run_dir)
    if not image:
        return
    with contextlib.suppress(subprocess.SubprocessError, OSError):
        subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{run_dir}:/target",
                image,
                "find", "/target", "-mindepth", "1", "-delete",
            ],
            capture_output=True, text=True, errors="replace", timeout=120, check=False,
        )


def delete_run(run_id: str) -> bool:
    """Permanently remove a run directory. Path-validated: only a real run dir
    directly under RUNS_DIR can be removed (never a traversal or a sibling).

    New runs reclaim container-root-owned files back to the host user before
    they ever land here (DockerRunner.reclaim_ownership), but a run from
    before that fix — or one that crashed before reclaiming — can still have
    root-owned build output sitting in its worktree, which a plain rmtree
    silently can't touch. Fall back to a docker-assisted removal for exactly
    those leftovers rather than reporting a misleading "not found"."""
    run_dir = _valid_run_dir(run_id)
    if run_dir is None:
        return False
    shutil.rmtree(run_dir, ignore_errors=True)
    if run_dir.exists():
        _force_remove_via_docker(run_dir)
        shutil.rmtree(run_dir, ignore_errors=True)
    if run_dir.exists():
        raise RunDeleteError(
            f"could not remove {run_id}: files remain after a docker-assisted "
            "cleanup attempt (root-owned build output the backend can't touch, "
            "and no project image was available to clean it up with)"
        )
    return True


def stats() -> dict:
    runs = list_runs()
    by_status: dict = {}
    by_cwe: dict = {}
    total_cost = 0.0
    for run in runs:
        by_status[run["status"]] = by_status.get(run["status"], 0) + 1
        cwe = run.get("cwe_id") or "unknown"
        entry = by_cwe.setdefault(cwe, {"cwe_id": cwe, "cwe_name": run.get("cwe_name"), "total": 0, "accepted": 0})
        entry["total"] += 1
        if run["status"] == "accepted":
            entry["accepted"] += 1
        total_cost += run["totals"].get("cost_usd") or 0
    total = len(runs)
    accepted = by_status.get("accepted", 0)
    return {
        "total_runs": total,
        "accepted": accepted,
        "rejected": by_status.get("rejected", 0),
        "accept_rate": round(accepted / total, 3) if total else 0,
        "by_status": by_status,
        "by_cwe": sorted(by_cwe.values(), key=lambda e: e["total"], reverse=True),
        "total_cost_usd": round(total_cost, 2),
        "distinct_cves": len({r["cve_id"] for r in runs if r.get("cve_id")}),
    }
