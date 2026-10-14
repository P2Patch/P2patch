"""Live run monitor — launch a pipeline run and stream its progress.

The pipeline records progress to disk as it runs: ``state.json`` is rewritten
after every stage, ``agent_io/<name>/input.md`` appears the moment an agent
starts and ``output.json`` when it finishes, and ``docker/<name>.log`` lands
after each command. Every ``claude`` / ``docker`` call is a *blocking*
subprocess, so the finest honest live signal is the **stage boundary** — which
is exactly what the dashboard's signal-rail renders.

We launch ``python -m security_pipeline run --alert ...`` as a child process,
tee its combined stdout/stderr to a log, discover the run directory it creates
(the finding-id is deterministic, so we watch for a matching dir created after
launch), and expose a Server-Sent-Events stream that emits typed events until
the run reaches a terminal verdict.

Nothing here mutates existing run artifacts; a launch only ever adds a new run
directory (exactly as the CLI would) plus a small record under ``RUNS_DIR/.live``.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import groundtruth
import runs as runs_mod
import sources
from security_pipeline.claude_agents import DEFAULT_AGENT_MODEL
from security_pipeline.metadata import load_alert
from security_pipeline.models import RunOptions
from security_pipeline.openrouter import (
    OpenRouterConfigError,
    describe_openrouter_config,
    is_openrouter_model,
)
from security_pipeline.zai import ZaiConfigError, describe_zai_config, is_zai_model
from security_pipeline.pipeline import (
    RUN_DIR_ANNOUNCEMENT,
    existing_run_dirs,
    finding_id_from_parts,
)
from security_pipeline.stages import PROFILES as PIPELINE_PROFILES
from security_pipeline.stages import PROFILE_PATCHER_EVIDENCE

# Where launch records + orchestrator logs live (sibling of the run dirs, hidden
# from the run listing which only matches ``*_finding-*``).
LIVE_DIR = config.RUNS_DIR / ".live"

ALERT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.json$")
EFFORT_ORDER = ["low", "medium", "high", "xhigh", "max"]
EFFORTS = set(EFFORT_ORDER)
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/~-]*$")
# Free-form experiment tag. Passed to the pipeline as a list arg (no shell), so
# there is no injection surface; we still bound length and forbid control chars
# so it stays a clean single-line token in the run artifacts and the UI.
LABEL_MAX = 60
LABEL_RE = re.compile(r"^[\w .\-:/#()+]+$")
HARDENING_ROUNDS_DEFAULT = 4
HARDENING_ROUNDS_MIN = 1
HARDENING_ROUNDS_MAX = 10
# Patcher self-correction budget: how many times a failing objective gate
# (POV-after, regressions, a hardening round) is handed back to the patcher.
# 1 == the old one-shot gates, where the first failure rejects the run.
CORRECTION_ATTEMPTS_DEFAULT = RunOptions.max_correction_attempts
CORRECTION_ATTEMPTS_MIN = 1
CORRECTION_ATTEMPTS_MAX = 10
# Exploiter retry budget: how many times a POV that does not reproduce on the
# unpatched code is handed back to the exploiter.
EXPLOIT_ATTEMPTS_DEFAULT = RunOptions.max_exploit_attempts
EXPLOIT_ATTEMPTS_MIN = 1
EXPLOIT_ATTEMPTS_MAX = 10
TERMINAL = {"accepted", "rejected", "dry_run", "skipped", "error"}
# Coarse *launch-lifecycle* terminal states (distinct from the pipeline verdict
# above): a launch is done once its process has exited or been cancelled.
LAUNCH_TERMINAL = {"done", "stopped", "error", "interrupted"}
# Launch ids are minted by _make_launch; this is also the path-traversal guard
# for the on-disk record lookups that back cross-restart addressing.
LAUNCH_ID_RE = re.compile(r"^launch-[0-9]+-[0-9a-f]+$")

# Persisted scheduler config (concurrency + pause flag) — the queue itself is
# reconstructed from the per-launch records, so this only holds global knobs.
SCHED_PATH = LIVE_DIR / "scheduler.json"


# ---------------------------------------------------------------------------
# Process helpers — a launch's child may outlive the backend (it is spawned in
# its own session), so liveness/stop must work by pid/pgid, not just Popen.
# ---------------------------------------------------------------------------
def _pid_alive(pid) -> bool:
    """True if a process with this pid currently exists."""
    try:
        os.kill(int(pid), 0)
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True  # exists, just not signalable by us
    return True


def _proc_cmdline(pid) -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["ps", "-p", str(int(pid)), "-o", "command="],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
        return out or None
    except (subprocess.CalledProcessError, ValueError, TypeError, OSError):
        return None


def _pid_is_ours(pid) -> bool:
    """Guard against pid reuse: only treat a pid as our run if its command line
    still looks like the pipeline we launched. Used before signalling or
    reattaching, never on the hot liveness path."""
    cmd = _proc_cmdline(pid)
    return bool(cmd and "security_pipeline" in cmd)

# One-line human descriptions of each experiment arm, surfaced in the launcher.
PROFILE_DESCRIPTIONS = {
    "full": "Exploiter → Patcher (sees the POV) → Verifier. The full hypothesis arm.",
    "baseline": "Alert-only patch — no exploiter, POV, or verifier. Judged offline.",
    "baseline_eval": "Exploiter builds the scorer but it is withheld from the patcher; same objective gates as full.",
    "no_verifier": "Everything except the LLM verifier gate.",
    "hardening": "Exploiter and patcher iterate on bypass variants until the patch is stable or the round limit is reached.",
}

# Selectable models. Values are passed verbatim to `claude --model`; aliases are
# robust across CLI versions. Empty value == the pipeline's pinned default,
# `claude_agents.DEFAULT_AGENT_MODEL` (it used to mean "no --model flag", which
# silently inherited whatever model the operator's ~/.claude/settings.json set).
# Edit this list to expose more models in the launcher.
#
# Alternate-provider rows use isolated per-run Claude Code settings rather than
# changing the operator's normal ~/.claude/settings.json. `_validate_options`
# checks their credentials up front so a misconfigured host fails at launch
# rather than inside the first agent.
MODELS = [
    {"value": "", "label": f"Default ({DEFAULT_AGENT_MODEL})", "provider": "anthropic"},
    {"value": "haiku", "label": "Haiku 4.5", "provider": "anthropic"},
    {"value": "glm-5.2", "label": "GLM 5.2 (Z.ai)", "provider": "zai"},
    {"value": "glm-5.1", "label": "GLM 5.1 (Z.ai)", "provider": "zai"},
    {
        "value": "deepseek/deepseek-v4-flash",
        "label": "DeepSeek V4 Flash (OpenRouter)",
        "provider": "openrouter",
    },
    {
        "value": "openai/gpt-5.6-luna",
        "label": "GPT-5.6 Luna (OpenRouter)",
        "provider": "openrouter",
    },
    {
        "value": "z-ai/glm-5.2:floor",
        "label": "GLM 5.2 (OpenRouter, StreamLake FP8)",
        "provider": "openrouter",
    },
    {
        "value": "z-ai/glm-5.2",
        "label": "GLM 5.2 (OpenRouter, default routing)",
        "provider": "openrouter",
    },
]


def launch_options() -> Dict[str, Any]:
    """Selectors the launcher renders: experiment profiles, efforts, models."""
    return {
        "profiles": [
            {
                "value": name,
                "stages": list(stages),
                "patcher_evidence": PROFILE_PATCHER_EVIDENCE.get(name, "full"),
                "description": PROFILE_DESCRIPTIONS.get(name, ""),
            }
            for name, stages in PIPELINE_PROFILES.items()
        ],
        "default_profile": "full",
        "efforts": list(EFFORT_ORDER),
        "models": MODELS,
        "hardening_rounds": {
            "default": HARDENING_ROUNDS_DEFAULT,
            "min": HARDENING_ROUNDS_MIN,
            "max": HARDENING_ROUNDS_MAX,
        },
        "correction_attempts": {
            "default": CORRECTION_ATTEMPTS_DEFAULT,
            "min": CORRECTION_ATTEMPTS_MIN,
            "max": CORRECTION_ATTEMPTS_MAX,
        },
        "exploit_attempts": {
            "default": EXPLOIT_ATTEMPTS_DEFAULT,
            "min": EXPLOIT_ATTEMPTS_MIN,
            "max": EXPLOIT_ATTEMPTS_MAX,
        },
    }

# Human labels for the coarse stage the run is currently working through.
STAGE_LABEL = {key: label for key, _kind, label in runs_mod.STAGE_ORDER}

# In-process registry of launches. uvicorn runs as one long-lived process, so
# this survives across requests for the life of the server; launch.json on disk
# makes launches listable/re-openable after the SSE connection drops.
_LAUNCHES: Dict[str, "Launch"] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Launch:
    def __init__(self, launch_id: str, alert_file: str, options: Dict[str, Any]) -> None:
        self.id = launch_id
        self.alert_file = alert_file
        self.options = options
        self.dir = LIVE_DIR / launch_id
        self.log_path = self.dir / "orchestrator.log"
        self.started_at = _now_iso()
        self.started_monotonic = time.monotonic()
        self.started_wall = time.time()
        self.proc: Optional[subprocess.Popen] = None
        self._log_fh = None
        self.run_id: Optional[str] = None
        self.run_dir: Optional[Path] = None
        self.finding_id: Optional[str] = options.get("finding_id")
        # Lifecycle: queued -> running -> done | stopped | error. Batch launches
        # start "queued" (the scheduler spawns them up to the concurrency limit);
        # single launches are spawned immediately.
        self.state: str = "queued"
        self.queued_at: str = self.started_at
        # Outcome parsed from the orchestrator's final summary line (covers the
        # "skipped / no run dir created" case where there is no verdict.json).
        self.summary: Optional[Dict[str, Any]] = None
        # Authoritative process identity, kept even when we no longer hold the
        # Popen (e.g. a child reattached after a backend restart). pgid lets us
        # stop the whole tree — the pipeline's docker/claude grandchildren too.
        self.pid: Optional[int] = None
        self.pgid: Optional[int] = None
        # True when rebuilt from a disk record (no live Popen) rather than spawned
        # in this process; reconciliation/stop then work purely by pid/pgid.
        self.reattached: bool = False
        # Free-form note (e.g. why a launch was reconciled on startup).
        self.note: Optional[str] = None

    # -- reconstruction --------------------------------------------------
    @classmethod
    def from_record(cls, rec: Dict[str, Any]) -> "Launch":
        """Rebuild a Launch from its persisted record (post-restart recovery)."""
        ln = cls(rec["launch_id"], rec.get("alert_file", ""), rec.get("options") or {})
        ln.state = rec.get("state", "done")
        ln.queued_at = rec.get("queued_at", ln.queued_at)
        ln.started_at = rec.get("started_at", ln.started_at)
        ln.pid = rec.get("pid")
        ln.pgid = rec.get("pgid")
        ln.run_id = rec.get("run_id")
        rd = rec.get("run_dir")
        ln.run_dir = Path(rd) if rd else None
        ln.finding_id = rec.get("finding_id") or (rec.get("options") or {}).get("finding_id")
        ln.summary = rec.get("summary")
        ln.note = rec.get("note")
        ln.reattached = True
        # monotonic clocks don't survive a process boundary; derive wall start
        # from the persisted timestamp so run-dir discovery + elapsed stay sane.
        try:
            ln.started_wall = datetime.fromisoformat(rec["started_at"]).timestamp()
        except (KeyError, ValueError, TypeError):
            pass
        return ln

    # -- persistence -----------------------------------------------------
    def record(self) -> Dict[str, Any]:
        rec = {
            "launch_id": self.id,
            "alert_file": self.alert_file,
            "options": self.options,
            "state": self.state,
            "queued_at": self.queued_at,
            "started_at": self.started_at,
            "pid": self.pid or (self.proc.pid if self.proc else None),
            "pgid": self.pgid,
            "run_id": self.run_id,
            "run_dir": str(self.run_dir) if self.run_dir else None,
            "finding_id": self.finding_id,
            "cve_id": self.options.get("cve_id"),
            "project_slug": self.options.get("project_slug"),
        }
        if self.summary is not None:
            rec["summary"] = self.summary
        if self.note is not None:
            rec["note"] = self.note
        return rec

    def persist(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "launch.json").write_text(
            json.dumps(self.record(), indent=2) + "\n", encoding="utf-8"
        )

    # -- process state ---------------------------------------------------
    def poll(self) -> Optional[int]:
        return self.proc.poll() if self.proc else None

    @property
    def alive(self) -> bool:
        # A live Popen we own is authoritative; otherwise (reattached orphan) fall
        # back to a cheap pid liveness probe. Terminal launch states are never
        # alive even if a stale pid happens to be reused.
        if self.proc is not None:
            return self.proc.poll() is None
        if self.state in LAUNCH_TERMINAL:
            return False
        return self.pid is not None and _pid_alive(self.pid)

    def signal_stop(self) -> None:
        """Terminate the run. Kills the whole process group when we can (so the
        pipeline's docker/claude children die too), guarding against pid reuse."""
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            return
        # Reattached orphan: only signal if the pid is still alive AND still ours.
        if self.pid is None or not _pid_alive(self.pid) or not _pid_is_ours(self.pid):
            return
        try:
            if self.pgid:
                os.killpg(int(self.pgid), signal.SIGTERM)
            else:
                os.kill(int(self.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, ValueError, TypeError):
            pass

    def close_log(self) -> None:
        if self._log_fh is not None:
            try:
                self._log_fh.flush()
                self._log_fh.close()
            except OSError:
                pass
            self._log_fh = None


# ---------------------------------------------------------------------------
# Targets — what can be launched
# ---------------------------------------------------------------------------
def _alert_target(alert_path: Path) -> Optional[Dict[str, Any]]:
    """Resolve one alert file into a launchable target descriptor, or None."""
    try:
        alert = load_alert(alert_path)
    except (OSError, json.JSONDecodeError):
        return None
    cve_id = alert.get("cve_id")
    row = groundtruth.project_rows().get(cve_id) if cve_id else None
    if not row:
        return None
    project_slug = row["project_slug"]
    finding_id = finding_id_from_parts(alert_path.name, project_slug, cve_id)
    source_path = config.DATASET_DIR / "project-sources" / project_slug
    prior = existing_run_dirs(config.RUNS_DIR, finding_id)
    prior_runs = []
    for d in prior:
        verdict = runs_mod._read_json(d / "verdict.json") or {}
        state = runs_mod._read_state(d / "state.json")
        status = verdict.get("status") or state.get("status") or "unknown"
        if status == "dry_run":
            continue  # dry runs never block a real run of any profile
        prior_runs.append(
            {
                "run_id": d.name,
                "profile": verdict.get("profile") or state.get("profile") or "full",
                "status": status,
            }
        )
    return {
        "alert_file": alert_path.name,
        "cve_id": cve_id,
        "cwe_id": row.get("cwe_id", "") or alert.get("cwe_id", ""),
        "cwe_name": row.get("cwe_name", ""),
        "project_slug": project_slug,
        "finding_id": finding_id,
        "sources_present": source_path.exists(),
        "clonable": sources.is_clonable(project_slug),
        "prior_runs": prior_runs,
        "prior_run_ids": [d.name for d in prior],  # retained for compatibility
        "vuln_count": len(alert.get("vulnerabilities", []) or []),
    }


def list_targets() -> List[Dict[str, Any]]:
    if not config.ALERTS_DIR.exists():
        return []
    out = []
    for alert_path in sorted(config.ALERTS_DIR.glob("*.json")):
        target = _alert_target(alert_path)
        if target:
            out.append(target)
    out.sort(key=lambda t: t["cve_id"])
    return out


# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
class LaunchError(ValueError):
    pass


def _resolve_alert(alert_file: str) -> Path:
    if not ALERT_NAME_RE.match(alert_file or ""):
        raise LaunchError(f"invalid alert file name: {alert_file!r}")
    path = (config.ALERTS_DIR / alert_file).resolve()
    if path.parent != config.ALERTS_DIR.resolve() or not path.is_file():
        raise LaunchError(f"alert not found under alerts dir: {alert_file}")
    return path


def _clean_label(label) -> str:
    """Normalize + validate a run label; returns "" when unset."""
    label = (label or "").strip()
    if not label:
        return ""
    if len(label) > LABEL_MAX:
        raise LaunchError(f"label too long (max {LABEL_MAX} characters)")
    if not LABEL_RE.match(label):
        raise LaunchError(
            "invalid label: use letters, digits, spaces or . _ - : / # ( ) +"
        )
    return label


def _validate_int_option(name, value, low, high) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LaunchError(f"{name} must be an integer")
    if not low <= value <= high:
        raise LaunchError(f"{name} must be between {low} and {high}")


def _validate_options(
    target, effort, model, profile, dry_run, max_rounds,
    max_correction_attempts=CORRECTION_ATTEMPTS_DEFAULT,
    max_exploit_attempts=EXPLOIT_ATTEMPTS_DEFAULT,
) -> None:
    if effort and effort not in EFFORTS:
        raise LaunchError(f"invalid effort: {effort!r}")
    if model and not MODEL_RE.match(model):
        raise LaunchError(f"invalid model: {model!r}")
    # A GLM model needs the operator's Z.ai settings file; check it here so the
    # launcher can say so, instead of the run failing to authenticate mid-agent.
    if is_zai_model(model) and not dry_run:
        try:
            describe_zai_config(model)
        except ZaiConfigError as exc:
            raise LaunchError(str(exc)) from None
    elif is_openrouter_model(model) and not dry_run:
        try:
            describe_openrouter_config(model)
        except OpenRouterConfigError as exc:
            raise LaunchError(str(exc)) from None
    if profile not in PIPELINE_PROFILES:
        raise LaunchError(f"invalid profile: {profile!r} (known: {', '.join(PIPELINE_PROFILES)})")
    _validate_int_option("max_rounds", max_rounds, HARDENING_ROUNDS_MIN, HARDENING_ROUNDS_MAX)
    _validate_int_option(
        "max_correction_attempts", max_correction_attempts,
        CORRECTION_ATTEMPTS_MIN, CORRECTION_ATTEMPTS_MAX,
    )
    _validate_int_option(
        "max_exploit_attempts", max_exploit_attempts,
        EXPLOIT_ATTEMPTS_MIN, EXPLOIT_ATTEMPTS_MAX,
    )
    if not dry_run and not target["sources_present"]:
        raise LaunchError(
            "project sources are not present locally — a real run needs "
            f"benchmark/dataset/project-sources/{target['project_slug']} (use dry run instead)"
        )


def _make_launch(
    alert_file, *, effort, model, profile, dry_run, skip_docker_build, rerun,
    label="", max_rounds=HARDENING_ROUNDS_DEFAULT,
    max_correction_attempts=CORRECTION_ATTEMPTS_DEFAULT,
    max_exploit_attempts=EXPLOIT_ATTEMPTS_DEFAULT,
):
    """Validate and register a queued Launch (not yet spawned)."""
    alert_path = _resolve_alert(alert_file)
    target = _alert_target(alert_path)
    if target is None:
        raise LaunchError(f"alert has no project_info mapping: {alert_file}")
    profile = profile or "full"
    _validate_options(
        target, effort, model, profile, dry_run, max_rounds,
        max_correction_attempts, max_exploit_attempts,
    )
    label = _clean_label(label)
    launch_id = f"launch-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
    options = {
        "effort": effort,
        "model": model,
        "profile": profile,
        "label": label,
        "dry_run": dry_run,
        "skip_docker_build": skip_docker_build,
        "rerun": rerun,
        "max_rounds": max_rounds,
        "max_correction_attempts": max_correction_attempts,
        "max_exploit_attempts": max_exploit_attempts,
        "cve_id": target["cve_id"],
        "cwe_id": target["cwe_id"],
        "project_slug": target["project_slug"],
        "finding_id": target["finding_id"],
    }
    ln = Launch(launch_id, alert_file, options)
    _LAUNCHES[launch_id] = ln
    ln.persist()
    return ln, target


def _build_cmd(alert_path: Path, options: Dict[str, Any]) -> List[str]:
    cmd = [
        sys.executable,
        "-u",  # unbuffered so the summary line reaches the log promptly
        "-m",
        "security_pipeline",
        "run",
        "--alert",
        str(alert_path),
        "--profile",
        options.get("profile") or "full",
        "--effort",
        options.get("effort") or "high",
        # Tee each agent's stream-json so the monitor can follow it token-by-token.
        "--stream",
    ]
    if options.get("model"):
        cmd += ["--model", options["model"]]
    if options.get("label"):
        cmd += ["--label", options["label"]]
    if options.get("dry_run"):
        cmd.append("--dry-run")
    if options.get("skip_docker_build"):
        cmd.append("--skip-docker-build")
    if options.get("rerun"):
        cmd.append("--rerun")
    cmd += ["--max-rounds", str(options.get("max_rounds", HARDENING_ROUNDS_DEFAULT))]
    cmd += [
        "--max-correction-attempts",
        str(options.get("max_correction_attempts", CORRECTION_ATTEMPTS_DEFAULT)),
        "--max-exploit-attempts",
        str(options.get("max_exploit_attempts", EXPLOIT_ATTEMPTS_DEFAULT)),
    ]
    return cmd


def _spawn(ln: Launch) -> None:
    """Start the pipeline subprocess for a queued launch."""
    alert_path = _resolve_alert(ln.alert_file)
    cmd = _build_cmd(alert_path, ln.options)
    ln.dir.mkdir(parents=True, exist_ok=True)
    ln._log_fh = open(ln.log_path, "w", encoding="utf-8", buffering=1)
    ln._log_fh.write(f"$ {' '.join(cmd)}\n\n")
    ln._log_fh.flush()
    ln.proc = subprocess.Popen(
        cmd,
        cwd=str(config.REPO_ROOT),
        stdout=ln._log_fh,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        # Own session/process group: the run survives a backend restart (so we can
        # reattach to it) and can be stopped as a whole tree via its pgid.
        start_new_session=True,
    )
    ln.pid = ln.proc.pid
    try:
        ln.pgid = os.getpgid(ln.proc.pid)
    except OSError:
        ln.pgid = ln.proc.pid  # setsid makes pgid == pid
    ln.reattached = False
    # Stamp the start clocks now that the process is really running, so run-dir
    # discovery binds the dir created at/after this moment (not enqueue time).
    ln.started_at = _now_iso()
    ln.started_monotonic = time.monotonic()
    ln.started_wall = time.time()
    ln.state = "running"
    ln.persist()


def launch(
    alert_file: str,
    *,
    effort: str = "high",
    model: Optional[str] = None,
    profile: str = "full",
    label: str = "",
    dry_run: bool = False,
    skip_docker_build: bool = False,
    rerun: bool = False,
    max_rounds: int = HARDENING_ROUNDS_DEFAULT,
    max_correction_attempts: int = CORRECTION_ATTEMPTS_DEFAULT,
    max_exploit_attempts: int = EXPLOIT_ATTEMPTS_DEFAULT,
) -> Dict[str, Any]:
    """A single, immediate run (bypasses the concurrency queue)."""
    ln, target = _make_launch(
        alert_file, effort=effort, model=model, profile=profile, label=label,
        dry_run=dry_run, skip_docker_build=skip_docker_build, rerun=rerun,
        max_rounds=max_rounds, max_correction_attempts=max_correction_attempts,
        max_exploit_attempts=max_exploit_attempts,
    )
    _spawn(ln)
    return {"launch_id": ln.id, **ln.record(), "target": target}


# ---------------------------------------------------------------------------
# Batch scheduler — queue N runs, keep <= _MAX_CONCURRENCY alive at a time
# ---------------------------------------------------------------------------
_QUEUE: List[str] = []
_MAX_CONCURRENCY = 1
_paused = False  # when true the scheduler reaps/reattaches but starts no new runs
_sched_lock = threading.Lock()
_sched_thread: Optional[threading.Thread] = None
CONCURRENCY_MAX = 8


def _load_scheduler() -> None:
    """Restore concurrency + pause flag from disk (called once on startup)."""
    global _MAX_CONCURRENCY, _paused
    try:
        rec = json.loads(SCHED_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    try:
        _MAX_CONCURRENCY = max(1, min(int(rec.get("concurrency", 1)), CONCURRENCY_MAX))
    except (TypeError, ValueError):
        pass
    _paused = bool(rec.get("paused", False))


def _save_scheduler() -> None:
    try:
        LIVE_DIR.mkdir(parents=True, exist_ok=True)
        SCHED_PATH.write_text(
            json.dumps({"concurrency": _MAX_CONCURRENCY, "paused": _paused}, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError:
        pass


def set_concurrency(n) -> int:
    global _MAX_CONCURRENCY
    try:
        _MAX_CONCURRENCY = max(1, min(int(n), CONCURRENCY_MAX))
    except (TypeError, ValueError):
        _MAX_CONCURRENCY = 1
    _save_scheduler()
    return _MAX_CONCURRENCY


def pause() -> Dict[str, Any]:
    """Hold the queue: running launches keep going, no new ones start."""
    global _paused
    _paused = True
    _save_scheduler()
    return scheduler_status()


def resume() -> Dict[str, Any]:
    """Release the queue and start pumping again."""
    global _paused
    _paused = False
    _save_scheduler()
    _ensure_scheduler()
    _pump()
    return scheduler_status()


def scheduler_status() -> Dict[str, Any]:
    """Queue + concurrency + pause snapshot for the launcher header."""
    _reap()
    with _sched_lock:
        queued = sum(1 for ln in list(_LAUNCHES.values()) if ln.state == "queued")
    return {
        "concurrency": _MAX_CONCURRENCY,
        "paused": _paused,
        "running": _running_count(),
        "queued": queued,
    }


def _running_count() -> int:
    return sum(1 for ln in list(_LAUNCHES.values()) if ln.state == "running" and ln.alive)


def _finalize_dead(ln: Launch) -> None:
    """A 'running' launch whose process is gone → settle its terminal state.

    A child we spawned and reaped in-process exited normally, so it's ``done``
    (the real verdict lives in the run dir). A reattached orphan that vanished
    without a terminal verdict was cut off mid-run → ``interrupted``. Binding the
    run id here means a restart never resurfaces a finished launch as running."""
    try:
        _discover_run_dir(ln)
    except Exception:  # noqa: BLE001
        pass
    disk_status = None
    if ln.run_dir is not None:
        verdict = runs_mod._read_json(ln.run_dir / "verdict.json") or {}
        state = runs_mod._read_state(ln.run_dir / "state.json")
        disk_status = verdict.get("status") or state.get("status")
    if ln.reattached and disk_status not in TERMINAL:
        ln.state = "interrupted"
        if ln.note is None:
            ln.note = "process ended while the backend was not attached"
    else:
        ln.state = "done"
    ln.close_log()
    ln.persist()


def _reap() -> None:
    for ln in list(_LAUNCHES.values()):
        if ln.state == "running" and not ln.alive:
            _finalize_dead(ln)


def _pump() -> None:
    """Reap finished runs and start queued ones up to the concurrency limit."""
    with _sched_lock:
        _reap()
        while not _paused and _QUEUE and _running_count() < _MAX_CONCURRENCY:
            lid = _QUEUE.pop(0)
            ln = _LAUNCHES.get(lid)
            if ln is None or ln.state != "queued":
                continue
            try:
                _spawn(ln)
            except Exception as exc:  # noqa: BLE001 - record and skip a bad launch
                ln.state = "error"
                ln.summary = {"status": "error", "reason": str(exc)}
                ln.persist()


def _scheduler_loop() -> None:
    while True:
        try:
            _pump()
        except Exception:  # noqa: BLE001 - the scheduler must never die
            pass
        time.sleep(1.5)


def _ensure_scheduler() -> None:
    global _sched_thread
    if _sched_thread is None or not _sched_thread.is_alive():
        _sched_thread = threading.Thread(target=_scheduler_loop, daemon=True, name="launch-scheduler")
        _sched_thread.start()


def _dedup(values: List[Any]) -> List[Any]:
    """Order-preserving dedup, so a repeated axis value can't double a run."""
    out: List[Any] = []
    for v in values:
        if v not in out:
            out.append(v)
    return out


def launch_batch(
    alert_files,
    *,
    concurrency: int = 1,
    effort: str = "high",
    model: Optional[str] = None,
    profile: str = "full",
    label: str = "",
    dry_run: bool = False,
    skip_docker_build: bool = False,
    rerun: bool = False,
    efforts: Optional[List[str]] = None,
    profiles: Optional[List[str]] = None,
    models: Optional[List[Optional[str]]] = None,
    max_rounds: int = HARDENING_ROUNDS_DEFAULT,
    max_correction_attempts: int = CORRECTION_ATTEMPTS_DEFAULT,
    max_exploit_attempts: int = EXPLOIT_ATTEMPTS_DEFAULT,
) -> Dict[str, Any]:
    """Queue one run per (alert × effort × profile × model) combination; the
    scheduler starts them up to ``concurrency``.

    The plural axes describe a matrix — each falls back to its singular
    counterpart when omitted, so a caller passing only the singulars still gets
    exactly one run per alert. Alerts are the outer loop, so every variant of a
    finding sits together in the queue.
    """
    global _paused
    set_concurrency(concurrency)
    _paused = False  # launching a batch means "go" — clear any prior hold
    _save_scheduler()
    eff_axis = _dedup(list(efforts)) if efforts else [effort]
    prof_axis = _dedup(list(profiles)) if profiles else [profile]
    model_axis = _dedup([m or None for m in models]) if models else [model]
    results: List[Dict[str, Any]] = []
    for af in alert_files:
        for eff in eff_axis:
            for prof in prof_axis:
                for mod in model_axis:
                    try:
                        ln, _ = _make_launch(
                            af, effort=eff, model=mod, profile=prof, label=label,
                            dry_run=dry_run, skip_docker_build=skip_docker_build, rerun=rerun,
                            max_rounds=max_rounds,
                            max_correction_attempts=max_correction_attempts,
                            max_exploit_attempts=max_exploit_attempts,
                        )
                        _QUEUE.append(ln.id)
                        results.append({"launch_id": ln.id, **ln.record()})
                    except LaunchError as exc:
                        results.append(
                            {
                                "alert_file": af,
                                "effort": eff,
                                "profile": prof,
                                "model": mod,
                                "error": str(exc),
                            }
                        )
    _ensure_scheduler()
    _pump()  # start the first slice immediately
    queued = [r for r in results if "launch_id" in r]
    return {"concurrency": _MAX_CONCURRENCY, "queued": len(queued), "launches": results}


def _load_record(launch_id: str) -> Optional[Dict[str, Any]]:
    if not LAUNCH_ID_RE.match(launch_id or ""):
        return None  # path-traversal guard (id lands in a filesystem path)
    try:
        return json.loads((LIVE_DIR / launch_id / "launch.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def get(launch_id: str) -> Optional[Launch]:
    """The in-memory launch handle, rebuilt from its disk record on a miss so a
    launch stays addressable (snapshot / stream / stop) across a backend restart."""
    ln = _LAUNCHES.get(launch_id)
    if ln is not None:
        return ln
    rec = _load_record(launch_id)
    if rec is None:
        return None
    ln = Launch.from_record(rec)
    _LAUNCHES[launch_id] = ln
    return ln


def stop(launch_id: str) -> Dict[str, Any]:
    """Stop a launch by id, whether queued, running in-process, or a reattached
    orphan — and always persist the terminal state so it survives a restart."""
    ln = get(launch_id)
    if ln is None:
        raise LaunchError(f"unknown launch: {launch_id}")
    with _sched_lock:
        if ln.state == "queued":
            if ln.id in _QUEUE:
                _QUEUE.remove(ln.id)
            ln.state = "stopped"
            ln.persist()
            return {"launch_id": launch_id, "stopped": True, "was_queued": True}
    if ln.alive:
        ln.signal_stop()
        ln.state = "stopped"
        ln.close_log()
        ln.persist()
    elif ln.state == "running":
        # Ended on its own between poll and stop — record its honest outcome.
        _finalize_dead(ln)
    return {"launch_id": launch_id, "stopped": True, "state": ln.state, "returncode": ln.poll()}


def stop_all() -> Dict[str, Any]:
    """Halt everything: stop every running launch and cancel the whole queue,
    then pause. Sweeps disk too, so an untracked queued/running record can't
    survive. This is the single 'stop the rest of the experiments' control."""
    global _paused
    stopped: set = set()
    with _sched_lock:
        _QUEUE.clear()
    for ln in list(_LAUNCHES.values()):
        if ln.state == "queued":
            ln.state = "stopped"
            ln.persist()
            stopped.add(ln.id)
        elif ln.state == "running":
            if ln.alive:
                ln.signal_stop()
            ln.state = "stopped"
            ln.close_log()
            ln.persist()
            stopped.add(ln.id)
    if LIVE_DIR.is_dir():
        for child in LIVE_DIR.glob("launch-*"):
            if child.name in _LAUNCHES:
                continue
            rec = _load_record(child.name)
            if not rec or rec.get("state") not in ("queued", "running"):
                continue
            ln = Launch.from_record(rec)
            _LAUNCHES[ln.id] = ln
            if ln.alive:
                ln.signal_stop()
            ln.state = "stopped"
            ln.persist()
            stopped.add(ln.id)
    _paused = True
    _save_scheduler()
    return {"stopped": len(stopped), "paused": True}


def recover() -> Dict[str, Any]:
    """Rebuild launch/queue state from disk after a (re)start — the crux of the
    durability fix. Called once at app startup.

    * Reattach to any run whose child is still alive (it was spawned in its own
      session, so it outlived the old backend) — we regain liveness, streaming
      and stop control instead of orphaning it.
    * Reconcile runs whose child is gone to a terminal state (done / interrupted)
      so nothing is left falsely 'running'.
    * Requeue launches that were still 'queued', but hold the scheduler *paused*
      so an unclean restart never silently resumes real API spend — the user
      resumes explicitly (or a fresh batch clears the hold).

    Terminal records are left on disk and lazy-loaded by ``get`` only on demand."""
    global _paused
    LIVE_DIR.mkdir(parents=True, exist_ok=True)
    _load_scheduler()
    reattached = reconciled = requeued = 0
    if LIVE_DIR.is_dir():
        recs = [r for r in (_load_record(c.name) for c in LIVE_DIR.glob("launch-*")) if r]
        recs.sort(key=lambda r: r.get("queued_at") or r.get("started_at") or "")
        for rec in recs:
            state = rec.get("state")
            if state not in ("queued", "running"):
                continue
            ln = Launch.from_record(rec)
            _LAUNCHES[ln.id] = ln
            if state == "running":
                if ln.pid and _pid_alive(ln.pid) and _pid_is_ours(ln.pid):
                    ln.note = "reattached after backend restart"
                    ln.persist()
                    reattached += 1
                else:
                    _finalize_dead(ln)
                    reconciled += 1
            else:  # queued
                _QUEUE.append(ln.id)
                requeued += 1
    if requeued:
        _paused = True  # safety: hold the recovered queue until the user resumes
        _save_scheduler()
    _ensure_scheduler()
    _pump()  # reattached runs count toward concurrency; queue stays held if paused
    return {
        "reattached": reattached,
        "reconciled": reconciled,
        "requeued": requeued,
        "paused": _paused,
        "concurrency": _MAX_CONCURRENCY,
    }


def launch_for_run(run_id: str) -> Optional[str]:
    """The launch id that produced a given run, if we can find it."""
    for ln in list(_LAUNCHES.values()):
        if ln.run_id == run_id:
            return ln.id
    if LIVE_DIR.is_dir():
        for child in LIVE_DIR.glob("launch-*"):
            rec = _load_record(child.name)
            if rec and rec.get("run_id") == run_id:
                return rec.get("launch_id")
    return None


def is_run_active(run_id: str) -> bool:
    return any(ln.alive and ln.run_id == run_id for ln in list(_LAUNCHES.values()))


def stop_run(run_id: str) -> Dict[str, Any]:
    lid = launch_for_run(run_id)
    if lid is None:
        raise LaunchError(f"no launch found for run: {run_id}")
    return stop(lid)


def list_launches(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """All launches in this session (live state, including queued) merged with
    recent disk records from prior sessions. `limit` of None/0 returns every
    launch — truncating hides active runs, since a batch sorts newest-queued
    first while the scheduler starts the oldest-queued ones."""
    _reap()
    seen: Dict[str, Dict[str, Any]] = {}
    for lid, ln in list(_LAUNCHES.items()):
        rec = ln.record()
        rec["is_running"] = ln.alive
        seen[lid] = rec
    if LIVE_DIR.is_dir():
        for child in sorted(LIVE_DIR.glob("launch-*"), reverse=True):
            rec = _load_record(child.name)
            if not rec:
                continue
            lid = rec.get("launch_id")
            if lid and lid not in seen:
                rec.setdefault("state", "done")
                rec["is_running"] = False
                seen[lid] = rec
    out = sorted(
        seen.values(),
        key=lambda r: r.get("queued_at") or r.get("started_at") or "",
        reverse=True,
    )
    return out[:limit] if limit else out


# ---------------------------------------------------------------------------
# Snapshot — derive a live view from what's on disk right now
# ---------------------------------------------------------------------------
def _summary_from_log(log_text: str) -> Optional[Dict[str, Any]]:
    """The orchestrator prints one JSON object per alert outcome; take the last."""
    found = None
    for line in log_text.splitlines():
        line = line.strip()
        if not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "status" in obj and "run_id" in obj:
            found = obj
    return found


_RUN_DIR_LINE_RE = re.compile(
    rf"^{re.escape(RUN_DIR_ANNOUNCEMENT)}(.+)$", re.MULTILINE
)


def _announced_run_dir_name(log_text: str) -> Optional[str]:
    """The run directory the child itself named, from its own log."""
    for line in reversed(_RUN_DIR_LINE_RE.findall(log_text or "")):
        name = Path(line.strip()).name
        # Name only, checked against the run-id shape; the caller resolves it
        # under RUNS_DIR, so a log line can never point outside it.
        if runs_mod.RUN_RE.match(name):
            return name
    return None


def _bound_to_another_profile(ln: Launch) -> bool:
    """The run this launch is bound to records a profile it never asked for."""
    want = ln.options.get("profile")
    if not want or ln.run_dir is None:
        return False
    profile = (runs_mod._read_json(ln.run_dir / "state.json") or {}).get("profile")
    return bool(profile) and profile != want


def _guess_run_dir(ln: Launch) -> Optional[Path]:
    """Fallback for a run too old to announce itself: newest plausible match.

    Deliberately conservative, because the finding id does not distinguish runs
    of the same alert: a dir already bound to another launch, or whose recorded
    profile is not the one we asked for, is never ours. Without those two
    filters a launch bound whatever was newest — typically the run that had just
    finished in the slot before it, whose directory mtime is still fresh — and
    two monitors rendered the same run.
    """
    fid = ln.finding_id
    if not fid:
        return None
    claimed = {other.run_id for other in _LAUNCHES.values() if other is not ln and other.run_id}
    want_profile = ln.options.get("profile")
    # Candidates are sorted ascending by name (timestamp-prefixed) so the last
    # qualifying one is the newest.
    best: Optional[Path] = None
    for d in existing_run_dirs(config.RUNS_DIR, fid):
        if d.name in claimed:
            continue
        try:
            mtime = d.stat().st_mtime
        except OSError:
            continue
        # Created at/after our launch (2s clock skew).
        if mtime + 2 < ln.started_wall:
            continue
        profile = (runs_mod._read_json(d / "state.json") or {}).get("profile")
        if want_profile and profile and profile != want_profile:
            continue
        best = d
    return best


def _discover_run_dir(ln: Launch, log_text: Optional[str] = None) -> Optional[Path]:
    """Bind the run dir this launch's own child created.

    Prefers the announcement the child prints when it claims the directory —
    exact, and immune to two runs of the same alert overlapping — and falls back
    to the timestamp heuristic for runs started before that line existed.

    A binding is normally made once and kept, but a wrong one is *repaired*
    rather than lived with: a launch that guessed before its child got far enough
    would otherwise render another run's stages for the rest of its life, and
    leave its own run with no launch pointing at it (``launch_for_run``).
    """
    if log_text is None:
        try:
            log_text = ln.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
    announced = _announced_run_dir_name(log_text)
    if ln.run_dir is not None:
        corrected: Optional[Path] = None
        if announced and announced != ln.run_dir.name:
            corrected = runs_mod._valid_run_dir(announced)
        elif _bound_to_another_profile(ln):
            # Pre-announcement records: a hardening launch showing a baseline run
            # is provably not its own, so re-run discovery for it.
            corrected = _guess_run_dir(ln)
        if corrected is not None and corrected != ln.run_dir:
            ln.run_id, ln.run_dir = corrected.name, corrected
            ln.persist()
        return ln.run_dir
    best = runs_mod._valid_run_dir(announced) if announced else _guess_run_dir(ln)
    if best is not None:
        ln.run_id = best.name
        ln.run_dir = best
        ln.persist()
    return best


def _running_agent(run_dir: Path, key: str) -> bool:
    agent_dir = run_dir / "agent_io" / key
    return (agent_dir / "input.md").exists() and not (agent_dir / "output.json").exists()


def _running_labeled_agent(run_dir: Path, matches) -> Optional[str]:
    """The most recently started labeled agent still working, if any.

    Labeled agents (hardening rounds, correction/retry attempts) each get their
    own ``agent_io/<label>`` folder, so "started but not finished" is
    input.md-without-output.json, and the newest such folder is the live one.
    """
    io_root = run_dir / "agent_io"
    if not io_root.is_dir():
        return None
    active: List[tuple[float, str]] = []
    for child in io_root.iterdir():
        if not child.is_dir() or not matches(child.name):
            continue
        input_path = child / "input.md"
        if not input_path.exists() or (child / "output.json").exists():
            continue
        try:
            started = input_path.stat().st_mtime
        except OSError:
            started = 0.0
        active.append((started, child.name))
    return max(active)[1] if active else None


# A transient-API-error re-roll runs in ``<label>_apierr_a<N>`` (see
# ClaudeAgentRunner.run). It belongs to the same rail stage as its base label, so
# stripping the suffix lets every matcher below attribute the in-flight re-roll to
# the right stage instead of leaving the rail looking stalled during it.
_APIERR_SUFFIX_RE = re.compile(r"_apierr_a[1-9][0-9]*$")


def _base_label(name: str) -> str:
    return _APIERR_SUFFIX_RE.sub("", name)


def _running_hardening_agent(run_dir: Path) -> Optional[str]:
    """Return the labeled per-round agent currently working, if any."""
    return _running_labeled_agent(
        run_dir, lambda name: bool(runs_mod.HARDENING_AGENT_RE.match(_base_label(name)))
    )


# A stage whose first-pass agent has finished may still be in flight because the
# gate sent the work back: the exploiter re-doing a POV that did not reproduce,
# or the patcher fixing a patch that failed the POV-after / regression gate.
_RETRY_AGENT_PREFIX = {
    "exploiter": "exploiter_retry_a",
    "pov_before_patch": "exploiter_retry_a",
    "pov_after_patch": "patcher_correction",
    "patch_and_regression": "patcher_correction",
}


def _active_agent_for_stage(run_dir: Path, stage_key: str) -> Optional[str]:
    if stage_key == "harden":
        return _running_hardening_agent(run_dir)
    if _running_agent(run_dir, stage_key):
        return stage_key
    # A transient-API-error re-roll of the base agent runs in
    # ``<stage_key>_apierr_a<N>`` (only reached once the blocked base attempt has
    # written its output.json, so it never shadows the ``_running_agent`` check
    # above). Correction/hardening re-rolls are caught by the prefix / hardening
    # matchers, which strip the same suffix.
    base_retry = _running_labeled_agent(
        run_dir, lambda name: name != stage_key and _base_label(name) == stage_key
    )
    if base_retry:
        return base_retry
    prefix = _RETRY_AGENT_PREFIX.get(stage_key)
    if prefix:
        return _running_labeled_agent(run_dir, lambda name: name.startswith(prefix))
    return None


def live_stages(run_dir: Path, state: dict, terminal: bool) -> tuple[list, Optional[str]]:
    """Signal-rail stages with a live 'running' marker for the current stage.

    Reuses the same pass/fail logic the run-detail view uses, then overlays a
    single 'running' stage: the first stage not yet resolved (sequential
    pipeline), refined by agent input/output markers for precision.
    """
    agents = runs_mod._agent_summaries(state, run_dir)
    order = runs_mod.rail_stages(state.get("profile") or "full", state.get("stages"))
    stages = runs_mod._stage_states(state, agents, terminal=False, order=order)
    running_key: Optional[str] = None

    if terminal:
        for stage in stages:
            if stage["status"] == "pending":
                stage["status"] = "skipped"
        return stages, None

    for stage in stages:
        if stage["status"] == "pass":
            continue
        # A gate that just failed is not a verdict while the agent that owns it is
        # being sent back to fix it — show the retry in flight, not the failure.
        if stage["status"] == "fail":
            retrying = _active_agent_for_stage(run_dir, stage["key"])
            if not retrying:
                continue
            stage["status"] = "running"
            stage["detail"] = f"{retrying} working…"
            running_key = stage["key"]
            break
        # First unresolved stage is the one in flight.
        stage["status"] = "running"
        running_key = stage["key"]
        active_agent = _active_agent_for_stage(run_dir, stage["key"])
        if active_agent:
            stage["detail"] = f"{active_agent} working…"
        break

    return stages, running_key


def _agent_elapsed(run_dir: Path, key: str) -> Optional[float]:
    agent_name = _active_agent_for_stage(run_dir, key) or key
    inp = run_dir / "agent_io" / agent_name / "input.md"
    if inp.exists():
        try:
            return max(0.0, time.time() - inp.stat().st_mtime)
        except OSError:
            return None
    return None


def _tail(parts: List[str], limit: int) -> str:
    joined = "".join(parts)
    return joined[-limit:] if len(joined) > limit else joined


def _agent_activity(run_dir: Path, key: str) -> Optional[Dict[str, Any]]:
    """Fold an agent's stream.jsonl into a compact 'what is it doing now' view.

    Present only when the pipeline ran with ``--stream``. We accumulate the
    thinking / response deltas, count turns and tool uses, and track the current
    phase so the UI can show the agent working in real time (the original brief:
    watch it the way Claude Code shows its own process). Returns tails, not the
    full transcript, to keep each SSE frame small.
    """
    path = run_dir / "agent_io" / key / "stream.jsonl"
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    thinking: List[str] = []
    text: List[str] = []
    tools: List[str] = []
    turns = 0
    phase = "starting"
    done = False
    output_tokens: Optional[int] = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        etype = e.get("type")
        if etype == "stream_event":
            ev = e.get("event", {})
            sub = ev.get("type")
            if sub == "content_block_start":
                cb = ev.get("content_block", {})
                cbt = cb.get("type")
                if cbt == "tool_use":
                    name = cb.get("name") or "tool"
                    tools.append(name)
                    phase = f"tool:{name}"
                elif cbt == "thinking":
                    phase = "thinking"
                elif cbt == "text":
                    phase = "responding"
            elif sub == "content_block_delta":
                delta = ev.get("delta", {})
                dt = delta.get("type")
                if dt == "thinking_delta":
                    thinking.append(delta.get("thinking", ""))
                    phase = "thinking"
                elif dt == "text_delta":
                    text.append(delta.get("text", ""))
                    phase = "responding"
            elif sub == "message_delta":
                usage = ev.get("usage") or {}
                if usage.get("output_tokens") is not None:
                    output_tokens = usage["output_tokens"]
        elif etype == "assistant":
            turns += 1
        elif etype == "result":
            done = True
            phase = "done"
            usage = e.get("usage") or {}
            if usage.get("output_tokens") is not None:
                output_tokens = usage["output_tokens"]

    return {
        "agent": key,
        "phase": phase,
        "turns": turns,
        "tool_count": len(tools),
        "recent_tools": tools[-6:],
        "thinking_tail": _tail(thinking, 700),
        "text_tail": _tail(text, 900),
        "output_tokens": output_tokens,
        "done": done,
    }


# Every labeled agent folder a retry/correction attempt can occupy. The stage
# rail already understood these (``_RETRY_AGENT_PREFIX``); the activity pane did
# not, so token counts and tool output went blank for the whole of a retry — the
# longest stretch of a run and exactly when someone is watching.
_LABELED_AGENT_PREFIXES = ("exploiter_retry_a", "patcher_correction")


def _live_agent_activity(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Activity for the agent that is currently in flight (input started, no output)."""
    labeled = _running_hardening_agent(run_dir) or _running_labeled_agent(
        run_dir, lambda name: name.startswith(_LABELED_AGENT_PREFIXES)
    )
    candidates = ([labeled] if labeled else []) + list(runs_mod.AGENT_NAMES)
    for akey in candidates:
        if _running_agent(run_dir, akey):
            return _agent_activity(run_dir, akey)
    return None


def _live_hardening_summary(run_dir: Path, state: dict) -> Optional[Dict[str, Any]]:
    """Augment persisted hardening history with an agent that is mid-round."""
    summary = runs_mod._hardening_summary(state)
    if summary is None:
        return None
    active = _running_hardening_agent(run_dir)
    summary["active_agent"] = active
    if not active:
        return summary
    match = runs_mod.HARDENING_AGENT_RE.match(active)
    if not match:
        return summary
    number = int(match.group(2))
    round_entry = next((r for r in summary["rounds"] if r["round"] == number), None)
    if round_entry is None:
        round_entry = {"round": number, "status": "running", "reason": None, "agents": {}, "commands": {}}
        summary["rounds"].append(round_entry)
        summary["rounds"].sort(key=lambda r: r["round"])
        summary["rounds_attempted"] = len(summary["rounds"])
    round_entry["status"] = "running"
    round_entry["active_agent"] = active
    round_entry["agents"][match.group(1)] = active
    summary["status"] = "running"
    return summary


def _queued_snapshot(ln: Launch) -> Dict[str, Any]:
    """A launch waiting in the batch queue: no process, no run dir yet."""
    return {
        "launch_id": ln.id,
        "alert_file": ln.alert_file,
        "options": ln.options,
        "state": ln.state,
        "started_at": ln.started_at,
        "elapsed_seconds": 0,
        "alive": False,
        "returncode": None,
        "run_id": None,
        "run_dir": None,
        "status": "queued",
        "reason": "waiting for a free slot",
        "terminal": False,
        "stages": [],
        "running_stage": None,
        "running_stage_label": None,
        "running_stage_elapsed": None,
        "steps": [],
        "commands": [],
        "agents": [],
        "agent_activity": None,
        "hardening": None,
        "summary": None,
        "log_bytes": 0,
    }


def snapshot(ln: Launch) -> Dict[str, Any]:
    """Everything the client needs to render the live monitor right now."""
    if ln.state == "queued":
        return _queued_snapshot(ln)
    alive = ln.alive
    returncode = ln.poll()

    log_text = ""
    try:
        log_text = ln.log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    # The log carries the child's own run-dir announcement, so read it first.
    run_dir = _discover_run_dir(ln, log_text)
    summary = _summary_from_log(log_text)
    if summary:
        ln.summary = summary

    status = "running"
    reason = ""
    stages: list = []
    running_key: Optional[str] = None
    steps: list = []
    commands: list = []
    agents: list = []
    running_elapsed: Optional[float] = None
    agent_activity: Optional[Dict[str, Any]] = None
    hardening: Optional[Dict[str, Any]] = None
    retries: Optional[Dict[str, Any]] = None
    terminal = False

    if run_dir is not None:
        state = runs_mod._read_state(run_dir / "state.json")
        verdict = runs_mod._read_json(run_dir / "verdict.json") or {}
        disk_status = verdict.get("status") or state.get("status") or "running"
        # A reattached orphan has no Popen, so returncode is always None; treat
        # "not alive with no live handle" as ended too, else the view never settles.
        terminal = disk_status in ("accepted", "rejected", "dry_run") or (
            not alive and (returncode is not None or ln.proc is None)
        )
        status = disk_status if disk_status in TERMINAL else ("running" if alive else disk_status)
        reason = verdict.get("reason") or state.get("reason") or ""
        stages, running_key = live_stages(run_dir, state, terminal=terminal and disk_status in TERMINAL)
        steps = state.get("steps", [])
        agents = runs_mod._agent_summaries(state, run_dir)
        commands = [
            {
                "name": c.get("name"),
                "exit_code": c.get("exit_code"),
                "timed_out": c.get("timed_out") in (True, "True"),
            }
            for c in state.get("commands", [])
        ]
        if running_key:
            running_elapsed = _agent_elapsed(run_dir, running_key)
        if not (terminal and disk_status in TERMINAL):
            agent_activity = _live_agent_activity(run_dir)
        hardening = _live_hardening_summary(run_dir, state)
        retries = runs_mod._retry_summary(state)
    elif not alive and summary:
        # No run dir was ever created (e.g. skipped, or a pre-run error).
        status = summary.get("status", "error")
        reason = summary.get("reason", "")
        ln.run_id = summary.get("run_id") or ln.run_id

    is_terminal = terminal or (status in TERMINAL) or (not alive and run_dir is None)

    return {
        "launch_id": ln.id,
        "alert_file": ln.alert_file,
        "options": ln.options,
        "state": ln.state,
        "started_at": ln.started_at,
        "elapsed_seconds": round(max(0.0, time.time() - ln.started_wall), 1),
        "alive": alive,
        "returncode": returncode,
        "run_id": ln.run_id,
        "run_dir": str(run_dir) if run_dir else None,
        "status": status,
        "reason": reason,
        "terminal": is_terminal,
        "stages": stages,
        "running_stage": running_key,
        "running_stage_label": STAGE_LABEL.get(running_key) if running_key else None,
        "running_stage_elapsed": round(running_elapsed, 1) if running_elapsed is not None else None,
        "steps": steps,
        "commands": commands,
        "agents": agents,
        "agent_activity": agent_activity,
        "hardening": hardening,
        "retries": retries,
        "summary": summary,
        "log_bytes": len(log_text.encode("utf-8")),
    }


def _signature(snap: Dict[str, Any]) -> str:
    """Cheap change key so we only push a 'state' event when something moves."""
    return json.dumps(
        {
            "status": snap["status"],
            "run_id": snap["run_id"],
            "running": snap["running_stage"],
            "stages": [(s["key"], s["status"]) for s in snap["stages"]],
            "agents": [(a["name"], a["ok"]) for a in snap["agents"]],
            "commands": [(c["name"], c["exit_code"]) for c in snap["commands"]],
            "hardening": (
                snap.get("hardening", {}).get("status") if snap.get("hardening") else None,
                [
                    (r.get("round"), r.get("status"))
                    for r in (snap.get("hardening") or {}).get("rounds", [])
                ],
            ),
            # A retry replaces an agent that already "finished", so without this
            # the rail would sit still while the exploiter/patcher redoes its work.
            "retries": (
                len((snap.get("retries") or {}).get("patch_corrections", [])),
                len((snap.get("retries") or {}).get("exploit_retries", [])),
            ),
            "terminal": snap["terminal"],
        },
        sort_keys=True,
    )


def _sse(event: str, data: Any) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def stream(ln: Launch):
    """Async SSE generator: log lines + state snapshots until terminal."""
    yield _sse("hello", {"launch_id": ln.id, "started_at": ln.started_at, "options": ln.options})

    log_offset = 0
    last_sig: Optional[str] = None
    last_activity_sig: Optional[str] = None
    idle_ticks = 0
    grace_polls = 3  # keep polling briefly after the process exits so the final
    #                  state.json / verdict.json is picked up

    while True:
        # 1) incremental orchestrator log
        try:
            with open(ln.log_path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(log_offset)
                chunk = fh.read()
                log_offset = fh.tell()
        except OSError:
            chunk = ""
        if chunk:
            yield _sse("log", {"text": chunk})

        # 2) state snapshot on structural change
        snap = snapshot(ln)
        sig = _signature(snap)
        if sig != last_sig:
            last_sig = sig
            yield _sse("state", snap)
            idle_ticks = 0
        else:
            idle_ticks += 1

        # 3) agent activity — its own frame so the streaming text can update every
        #    tick without re-pushing the whole state payload
        act = snap.get("agent_activity")
        act_sig = json.dumps(act, sort_keys=True) if act else None
        if act_sig != last_activity_sig:
            last_activity_sig = act_sig
            if act:
                yield _sse("agent", act)
                idle_ticks = 0

        # 4) terminal → flush and finish
        if snap["terminal"]:
            grace_polls -= 1
            if grace_polls <= 0:
                # final drain of the log
                try:
                    with open(ln.log_path, "r", encoding="utf-8", errors="replace") as fh:
                        fh.seek(log_offset)
                        tail = fh.read()
                        log_offset = fh.tell()
                    if tail:
                        yield _sse("log", {"text": tail})
                except OSError:
                    pass
                ln.close_log()
                yield _sse("done", snap)
                return

        # keepalive comment when nothing is moving
        if idle_ticks and idle_ticks % 12 == 0:
            yield ": keepalive\n\n"

        await asyncio.sleep(1.0)
