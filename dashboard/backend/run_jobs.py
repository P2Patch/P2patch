"""Background dashboard jobs that re-evaluate one already-finished run.

Three features need exactly the same thing: shell out to a pipeline CLI command
for a single run, off the request thread, at most once at a time, and let the
frontend poll for progress — ``fixpov replay`` (refresh a run's fixPOV
coverage after curating new POVs), ``respov replay`` (refresh its residual-gap
score), and ``retrofit`` (replay the verifier against a run recorded before its
profile included one).

The evaluation itself deliberately stays in the pipeline CLI so a
dashboard-triggered job and a terminal-triggered one share one implementation.
What lives here is the bookkeeping around it, which is where all the difficulty
turned out to be, and which is identical for both:

  * **Ownership is on disk, not in memory.** The in-memory set this replaced
    guarded one interpreter, so under more than one uvicorn worker each process
    had its own copy and two requests could evaluate the same run at once,
    racing over the staged directory, the docker logs, results.json and the
    status file. The lock lives next to the artifacts it protects.
  * **A lock whose holder is gone is reclaimed** (``_pid_alive``), so a killed
    worker cannot wedge a run forever.
  * **Every status write is tagged with the job that made it**, so a job
    finishing late cannot stamp its outcome onto a newer one.
  * **A deleted run is never resurrected.** Writing status unconditionally
    rebuilt the directory of a run deleted mid-job as a directory containing
    nothing but job bookkeeping.
  * **A job whose worker died without reporting** is surfaced as an error rather
    than as "running" forever — which would also block every future job.

``JobKind`` carries the per-feature differences: where the bookkeeping files
live, what makes a run eligible, the argv to run, and which artifact must come
back refreshed for the job to count as successful.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import config
import runs


class JobError(RuntimeError):
    """A job request that is unsafe or cannot be fulfilled."""


@dataclass(frozen=True)
class JobKind:
    """What distinguishes one background run-job from another."""

    label: str            # human name for the UI/errors ("fixPOV replay")
    subdir: str           # run_dir/<here>/ holds the status, log and lock files
    status_name: str      # e.g. "replay_status.json"
    log_name: str         # e.g. "replay.log"
    lock_name: str        # e.g. "replay.lock"
    thread_prefix: str
    # run_id -> {"available": bool, "unavailable_reason": str|None, ...extras}.
    # May raise JobError when the run cannot be addressed at all (not found, no
    # project mapping) — the API turns that into a 404 rather than a 400.
    availability: Callable[[str], Dict[str, Any]]
    # (run_id, availability) -> argv for the pipeline CLI.
    command: Callable[[str, Dict[str, Any]], list]
    # run_dir -> the artifact that must come back with a newer mtime. A command
    # that exits 0 without refreshing this did not actually evaluate anything.
    result_path: Callable[[Path], Path]
    # Key into runs.get_run(run_id) whose value is returned as the job's result.
    result_key: str
    # Exit codes that still produced a usable result. Both CLIs use 1 for
    # "finished, but something was inconclusive", which is worth displaying.
    ok_returncodes: Tuple[int, ...] = (0, 1)
    # id -> the directory the job's bookkeeping (lock/status/log) and result
    # live under. Defaults to a real `security_pipeline_runs/<run_id>`; the
    # LoopRepair fixpov/respov jobs point this at a `baselines/.../cves/<key>`
    # bundle directory instead — everything else in this module is agnostic to
    # what kind of "run" it is bookkeeping for.
    run_dir_resolver: Callable[[str], Optional[Path]] = runs.resolve_run_dir
    # id -> the detail dict `result_key` is read from for `status()`. Defaults to
    # a real pipeline run's own detail view; see `run_dir_resolver`.
    result_lookup: Callable[[str], Dict[str, Any]] = runs.get_run


# Guards the O_EXCL acquire against two threads of *this* process; cross-process
# exclusion is the on-disk lock's job.
_LOCK = threading.Lock()

# Deliberately a SEPARATE lock from _LOCK, not the same one. `start` calls
# `_executor` while already holding _LOCK, and threading.Lock is not reentrant —
# sharing it deadlocked the request thread on the very first POST, leaving the
# job wedged at "running" with no worker and no log.
_EXECUTOR_LOCK = threading.Lock()
_EXECUTORS: Dict[str, ThreadPoolExecutor] = {}


def _executor(kind: JobKind) -> ThreadPoolExecutor:
    """One small pool per kind, so a retrofit never queues behind a replay."""
    with _EXECUTOR_LOCK:
        pool = _EXECUTORS.get(kind.thread_prefix)
        if pool is None:
            pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix=kind.thread_prefix)
            _EXECUTORS[kind.thread_prefix] = pool
        return pool


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_json(path: Path) -> Optional[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by another user
    except OSError:
        return True
    return True


# --------------------------------------------------------------------------- #
# Lock ownership
# --------------------------------------------------------------------------- #


def _lock_path(kind: JobKind, run_dir: Path) -> Path:
    return run_dir / kind.subdir / kind.lock_name


def _status_path(kind: JobKind, run_dir: Path) -> Path:
    return run_dir / kind.subdir / kind.status_name


def _log_path(kind: JobKind, run_dir: Path) -> Path:
    return run_dir / kind.subdir / kind.log_name


def _lock_holder(kind: JobKind, run_dir: Path) -> Optional[dict]:
    """The live holder of the lock, clearing it if the owner is gone."""
    path = _lock_path(kind, run_dir)
    holder = _read_json(path)
    if holder is None:
        if path.exists():
            # Unreadable/truncated lock from a killed worker mid-write.
            with contextlib.suppress(OSError):
                path.unlink()
        return None
    pid = holder.get("pid")
    if isinstance(pid, int) and _pid_alive(pid):
        return holder
    with contextlib.suppress(OSError):
        path.unlink()
    return None


def _acquire(kind: JobKind, run_dir: Path, job_id: str) -> bool:
    path = _lock_path(kind, run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            if _lock_holder(kind, run_dir) is not None:
                return False
            continue  # the holder was dead and has just been cleared; retry once
        except OSError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"pid": os.getpid(), "job_id": job_id, "at": _now_iso()}, handle)
        return True
    return False


def _release(kind: JobKind, run_dir: Path, job_id: str) -> None:
    holder = _read_json(_lock_path(kind, run_dir))
    if holder is not None and holder.get("job_id") != job_id:
        return  # someone else owns it now; not ours to drop
    with contextlib.suppress(OSError):
        _lock_path(kind, run_dir).unlink()


def _owns(kind: JobKind, run_dir: Path, job_id: str) -> bool:
    holder = _read_json(_lock_path(kind, run_dir))
    return bool(holder and holder.get("job_id") == job_id)


def is_active(kind: JobKind, run_id: str) -> bool:
    """Whether a job of this kind currently owns the run.

    Deleting a run mid-job left a ghost behind: the delete succeeded, then the
    job's cleanup recreated its status file and with it a partial run directory
    that nothing would ever finish or clean up. The delete endpoint consults this
    the same way it consults the live-run registry.
    """
    run_dir = kind.run_dir_resolver(run_id)
    if run_dir is None:
        return False
    return _lock_holder(kind, run_dir) is not None


def _tail(path: Path, lines: int = 16) -> list:
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return content[-lines:]


def _run_dir_for(kind: JobKind, run_id: str) -> Path:
    run_dir = kind.run_dir_resolver(run_id)
    if run_dir is None:
        raise JobError(f"run not found: {run_id}")
    return run_dir


# --------------------------------------------------------------------------- #
# Status and execution
# --------------------------------------------------------------------------- #


def status(kind: JobKind, run_id: str) -> Dict[str, Any]:
    """Availability, job state, recent log output, and the current result."""
    run_dir = _run_dir_for(kind, run_id)
    availability = kind.availability(run_id)
    record = _read_json(_status_path(kind, run_dir)) or {"state": "absent"}
    detail = kind.result_lookup(run_id) or {}
    state = record.get("state", "absent")
    error = record.get("error")
    if state == "running" and _lock_holder(kind, run_dir) is None:
        # The worker (or the whole backend) died without reaching its cleanup.
        # Reporting "running" forever would also block every future job.
        state = "error"
        error = error or f"{kind.label} worker exited without reporting a result"
    return {
        "run_id": run_id,
        **availability,
        "state": state,
        "started_at": record.get("started_at"),
        "finished_at": record.get("finished_at"),
        "returncode": record.get("returncode"),
        "error": error,
        "log_tail": _tail(_log_path(kind, run_dir)),
        "result": detail.get(kind.result_key),
    }


def _run_job(
    kind: JobKind, run_id: str, availability: Dict[str, Any], run_dir: Path, job_id: str
) -> None:
    status_path = _status_path(kind, run_dir)
    log_path = _log_path(kind, run_dir)
    results_path = kind.result_path(run_dir)
    try:
        previous_result_mtime = results_path.stat().st_mtime_ns
    except OSError:
        previous_result_mtime = None
    returncode: Optional[int] = None
    error: Optional[str] = None
    try:
        if not run_dir.is_dir():
            # Deleted between submission and pickup. Creating the log directory
            # here would rebuild the run as a directory containing nothing but
            # job bookkeeping.
            raise JobError("run directory no longer exists")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                kind.command(run_id, availability),
                cwd=str(config.REPO_ROOT),
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        returncode = completed.returncode
        results = _read_json(results_path)
        try:
            result_refreshed = results_path.stat().st_mtime_ns != previous_result_mtime
        except OSError:
            result_refreshed = False
        # A non-zero-but-tolerated exit (something inconclusive) still produced a
        # usable result. An unrefreshed artifact means nothing was evaluated,
        # whatever the exit code claimed.
        if returncode not in kind.ok_returncodes or results is None or not result_refreshed:
            error = f"{kind.label} exited {returncode}"
    except Exception as exc:  # noqa: BLE001 - surface worker failures to the UI
        error = f"{type(exc).__name__}: {exc}"
    finally:
        # Only report if this job still owns the run and the run still exists.
        # Writing unconditionally resurrected the directory of a run that was
        # deleted while the job was in flight, and let a job that finished late
        # overwrite the status of a newer one.
        previous = _read_json(status_path) or {}
        if run_dir.is_dir() and _owns(kind, run_dir, job_id) and previous.get("job_id") in (job_id, None):
            _write_json(
                status_path,
                {
                    "state": "error" if error else "done",
                    "job_id": job_id,
                    "started_at": previous.get("started_at"),
                    "finished_at": _now_iso(),
                    "returncode": returncode,
                    "error": error,
                },
            )
        _release(kind, run_dir, job_id)


def start(kind: JobKind, run_id: str) -> Dict[str, Any]:
    """Start a job of this kind for one run, or rejoin the one already running."""
    run_dir = _run_dir_for(kind, run_id)
    availability = kind.availability(run_id)
    if not availability.get("available"):
        raise JobError(availability.get("unavailable_reason") or f"{kind.label} unavailable")

    job_id = uuid.uuid4().hex
    with _LOCK:  # keeps two threads of *this* process off the same O_EXCL race
        if not _acquire(kind, run_dir, job_id):
            return status(kind, run_id)  # already running — rejoin it
        _write_json(
            _status_path(kind, run_dir),
            {
                "state": "running",
                "job_id": job_id,
                "started_at": _now_iso(),
                "finished_at": None,
                "returncode": None,
                "error": None,
            },
        )
        try:
            _executor(kind).submit(_run_job, kind, run_id, availability, run_dir, job_id)
        except RuntimeError:
            _release(kind, run_dir, job_id)
            raise
    return status(kind, run_id)
