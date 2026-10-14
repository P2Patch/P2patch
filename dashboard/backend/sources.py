"""On-demand cloning of project sources for the live launcher.

A launch can only do *real* work if the project's vulnerable source tree exists
at ``dataset/project-sources/<slug>``. Many alerts ship without that clone,
so the launcher shows them as "no sources" and only allows a dry run.

This module fetches a missing source on demand by driving the pipeline's own
``python -m security_pipeline fetch --project <slug>`` (which reads the repo URL
+ buggy commit from ``project_info.csv`` and applies the dataset's buildability
patch, if any). Each clone runs as a small background job the UI can poll:
``POST /api/sources/<slug>/clone`` starts one, ``GET /api/sources/<slug>``
reports progress. Nothing else on disk is touched — a successful job only adds
the ``project-sources/<slug>`` directory, exactly as running the fetch command
by hand would.
"""
from __future__ import annotations

import csv
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import config

SOURCES_DIR = config.DATASET_DIR / "project-sources"
CLONE_LOG_DIR = config.RUNS_DIR / ".clones"  # small per-slug clone logs

# Project slugs are ``<org>__<repo>_<CVE>_<version>`` — letters, digits and
# ``_ . -`` only. The regex is also the path-traversal guard: no separators.
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")

CLONE_TIMEOUT_S = 1800  # a large monorepo shallow-clone should still be minutes


class SourceError(Exception):
    """A clone request that cannot be honoured (bad slug / no metadata)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- clonable-slug index (from project_info.csv, refreshed on mtime change) ---
_slugs_cache: Optional[set] = None
_slugs_mtime: Optional[float] = None


def clonable_slugs() -> set:
    """Set of project slugs the fetch command knows how to clone (col 1 of the CSV)."""
    global _slugs_cache, _slugs_mtime
    csv_path = config.PROJECT_INFO_CSV
    try:
        mtime = csv_path.stat().st_mtime
    except OSError:
        return set()
    if _slugs_cache is None or mtime != _slugs_mtime:
        slugs: set = set()
        try:
            with open(csv_path, newline="") as fh:
                for i, row in enumerate(csv.reader(fh)):
                    if i == 0 or len(row) < 2:
                        continue  # header / short row
                    if row[1]:
                        slugs.add(row[1])
        except OSError:
            return _slugs_cache or set()
        _slugs_cache, _slugs_mtime = slugs, mtime
    return _slugs_cache


def is_clonable(slug: str) -> bool:
    return bool(slug) and slug in clonable_slugs()


def source_present(slug: str) -> bool:
    return (SOURCES_DIR / slug).is_dir()


# --- clone jobs --------------------------------------------------------------
class CloneJob:
    def __init__(self, slug: str) -> None:
        self.slug = slug
        self.state = "queued"  # queued | cloning | done | error
        self.started: Optional[str] = None
        self.finished: Optional[str] = None
        self.returncode: Optional[int] = None
        self.error: Optional[str] = None
        self.log_path = CLONE_LOG_DIR / f"{slug}.log"

    def record(self) -> Dict[str, Any]:
        # A directory that shows up after a failed job (cloned out-of-band, a
        # terminal fetch run, a fixed repo URL) outranks the stale error:
        # nothing else can clear it, since start_clone short-circuits on an
        # already-present source. "queued"/"cloning" are left alone — a
        # running clone creates its target directory as it works, so presence
        # alone would call a half-finished clone done.
        present = source_present(self.slug)
        state = "done" if (self.state == "error" and present) else self.state
        return {
            "project_slug": self.slug,
            "state": state,
            "present": present,
            "clonable": is_clonable(self.slug),
            "started": self.started,
            "finished": self.finished,
            "error": None if state == "done" else self.error,
            "log_tail": _tail_file(self.log_path, 14),
        }


_JOBS: Dict[str, CloneJob] = {}
_LOCK = threading.Lock()
# Cap concurrent git clones so a "clone everything missing" burst stays polite.
_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="clone")


def _tail_file(path: Path, n: int) -> List[str]:
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return []
    return lines[-n:]


def _run_job(job: CloneJob) -> None:
    job.state = "cloning"
    job.started = _now_iso()
    CLONE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(job.log_path, "w") as log:
            proc = subprocess.run(
                [sys.executable, "-m", "security_pipeline", "fetch", "--project", job.slug],
                cwd=str(config.REPO_ROOT),
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=CLONE_TIMEOUT_S,
            )
        job.returncode = proc.returncode
        if proc.returncode == 0 and source_present(job.slug):
            job.state = "done"
        else:
            job.state = "error"
            job.error = f"fetch exited {proc.returncode}"
            _cleanup_partial(job.slug)
    except subprocess.TimeoutExpired:
        job.state = "error"
        job.error = f"clone timed out after {CLONE_TIMEOUT_S}s"
        _cleanup_partial(job.slug)
    except Exception as exc:  # pragma: no cover - defensive
        job.state = "error"
        job.error = str(exc)
        _cleanup_partial(job.slug)
    finally:
        job.finished = _now_iso()


def _cleanup_partial(slug: str) -> None:
    """Remove a half-cloned dir so the target stays 'no sources' and retryable.

    Only ever runs after a job that *started* with the dir absent (start_clone
    returns early when it already exists), so this can only remove what the
    failed job itself created. ``slug`` is SLUG_RE-validated: no separators.
    """
    if not SLUG_RE.match(slug):
        return
    target = SOURCES_DIR / slug
    if target.is_dir():
        shutil.rmtree(target, ignore_errors=True)


def status(slug: str) -> Dict[str, Any]:
    """Current source/clone status for one slug (no side effects)."""
    if not SLUG_RE.match(slug):
        raise SourceError(f"invalid project slug: {slug!r}")
    with _LOCK:
        job = _JOBS.get(slug)
    if job is not None:
        return job.record()
    return {
        "project_slug": slug,
        "state": "done" if source_present(slug) else "absent",
        "present": source_present(slug),
        "clonable": is_clonable(slug),
        "started": None,
        "finished": None,
        "error": None,
        "log_tail": [],
    }


def start_clone(slug: str) -> Dict[str, Any]:
    """Kick off (or rejoin) a background clone of ``slug``; returns its status.

    Idempotent: if the source is already present it returns done; if a job is
    already running it returns that job's record instead of starting a second.
    """
    if not SLUG_RE.match(slug):
        raise SourceError(f"invalid project slug: {slug!r}")
    if source_present(slug):
        return status(slug)
    if not is_clonable(slug):
        raise SourceError(
            f"no clone metadata for {slug!r} — not listed in project_info.csv"
        )
    with _LOCK:
        job = _JOBS.get(slug)
        if job is not None and job.state in ("queued", "cloning"):
            return job.record()
        job = CloneJob(slug)
        _JOBS[slug] = job
        _EXECUTOR.submit(_run_job, job)
        return job.record()
