"""Score a LoopRepair-generated patch against the pipeline's own curated
fixPOV / residual POV manifests.

LoopRepair's ``patch.diff`` is a bare unified-diff hunk with no file header at
all (no ``---``/``+++`` lines) — a format ``git apply`` cannot consume on its
own. The target file is recovered from ``verification.json``'s
``patch_location`` (an absolute in-container path, e.g.
``/data/vulnloc/libming/CVE-2016-9264/src/util/listmp3.c:105:5``) and
``bug.json``'s ``source-directory``, then a header is synthesized before
handing the patch to ``fixpov replay-patch`` / ``respov replay-patch``
(``security_pipeline/cli.py``) — the same reconstruction machinery
(``_ReplayCheckout`` + ``evaluate_manifest``) a pipeline run's own POV replay
uses, so a LoopRepair CVE and a pipeline run are measured against literally
the same certified manifests and the same Docker images.

All the background-job bookkeeping (on-disk lock, dead-holder reclamation,
job-tagged status writes, deleted-target protection) is ``run_jobs``,
unmodified from how it already backs ``fix_pov_replay``/
``residual_replay``/``retrofit_job`` — this module only supplies the
LoopRepair-specific pieces: the CVE -> project_slug mapping, the patch header
synthesis, and the CLI argv. ``run_jobs.JobKind.run_dir_resolver`` is pointed
at a CVE's ``baselines/runs/loop_repair/merged/cves/<key>/`` bundle directory
instead of a ``security_pipeline_runs/<run_id>`` — everything else in that
module is agnostic to what kind of "run" it is bookkeeping for.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import groundtruth
import loop_repair
import run_jobs
import runs

ReplayError = run_jobs.JobError

_FAMILY_LABEL = {"fixpov": "fixPOV", "respov": "residual"}
_FAMILY_RESULTS_SUBDIR = {"fixpov": "fix_pov", "respov": "residual"}


def _project_slug_for(key: str) -> Optional[str]:
    result = loop_repair.get_result(key)
    if result is None:
        return None
    row = groundtruth.project_rows().get(result["cve"])
    return row.get("project_slug") if row else None


_FAMILY_MANIFEST_DIR = {"fixpov": config.fix_povs_dir, "respov": config.residual_povs_dir}


def _manifest_path(family: str, project_slug: str) -> Path:
    return _FAMILY_MANIFEST_DIR[family]() / project_slug / "manifest.json"


def _synthesize_patch(key: str) -> "tuple[Optional[str], Optional[str]]":
    """(patch_text, error) — recover the patched file's repo-relative path and
    prepend a ``--- a/<rel>`` / ``+++ b/<rel>`` header LoopRepair's raw hunk-only
    diff is missing, so it becomes ``git apply``-able."""
    cve_dir = loop_repair._cve_dir(key)
    if cve_dir is None:
        return None, "CVE bundle directory not found"
    bug = loop_repair._read_json(cve_dir / "bug.json")
    verification = loop_repair._read_json(cve_dir / "verification.json")
    if not bug or not verification:
        return None, "bug.json or verification.json is missing"
    location = verification.get("patch_location")
    if not location:
        return None, "LoopRepair produced no patch for this CVE (patch_location is empty)"
    raw = loop_repair._read_text(cve_dir / "patch.diff")
    if not raw or not raw.strip():
        return None, "patch.diff is missing or empty"

    abs_path = location.rsplit(":", 2)[0]
    project_name = (bug.get("project") or {}).get("name", "")
    bug_name = bug.get("name", "")
    source_dir = bug.get("source-directory", "")
    prefix = f"/data/vulnloc/{project_name}/{bug_name}/{source_dir}/"
    if not abs_path.startswith(prefix):
        return None, f"patch_location does not match the expected scenario layout: {abs_path}"
    rel = os.path.normpath(abs_path[len(prefix):])
    if rel.startswith("..") or rel.startswith("/") or rel == ".":
        return None, f"patch_location resolves outside the source tree: {rel}"
    return f"--- a/{rel}\n+++ b/{rel}\n{raw}", None


def _availability(family: str, key: str) -> Dict[str, Any]:
    result = loop_repair.get_result(key)
    if result is None:
        raise ReplayError(f"loop_repair result not found: {key}")
    slug = _project_slug_for(key)
    manifest: Optional[Path] = None
    reason: Optional[str] = None
    if slug is None:
        reason = "no project_info.csv mapping found for this CVE"
    else:
        manifest = _manifest_path(family, slug)
        if not result.get("has_patch"):
            reason = "LoopRepair produced no patch for this CVE"
        elif not manifest.is_file():
            reason = f"No curated {_FAMILY_LABEL[family]} POV manifest exists for this project yet"
        else:
            _, synth_error = _synthesize_patch(key)
            reason = synth_error
    return {
        "available": reason is None,
        "unavailable_reason": reason,
        "project_slug": slug,
        "has_manifest": bool(manifest and manifest.is_file()),
    }


def _command(family: str) -> Any:
    def build(key: str, availability: Dict[str, Any]) -> List[str]:
        patch_text, err = _synthesize_patch(key)
        if err or patch_text is None:
            raise ReplayError(err or "could not synthesize a patch")
        cve_dir = loop_repair._cve_dir(key)
        if cve_dir is None:
            raise ReplayError(f"loop_repair CVE directory not found: {key}")
        staged = cve_dir / f"{family}_replay" / "staged_patch.diff"
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(patch_text, encoding="utf-8")
        out = cve_dir / _FAMILY_RESULTS_SUBDIR[family] / "results.json"
        return [
            sys.executable, "-m", "security_pipeline", family, "replay-patch",
            "--project", availability["project_slug"],
            "--patch-file", str(staged),
            "--out", str(out),
            "--label", key,
            "--workspace-root", str(config.REPO_ROOT),
            "--runs-dir", str(config.RUNS_DIR),
        ]

    return build


def _cve_dir_resolver(key: str) -> Optional[Path]:
    return loop_repair._cve_dir(key)


def _result_lookup(key: str) -> Dict[str, Any]:
    cve_dir = loop_repair._cve_dir(key)
    if cve_dir is None:
        return {}
    return {
        "fix_pov_eval": runs._fix_pov_eval(cve_dir),
        "residual_eval": runs._residual_eval(cve_dir),
    }


FIXPOV_LOOPREPAIR_REPLAY = run_jobs.JobKind(
    label="loop-repair fixPOV replay",
    subdir="fixpov_replay",
    status_name="replay_status.json",
    log_name="replay.log",
    lock_name="replay.lock",
    thread_prefix="loop-fixpov-replay",
    availability=lambda key: _availability("fixpov", key),
    command=_command("fixpov"),
    result_path=lambda cve_dir: cve_dir / "fix_pov" / "results.json",
    result_key="fix_pov_eval",
    run_dir_resolver=_cve_dir_resolver,
    result_lookup=_result_lookup,
)

RESPOV_LOOPREPAIR_REPLAY = run_jobs.JobKind(
    label="loop-repair residual replay",
    subdir="respov_replay",
    status_name="replay_status.json",
    log_name="replay.log",
    lock_name="replay.lock",
    thread_prefix="loop-respov-replay",
    availability=lambda key: _availability("respov", key),
    command=_command("respov"),
    result_path=lambda cve_dir: cve_dir / "residual" / "results.json",
    result_key="residual_eval",
    run_dir_resolver=_cve_dir_resolver,
    result_lookup=_result_lookup,
)


def is_fixpov_replay_active(key: str) -> bool:
    return run_jobs.is_active(FIXPOV_LOOPREPAIR_REPLAY, key)


def fixpov_status(key: str) -> Dict[str, Any]:
    return run_jobs.status(FIXPOV_LOOPREPAIR_REPLAY, key)


def fixpov_start(key: str) -> Dict[str, Any]:
    return run_jobs.start(FIXPOV_LOOPREPAIR_REPLAY, key)


def is_respov_replay_active(key: str) -> bool:
    return run_jobs.is_active(RESPOV_LOOPREPAIR_REPLAY, key)


def respov_status(key: str) -> Dict[str, Any]:
    return run_jobs.status(RESPOV_LOOPREPAIR_REPLAY, key)


def respov_start(key: str) -> Dict[str, Any]:
    return run_jobs.start(RESPOV_LOOPREPAIR_REPLAY, key)
