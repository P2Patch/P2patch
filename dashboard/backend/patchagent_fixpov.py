"""Re-score one PatchAgent patch against our curated fixPOVs / residual POVs.

The sibling of ``san2patch_fixpov.py``, and identical in structure: the same
``fixpov replay-patch`` CLI, the same certified manifests, the same Docker images and the
same ``_ReplayCheckout`` reconstruction a pipeline run's own POV replay uses. A
PatchAgent case, a San2Patch case and a pipeline run are therefore measured by literally
the same oracle.

PatchAgent emits a plain unified diff (``---``/``+++``, no ``diff --git`` header), which
``patch -p1`` and ``git apply`` both accept, so like San2Patch there is no header to
synthesize.

One wrinkle this baseline has and San2Patch does not: a single run can cover two CVEs
sharing a buggy commit, so two keys resolve to the same ``patch.diff``. That is
deliberate -- each CVE carries its own POV set and its own verdict, and for libtiff
``c421b99`` those verdicts genuinely disagree (2/2 blocked for CVE-2016-5314, 0/2 for
CVE-2016-3186, which is a different bug the model was never shown).

All the background-job bookkeeping (on-disk lock, dead-holder reclamation, job-tagged
status writes, deleted-target protection) is ``run_jobs``, unmodified. This module only
supplies the PatchAgent-specific pieces: the case -> project_slug mapping, the argv, and
a ``run_dir_resolver`` pointing at the case's ``<batch>/gen_patch/<case>/`` directory.

The whole set was already scored out of band; these buttons exist for re-scoring one
case after a POV set is edited, which is the same reason San2Patch and LoopRepair have
them.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import config
import groundtruth
import run_jobs
import runs
import patchagent

from baselines import patch_source

ReplayError = run_jobs.JobError

_FAMILY_LABEL = {"fixpov": "fixPOV", "respov": "residual"}
_FAMILY_RESULTS_SUBDIR = {"fixpov": "fix_pov", "respov": "residual"}


def _project_slug_for(key: str) -> Optional[str]:
    row = groundtruth.project_rows().get(key)
    return row.get("project_slug") if row else None


_FAMILY_MANIFEST_DIR = {"fixpov": config.fix_povs_dir, "respov": config.residual_povs_dir}


def _manifest_path(family: str, project_slug: str) -> Path:
    return _FAMILY_MANIFEST_DIR[family]() / project_slug / "manifest.json"


def _availability(family: str, key: str) -> Dict[str, Any]:
    result = patchagent.get_result(key)
    if result is None:
        raise ReplayError(f"patchagent result not found: {key}")
    row = groundtruth.project_rows().get(key) or {}
    slug = row.get("project_slug")
    manifest: Optional[Path] = None
    reason: Optional[str] = None
    base: Dict[str, Any] = {}
    if slug is None:
        reason = "no project_info.csv row for this case id"
    else:
        manifest = _manifest_path(family, slug)
        if not result.get("has_patch"):
            reason = "PatchAgent produced no patch for this case"
        elif not manifest.is_file():
            reason = f"No curated {_FAMILY_LABEL[family]} POV manifest exists for this project yet"
        case = patch_source.find_case("patchagent", config.REPO_ROOT, key)
        if case is not None:
            base = patch_source.base_plan(
                "patchagent", config.REPO_ROOT, case, (row.get("buggy_commit_id") or "").strip(),
                source_path=config.dataset_dir() / "project-sources" / slug,
            )
    return {
        "available": reason is None,
        "unavailable_reason": reason,
        "project_slug": slug,
        "has_manifest": bool(manifest and manifest.is_file()),
        # Surfaced, not just used: a score taken on a different commit than the
        # dataset's is a fact the reader of the panel needs, the same way the
        # roll-up carries it.
        "base": base,
    }


def _command(family: str) -> Any:
    def build(key: str, availability: Dict[str, Any]) -> List[str]:
        case = patch_source.find_case("patchagent", config.REPO_ROOT, key)
        if case is None:
            raise ReplayError(f"patchagent case not found: {key}")
        text, err = patch_source.patch_text("patchagent", case)
        if err or text is None:
            raise ReplayError(err or "could not read the patch")
        staged = case.artifact_dir / f"{family}_replay" / "staged_patch.diff"
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(text, encoding="utf-8")
        out = case.artifact_dir / _FAMILY_RESULTS_SUBDIR[family] / "results.json"
        argv = [
            sys.executable, "-m", "security_pipeline", family, "replay-patch",
            "--project", availability["project_slug"],
            "--patch-file", str(staged),
            "--out", str(out),
            # Namespaced by tool: all three tools have a libtiff CVE-2017-7601 patch, and an
            # unprefixed label would have them share one scratch checkout.
            "--label", f"patchagent-{key}",
            "--workspace-root", str(config.REPO_ROOT),
            "--runs-dir", str(config.RUNS_DIR),
        ]
        # Same base decision the batch driver makes, from the same function. This
        # module's whole premise is that the button and `score_patches.py` score the
        # same bytes with the same oracle; leaving the base out here would have the
        # button score a different commit than the batch did -- exactly the kind of
        # disagreement with nothing in either output explaining it that patch_source
        # exists to prevent.
        base = availability.get("base") or {}
        if base.get("base_revision"):
            argv += ["--base-revision", base["base_revision"]]
        return argv

    return build


def _case_dir_resolver(key: str) -> Optional[Path]:
    return patchagent._case_dir(key)


def _result_lookup(key: str) -> Dict[str, Any]:
    d = patchagent._case_dir(key)
    if d is None:
        return {}
    return {
        "fix_pov_eval": runs._fix_pov_eval(d),
        "residual_eval": runs._residual_eval(d),
    }


FIXPOV_PATCHAGENT_REPLAY = run_jobs.JobKind(
    label="patchagent fixPOV replay",
    subdir="fixpov_replay",
    status_name="replay_status.json",
    log_name="replay.log",
    lock_name="replay.lock",
    thread_prefix="pa-fixpov-replay",
    availability=lambda key: _availability("fixpov", key),
    command=_command("fixpov"),
    result_path=lambda case_dir: case_dir / "fix_pov" / "results.json",
    result_key="fix_pov_eval",
    run_dir_resolver=_case_dir_resolver,
    result_lookup=_result_lookup,
)

RESPOV_PATCHAGENT_REPLAY = run_jobs.JobKind(
    label="patchagent residual replay",
    subdir="respov_replay",
    status_name="replay_status.json",
    log_name="replay.log",
    lock_name="replay.lock",
    thread_prefix="pa-respov-replay",
    availability=lambda key: _availability("respov", key),
    command=_command("respov"),
    result_path=lambda case_dir: case_dir / "residual" / "results.json",
    result_key="residual_eval",
    run_dir_resolver=_case_dir_resolver,
    result_lookup=_result_lookup,
)


def fixpov_status(key: str) -> Dict[str, Any]:
    return run_jobs.status(FIXPOV_PATCHAGENT_REPLAY, key)


def fixpov_start(key: str) -> Dict[str, Any]:
    return run_jobs.start(FIXPOV_PATCHAGENT_REPLAY, key)


def respov_status(key: str) -> Dict[str, Any]:
    return run_jobs.status(RESPOV_PATCHAGENT_REPLAY, key)


def respov_start(key: str) -> Dict[str, Any]:
    return run_jobs.start(RESPOV_PATCHAGENT_REPLAY, key)
