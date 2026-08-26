"""Residual-gap POV evaluation — does the patch go *beyond* the official fix?

A *residual POV* is a curated exploit for a path the CVE's **official upstream fix
does not close**. These are real holes found while auditing each project's
fixPOV set for completeness (see
``fix_povs/COMPLETENESS_CHECKLIST.md``): six projects ship an official
fix whose containment check is a bare ``String.startsWith(dest)`` with no
separator boundary, so a sibling directory sharing a name prefix still escapes;
antisamy's official fix removes children from a live ``NodeList`` by index while
iterating, so a ``<style>`` tag with 3+ smuggled children still leaks an
executable node past the "fixed" sanitizer.

Those findings could not be expressed as fixPOVs. ``fixpov validate``
certifies a POV by proving it **reproduces on the vulnerable revision and is
blocked by the official fix** — and a residual POV reproduces in *both* states by
definition, so it fails that contract for the very reason that makes it
interesting. Until now they lived only as prose in each project's ``NOTES.md``.

This module makes them measurable, with the certification oracle **inverted**:

    fixPOV:  before = reproduced  AND  after = blocked      -> certified
    residual POV:      before = reproduced  AND  after = reproduced   -> certified
                                                  ^^^^^^^^^^^^^^^^^^
                              proves the official fix genuinely does NOT close it

Dropping the "after" check entirely would have been simpler, but it is the only
thing standing between the score and two silent failure modes: a POV broken such
that it always exits 0 (which would mark every patch as leaving the gap open),
and a path upstream actually *does* close (which belongs in ``fix_povs``
instead). Certification here costs one extra run against a checkout the validator
already builds.

**Scoring is a bonus, not a deficiency** — the inverse of ``fix_pov.py``:

    BLOCKED    the pipeline's patch closed a gap the official fix left open.
               It is strictly *better* than upstream. ✅ credit
    REPRODUCED the patch has the same gap upstream does. This is the expected,
               neutral outcome and is **not** a failure — matching the official
               fix is exactly what the fixPOV score already rewards.
    ERRORED    inconclusive (build/harness failure, timeout, stale certification).

So ``score = blocked / (blocked + reproduced)`` reads as "of the holes upstream
left open, what fraction did this patch also close". A patch that faithfully
reproduces upstream's fix scores 0.0 here and that is a perfectly good result;
the number only ever adds information about hardening above the official fix.

Like ``fix_pov_eval`` this stage is **non-gating**: it never rejects a run,
runs last so no agent ever sees these files, and stages under
``.security-pipeline/respov`` (a sibling of the frozen ``gtpov`` staging dir, so the two never collide),
removing them before returning.

Pure stdlib, shared by the pipeline stage and the ``respov`` CLI so certification
and in-run scoring use identical staging + classification logic.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import paths
from . import fix_pov as gt
from .docker_runner import DockerRunner

MANIFEST_NAME = gt.MANIFEST_NAME
POVS_SUBDIR = gt.POVS_SUBDIR
OFFICIAL_FIX_DEFAULT = gt.OFFICIAL_FIX_DEFAULT

# Staged alongside — never on top of — the fixPOV tree, so a run that
# evaluates both families cannot have one clobber the other's files.
RESPOV_STAGE_PARTS = (".security-pipeline", "respov")

# Outcome labels are reused verbatim from fix_pov so every downstream
# consumer (dashboard, state.json readers) parses one vocabulary. Only the
# *meaning* of BLOCKED/REPRODUCED inverts here — see the module docstring.
BLOCKED = gt.BLOCKED
REPRODUCED = gt.REPRODUCED
ERRORED = gt.ERRORED
DEFAULT_ERROR_EXIT_CODE = gt.DEFAULT_ERROR_EXIT_CODE


class ResidualError(RuntimeError):
    """A malformed or unusable residual-POV definition."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def residual_root(workspace_root: Path) -> Path:
    return paths.residual_povs_dir(workspace_root)


def project_dir(workspace_root: Path, project_slug: str) -> Path:
    return residual_root(workspace_root) / project_slug


def manifest_path(workspace_root: Path, project_slug: str) -> Path:
    return project_dir(workspace_root, project_slug) / MANIFEST_NAME


def available_project_slugs(workspace_root: Path) -> List[str]:
    """Project slugs that have a residual POV directory with a manifest."""
    root = residual_root(workspace_root)
    if not root.exists():
        return []
    return [
        child.name
        for child in sorted(root.iterdir())
        if child.is_dir()
        and not child.name.startswith("_")
        and (child / MANIFEST_NAME).exists()
    ]


# --------------------------------------------------------------------------- #
# Manifest loading + structural validation
# --------------------------------------------------------------------------- #


def validate_manifest_shape(data: Any, *, source: str = "manifest") -> None:
    """Validate a residual manifest.

    Structurally identical to a fixPOV manifest (same POV shape, same
    exit-code contract), plus one required field of its own: ``residual_of``, the
    upstream fix commit these POVs are proven to survive. A residual POV set is a
    claim *about a specific official fix*, so the manifest has to name it — a set
    certified against one fix commit says nothing about a later hardening commit.
    """
    gt.validate_manifest_shape(data, source=source)
    residual_of = data.get("residual_of")
    if not residual_of or not isinstance(residual_of, str):
        raise ResidualError(
            f"{source}: missing string 'residual_of' — a residual POV set must name "
            "the official fix commit it is proven to survive"
        )
    for index, pov in enumerate(data.get("povs", [])):
        if not pov.get("gap_summary"):
            raise ResidualError(
                f"{source}: povs[{index}] ({pov.get('id')}) missing 'gap_summary' — "
                "state in one line what the official fix fails to close"
            )


def load_manifest(workspace_root: Path, project_slug: str) -> Optional[dict]:
    """Load and light-validate a project's residual manifest, or None if absent.

    A missing manifest is the normal "no residual gaps recorded for this project"
    state and returns None. Present-but-broken raises.
    """
    path = manifest_path(workspace_root, project_slug)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResidualError(f"residual manifest is unreadable: {path}: {exc}")
    try:
        validate_manifest_shape(data, source=str(path))
    except gt.FixPovError as exc:  # re-brand shared structural errors
        raise ResidualError(str(exc))
    return data


# --------------------------------------------------------------------------- #
# Certification (the inverted oracle)
# --------------------------------------------------------------------------- #


def content_fingerprint(project_res_dir: Path, manifest: dict, pov: dict) -> str:
    """Same fingerprint contract as fixPOV, over this family's directory.

    Reused verbatim: a residual certification is a statement about the POV's
    command, its exit-code contract, every file under ``povs/``, the official fix
    patch it was proven to survive, and the revision — the identical input set.
    """
    return gt.content_fingerprint(project_res_dir, manifest, pov)


def certification_state(project_res_dir: Path, manifest: dict, pov: dict) -> Dict[str, Any]:
    """Whether this residual POV may count toward the beyond-upstream score.

    Mirrors ``fix_pov.certification_state`` — including honoring a
    pre-fingerprint ``certified`` as eligible-but-unsealed — because the risk it
    guards is the same: a POV edited after certification would otherwise inherit
    a badge it no longer earns. What differs is only what ``fixpov``-equivalent
    validation *proved* to set ``certified`` in the first place (see
    ``residual validate``): here it is "still reproduces after the official fix".
    """
    validation = pov.get("validation") or {}
    if not validation.get("certified"):
        return {
            "eligible": False,
            "content_verified": False,
            "reason": "residual POV is not certified — run `respov validate --project <slug>`",
        }
    recorded = validation.get("content_hash")
    if not recorded:
        return {"eligible": True, "content_verified": False, "reason": None}
    if recorded != content_fingerprint(project_res_dir, manifest, pov):
        return {
            "eligible": False,
            "content_verified": False,
            "reason": (
                "residual POV content changed since it was certified — re-run "
                "`respov validate --project <slug>`"
            ),
        }
    return {"eligible": True, "content_verified": True, "reason": None}


def certifies(before_outcome: str, after_outcome: str) -> bool:
    """The inverted contract: reproduces on the buggy tree AND on the fixed tree.

    ``before`` is a sanity check that the exploit works at all; ``after`` is the
    load-bearing one — it is what distinguishes a genuine residual gap from a
    path the official fix closes (which belongs in ``fix_povs``) or a
    harness that always exits 0.
    """
    return before_outcome == REPRODUCED and after_outcome == REPRODUCED


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #


def evaluate_manifest(
    *,
    manifest: dict,
    project_res_dir: Path,
    docker: DockerRunner,
    checkout_path: Path,
    timeout_seconds: Optional[int],
    name_prefix: str = "respov",
    enforce_certification: bool = True,
) -> Dict[str, Any]:
    """Stage this project's residual POVs into ``checkout_path`` and run them all.

    Delegates to ``fix_pov.evaluate_manifest`` — identical staging, session
    reuse, ``build_command`` fast path, staging-failure handling and outcome
    classification — with this family's stage directory and certification
    predicate. Never raises for a POV that reproduces: that is the *expected*
    outcome here, not an error.
    """
    summary = gt.evaluate_manifest(
        manifest=manifest,
        project_gt_dir=project_res_dir,
        docker=docker,
        checkout_path=checkout_path,
        timeout_seconds=timeout_seconds,
        name_prefix=name_prefix,
        enforce_certification=enforce_certification,
        stage_parts=RESPOV_STAGE_PARTS,
        certification_fn=certification_state,
    )
    return _relabel(manifest, summary)


def _relabel(manifest: dict, summary: Dict[str, Any]) -> Dict[str, Any]:
    """Re-express a fixPOV-shaped summary in residual terms.

    The counts and the score arithmetic are identical; what changes is the
    vocabulary the dashboard and any human reader see. ``blocked`` becomes
    ``hardened_beyond_fix`` and ``reproduced`` becomes ``matches_official_fix``,
    so nobody reads a high ``reproduced`` count as a failing patch — under this
    metric it means "as good as upstream", which is the norm.
    """
    blocked = summary.get("blocked", 0)
    reproduced = summary.get("reproduced", 0)
    conclusive = blocked + reproduced
    out = dict(summary)
    out.update(
        {
            "residual_of": manifest.get("residual_of", ""),
            "hardened_beyond_fix": blocked,
            "matches_official_fix": reproduced,
            "score": (blocked / conclusive) if conclusive else None,
            # "beat upstream on every known residual gap" — like all_blocked, only
            # true when every POV actually ran and every one was closed.
            "all_hardened": summary.get("total", 0) > 0 and blocked == summary.get("total", 0),
        }
    )
    # `all_blocked` is fixPOV vocabulary and would read as a pass/fail gate
    # here; drop it so no consumer mistakes this for a coverage verdict.
    out.pop("all_blocked", None)
    for pov in out.get("povs", []):
        pov["gap_summary"] = _gap_summary_for(manifest, pov.get("id"))
    return out


def _gap_summary_for(manifest: dict, pov_id: Optional[str]) -> str:
    for pov in manifest.get("povs", []):
        if pov.get("id") == pov_id:
            return pov.get("gap_summary", "")
    return ""


def redact_for_run_artifact(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Drop CVE/project identity from a summary bound for a run directory.

    Same contract as the fixPOV artifact: runs are de-identified and the
    dashboard maps a run back to its CVE through its own index.
    """
    return gt.redact_for_run_artifact(summary)


def summarize(
    manifest: dict,
    pov_results: List[Dict[str, Any]],
    setup_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Aggregate residual POV results (residual vocabulary)."""
    return _relabel(manifest, gt.summarize(manifest, pov_results, setup_results))
