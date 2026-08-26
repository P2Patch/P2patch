"""fixPOV evaluation — a third, objective signal on top of the live
exploiter POV and the LLM verifier.

A *fixPOV* is a curated proof-of-concept exploit, derived from a CVE's
official advisory (GHSA/NVD) + fix commit(s) and certified once to **reproduce on
the unpatched code and be blocked by the official fix**. Unlike the exploiter's
single live POV (a regression witness that also gates the run), the fixPOV
set aims to cover *every* source-to-sink path the advisory describes, and it is
reused verbatim across every run of that project.

In a pipeline run the fixPOVs are replayed against the
*pipeline-patched* code purely to **measure** how many real exploit paths the
patch actually blocked. It is never a gate: a POV that still reproduces is
recorded, not rejected (see ``FixPovEvalStage``).

Exit-code convention (identical to the exploiter POV): a POV command exits ``0``
when the exploit reproduces (vulnerability present) and non-zero once a correct
fix blocks it. So on patched code:
  exit != reproduces_exit_code  -> "blocked"    (patch defended this path) ✅
  exit == reproduces_exit_code  -> "reproduced" (patch missed this path)   ❌
  timeout / staging error       -> "errored"    (inconclusive)

This module is pure stdlib (like the rest of ``security_pipeline``). It is shared
by the pipeline stage and the ``fixpov`` CLI so certification and in-run scoring
use exactly the same staging + classification logic.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import paths
from .docker_runner import DockerRunner
from .logging_io import ensure_dir
from .models import CommandResult

MANIFEST_NAME = "manifest.json"
OFFICIAL_FIX_DEFAULT = "official_fix.patch"
POVS_SUBDIR = "povs"
# POV files are staged into the checkout under this path so they never collide
# with the exploiter's own POV tree (.security-pipeline/pov) or the product code.
# FROZEN at the legacy "gtpov" name: every certified manifest's ``command``
# embeds this path (``bash .security-pipeline/gtpov/run.sh <id>``) and the
# command is part of the certification fingerprint, so renaming the directory
# would invalidate every fixPOV certification. Only the constant was renamed.
FIX_POV_STAGE_PARTS = (".security-pipeline", "gtpov")

# Outcome labels for a single POV run.
BLOCKED = "blocked"
REPRODUCED = "reproduced"
ERRORED = "errored"

# Exit code a POV command uses to signal a harness/build error (as opposed to a
# real blocked exploit). It is classified as ERRORED and excluded from the score,
# so a Maven/compile failure can never be mistaken for "the patch blocked it".
# Per-POV overridable via manifest ``error_exit_code``.
DEFAULT_ERROR_EXIT_CODE = 2

# A POV id names a docker log file (``docker/fixpov_<id>.log``) and is staged into
# shell commands, so it is restricted to a safe basename rather than trusted to
# be one. ``../`` in an id put log files outside the run's docker directory.
POV_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class FixPovError(RuntimeError):
    """A malformed or unusable fixPOV definition."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fix_pov_root(workspace_root: Path) -> Path:
    return paths.fix_povs_dir(workspace_root)


def project_dir(workspace_root: Path, project_slug: str) -> Path:
    return fix_pov_root(workspace_root) / project_slug


def manifest_path(workspace_root: Path, project_slug: str) -> Path:
    return project_dir(workspace_root, project_slug) / MANIFEST_NAME


def available_project_slugs(workspace_root: Path) -> List[str]:
    """Project slugs that have a fixPOV directory with a manifest."""
    root = fix_pov_root(workspace_root)
    if not root.exists():
        return []
    slugs = [
        child.name
        for child in sorted(root.iterdir())
        if child.is_dir()
        and not child.name.startswith("_")
        and (child / MANIFEST_NAME).exists()
    ]
    return slugs


# --------------------------------------------------------------------------- #
# Manifest loading + light structural validation (stdlib only, no jsonschema).
# --------------------------------------------------------------------------- #


def validate_manifest_shape(data: Any, *, source: str = "manifest") -> None:
    if not isinstance(data, dict):
        raise FixPovError(f"{source}: top level must be a JSON object")
    if not data.get("project_slug"):
        raise FixPovError(f"{source}: missing 'project_slug'")
    povs = data.get("povs")
    if not isinstance(povs, list) or not povs:
        raise FixPovError(f"{source}: 'povs' must be a non-empty array")
    seen_ids = set()
    for index, pov in enumerate(povs):
        where = f"{source}: povs[{index}]"
        if not isinstance(pov, dict):
            raise FixPovError(f"{where} must be an object")
        pov_id = pov.get("id")
        if not pov_id or not isinstance(pov_id, str):
            raise FixPovError(f"{where} missing string 'id'")
        if not POV_ID_RE.match(pov_id):
            raise FixPovError(
                f"{where} id {pov_id!r} is not a safe basename "
                f"(allowed: {POV_ID_RE.pattern}) — it names a log file"
            )
        if pov_id in seen_ids:
            raise FixPovError(f"{source}: duplicate pov id {pov_id!r}")
        seen_ids.add(pov_id)
        if not pov.get("command") or not isinstance(pov["command"], str):
            raise FixPovError(f"{where} ({pov_id}) missing string 'command'")
        exit_code = pov.get("reproduces_exit_code", 0)
        if not isinstance(exit_code, int):
            raise FixPovError(f"{where} ({pov_id}) 'reproduces_exit_code' must be an integer")


def load_manifest(workspace_root: Path, project_slug: str) -> Optional[dict]:
    """Load and light-validate a project's manifest, or None if none exists.

    A missing manifest is a normal "no fixPOVs for this project yet"
    state (returns None). A present-but-broken manifest raises FixPovError.
    """
    path = manifest_path(workspace_root, project_slug)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixPovError(f"fixPOV manifest is unreadable: {path}: {exc}")
    validate_manifest_shape(data, source=str(path))
    return data


# --------------------------------------------------------------------------- #
# Staging + classification
# --------------------------------------------------------------------------- #


def stage_dir_for(checkout_path: Path, stage_parts: Sequence[str] = FIX_POV_STAGE_PARTS) -> Path:
    return checkout_path.joinpath(*stage_parts)


def stage_povs(
    project_gt_dir: Path,
    checkout_path: Path,
    stage_parts: Sequence[str] = FIX_POV_STAGE_PARTS,
) -> Path:
    """Copy the project's ``povs/`` contents into ``<checkout>/.security-pipeline/gtpov``.

    The whole POV directory is staged (POVs may share fixtures/drivers); the
    manifest's per-POV ``command`` references files relative to /workspace/repo,
    e.g. ``bash .security-pipeline/gtpov/run.sh``. Any prior staged copy is
    cleared first so a re-run is deterministic.

    ``stage_parts`` lets a sibling POV family (see ``residual.py``) stage into its
    own directory, so the two never collide inside one checkout.
    """
    source = project_gt_dir / POVS_SUBDIR
    if not source.is_dir():
        raise FixPovError(f"fixPOV directory is missing: {source}")
    stage = stage_dir_for(checkout_path, stage_parts)
    if stage.exists():
        shutil.rmtree(stage, ignore_errors=True)
    ensure_dir(stage.parent)
    shutil.copytree(source, stage)
    return stage


def cleanup_stage(
    checkout_path: Path,
    stage_parts: Sequence[str] = FIX_POV_STAGE_PARTS,
) -> None:
    """Remove staged POV files so they never pollute a diff or leak to an agent."""
    shutil.rmtree(stage_dir_for(checkout_path, stage_parts), ignore_errors=True)


def content_fingerprint(project_gt_dir: Path, manifest: dict, pov: dict) -> str:
    """Hash everything a certification is a statement *about*.

    ``fixpov validate`` proves "this POV reproduces on the vulnerable revision and
    is blocked by the official fix". That claim is only transferable to a later
    run if none of its inputs moved, so the fingerprint covers the POV's command
    and exit-code contract, every file under ``povs/``, the official fix patch,
    and the revision the manifest names. Editing a POV script after certifying it
    now invalidates the certification instead of silently inheriting it.
    """
    digest = hashlib.sha256()
    for field in ("command", "reproduces_exit_code", "error_exit_code"):
        digest.update(f"{field}={pov.get(field)!r}\0".encode("utf-8"))
    fix_reference = manifest.get("fix_reference") or {}
    for key in sorted(fix_reference):
        digest.update(f"fix.{key}={fix_reference[key]!r}\0".encode("utf-8"))
    for key in ("vulnerable_revision", "project_version", "cve_id"):
        digest.update(f"{key}={manifest.get(key)!r}\0".encode("utf-8"))

    for name in (OFFICIAL_FIX_DEFAULT, fix_reference.get("official_fix_patch") or ""):
        patch = project_gt_dir / name if name else None
        if patch and patch.is_file():
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(patch.read_bytes()).digest())

    povs_dir = project_gt_dir / POVS_SUBDIR
    if povs_dir.is_dir():
        for item in sorted(povs_dir.rglob("*")):
            if item.is_symlink() or not item.is_file():
                continue
            digest.update(item.relative_to(povs_dir).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def certification_state(project_gt_dir: Path, manifest: dict, pov: dict) -> Dict[str, Any]:
    """Whether this POV may count toward a coverage score, and why not if not.

    ``certified`` without a ``content_hash`` is the pre-hash format: it is honored
    (those sets were certified before fingerprints existed) but reported as
    unsealed, and the next ``fixpov validate`` stamps it.
    """
    validation = pov.get("validation") or {}
    if not validation.get("certified"):
        return {
            "eligible": False,
            "content_verified": False,
            "reason": "POV is not certified — run `fixpov validate --project <slug>`",
        }
    recorded = validation.get("content_hash")
    if not recorded:
        return {"eligible": True, "content_verified": False, "reason": None}
    if recorded != content_fingerprint(project_gt_dir, manifest, pov):
        return {
            "eligible": False,
            "content_verified": False,
            "reason": (
                "POV content changed since it was certified — re-run "
                "`fixpov validate --project <slug>`"
            ),
        }
    return {"eligible": True, "content_verified": True, "reason": None}


def classify_outcome(
    result: CommandResult,
    reproduces_exit_code: int,
    error_exit_code: Optional[int] = DEFAULT_ERROR_EXIT_CODE,
) -> str:
    """Classify one POV run.

    A timeout, or the reserved ``error_exit_code`` (a build/harness failure), is
    ERRORED — inconclusive, excluded from the score — so infrastructure noise is
    never counted as the patch having blocked the exploit. Otherwise the run is
    REPRODUCED when it exits ``reproduces_exit_code`` and BLOCKED on any other
    (non-error) exit.
    """
    if result.timed_out:
        return ERRORED
    if error_exit_code is not None and result.exit_code == error_exit_code:
        return ERRORED
    if result.exit_code == reproduces_exit_code:
        return REPRODUCED
    return BLOCKED


def _pov_record(
    pov: dict,
    outcome: str,
    *,
    result: Optional[CommandResult] = None,
    reason: Optional[str] = None,
    content_verified: bool = False,
) -> Dict[str, Any]:
    return {
        "id": pov["id"],
        "description": pov.get("description", ""),
        "exploit_path": pov.get("exploit_path", ""),
        "covers_alert_paths": pov.get("covers_alert_paths", []),
        "command": pov["command"],
        "reproduces_exit_code": int(pov.get("reproduces_exit_code", 0)),
        "error_exit_code": pov.get("error_exit_code", DEFAULT_ERROR_EXIT_CODE),
        "exit_code": None if result is None else result.exit_code,
        "timed_out": bool(result is not None and result.timed_out),
        "outcome": outcome,
        # Why an ERRORED POV is inconclusive: build failure, missing
        # certification, stale certification. None for a conclusive run.
        "reason": reason,
        "content_verified": content_verified,
        "command_result": None if result is None else result.to_json_dict(),
    }


def _run_one_pov(
    docker: DockerRunner,
    pov: dict,
    timeout_seconds: Optional[int],
    name_prefix: str,
    content_verified: bool = False,
) -> Dict[str, Any]:
    result = docker.run_project_command(
        pov["command"], f"{name_prefix}_{pov['id']}", timeout_seconds
    )
    outcome = classify_outcome(
        result,
        int(pov.get("reproduces_exit_code", 0)),
        pov.get("error_exit_code", DEFAULT_ERROR_EXIT_CODE),
    )
    return _pov_record(pov, outcome, result=result, content_verified=content_verified)


def _pov_worker_count(manifest: dict, pov_count: int) -> int:
    """How many POVs to run concurrently within a single checkout.

    Only safe (>1) when the manifest declares a ``build_command``: that means the
    project is compiled once up front and each POV is a build-free run (no shared
    ``target/`` write race). Without ``build_command`` every POV self-compiles
    against the shared mounted repo, so they must stay sequential. Default caps at
    4; a manifest may lower/raise it via ``pov_parallelism``.
    """
    if not manifest.get("build_command"):
        return 1
    requested = manifest.get("pov_parallelism")
    if isinstance(requested, int) and requested >= 1:
        return max(1, min(requested, pov_count))
    return max(1, min(4, pov_count))


def evaluate_manifest(
    *,
    manifest: dict,
    project_gt_dir: Path,
    docker: DockerRunner,
    checkout_path: Path,
    timeout_seconds: Optional[int],
    name_prefix: str = "fixpov",
    enforce_certification: bool = True,
    stage_parts: Sequence[str] = FIX_POV_STAGE_PARTS,
    certification_fn: Optional[Callable[[Path, dict, dict], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Stage the POVs into ``checkout_path`` and run every one against ``docker``.

    Runs inside a single kept-alive container per checkout (``docker.session()``)
    so container startup, the mounted ``target/``, and the container's ``~/.m2``
    (plugin downloads) are warmed once and reused by every POV — instead of a cold
    ``docker run --rm`` + recompile + re-download per POV. If the manifest declares
    a ``build_command`` it is run once up front (compile the project + POV drivers)
    and the now build-free POVs may run concurrently; otherwise each POV
    self-compiles and they run sequentially. Falls back transparently to the old
    per-command path if a persistent container can't be started (or ``docker`` is a
    stub without ``session()``, e.g. in tests).

    Returns an aggregate summary (never raises for a POV that reproduces — that is
    a recorded outcome, not an error). ``docker`` must already be pointed at
    ``checkout_path`` (its mounted repo). Always cleans up the staged files before
    returning.
    """
    povs = manifest.get("povs", [])
    build_command = manifest.get("build_command")
    workers = _pov_worker_count(manifest, len(povs))
    pov_results: List[Dict[str, Any]] = []
    setup_results: List[Dict[str, Any]] = []

    # A POV may only count toward the score if its certification still stands.
    # `fixpov validate` is what *creates* certifications, so it opts out.
    # ``certification_fn`` lets a sibling POV family supply its own predicate
    # (residual POVs invert the "after" expectation — see ``residual.py``).
    certify = certification_fn or certification_state
    eligibility = {
        pov["id"]: (
            certify(project_gt_dir, manifest, pov)
            if enforce_certification
            else {"eligible": True, "content_verified": False, "reason": None}
        )
        for pov in povs
    }

    session_factory = getattr(docker, "session", None)
    session_cm = session_factory() if callable(session_factory) else contextlib.nullcontext()

    try:
        with session_cm as session_active:
            stage_povs(project_gt_dir, checkout_path, stage_parts)

            # POVs may only run concurrently when a persistent container is truly
            # active: they then share one warm container and each POV is a build-free
            # run. If the session fell back to per-command `docker run --rm`
            # (session_active is False/None), a "build-free" POV would instead
            # self-compile in its own throwaway container — running several full
            # builds at once would exhaust memory — so force sequential there.
            if not session_active:
                workers = 1

            # ``checkout_path`` is not a fresh checkout — it is the run's own
            # worktree, already configured/built once by the pipeline's own
            # ``build_command`` (this is deliberate session reuse, see the
            # module docstring). For an autoconf-based project this means a
            # subdirectory's ``config.cache`` may already be pinned to
            # whatever CFLAGS/LDFLAGS the main build last used. A manifest's
            # own ``setup_commands``/``build_command`` were authored and
            # certified (``fixpov validate``) against a *fresh* checkout, so if
            # its configure/make sequence doesn't happen to match the main
            # build's exactly, autoconf refuses to proceed rather than
            # silently reconfigure ("CFLAGS has changed since the previous
            # run... changes in the environment can compromise the build") —
            # a real failure (git__binutils-gdb CVE-2017-14745: config.cache
            # written by the main build's ``make configure-host`` step, which
            # the manifest's own setup_commands don't run, conflicted on the
            # very next ``make`` and errored the whole POV as ``errored``).
            # Clearing cached configure state before the manifest's own
            # first command runs (a no-op, best-effort on non-autoconf
            # projects) makes staging no longer depend on how the earlier
            # build happened to be sequenced. This is prepended onto the
            # first command that will actually execute (rather than issued
            # as its own extra `docker.run_project_command` call) so it
            # doesn't change the number or order of commands run against
            # ``docker`` — callers/tests that assert on that sequence are
            # unaffected. One-time cost at the end of a run, not inside an
            # agent's hot build loop, so it does not conflict with the
            # project's "never run a full clean rebuild" rule for agents.
            cache_clear_prefix = "find . -maxdepth 6 -name config.cache -delete 2>/dev/null; "
            setup_commands = list(manifest.get("setup_commands", []) or [])
            if setup_commands:
                setup_commands[0] = cache_clear_prefix + setup_commands[0]
            elif build_command:
                build_command = cache_clear_prefix + build_command

            # Staging/build failures are load-bearing: the score is only meaningful
            # if the code under test actually compiled. The checked-in POV runners
            # do map their own missing-artifact run to the reserved error exit
            # code, but nothing enforced that, and any POV that exits non-zero for
            # a reason other than `error_exit_code` — a runner that lets `mvn`'s
            # exit 1 through, a missing class exiting 1 — was counted as BLOCKED,
            # i.e. a broken build could score 100% coverage. So the harness now
            # checks these itself and refuses to draw any conclusion after a
            # failure, instead of trusting each POV to self-report.
            staging_failure: Optional[str] = None
            for command in setup_commands:
                setup = docker.run_project_command(
                    command, f"{name_prefix}_setup", timeout_seconds
                )
                setup_results.append(setup.to_json_dict())
                if not setup.ok:
                    staging_failure = (
                        f"fixPOV setup command failed (exit {setup.exit_code}): {command}"
                    )
                    break

            if build_command and staging_failure is None:
                build = docker.run_project_command(
                    build_command, f"{name_prefix}_build", timeout_seconds
                )
                setup_results.append(build.to_json_dict())
                if not build.ok:
                    staging_failure = (
                        f"fixPOV build command failed (exit {build.exit_code}); "
                        "no POV result from this checkout is conclusive"
                    )

            if staging_failure is not None:
                pov_results = [
                    _pov_record(pov, ERRORED, reason=staging_failure) for pov in povs
                ]
            else:
                runnable = [pov for pov in povs if eligibility[pov["id"]]["eligible"]]
                pov_results = [
                    _pov_record(pov, ERRORED, reason=eligibility[pov["id"]]["reason"])
                    for pov in povs
                    if not eligibility[pov["id"]]["eligible"]
                ]

                def run(pov: dict) -> Dict[str, Any]:
                    return _run_one_pov(
                        docker,
                        pov,
                        timeout_seconds,
                        name_prefix,
                        eligibility[pov["id"]]["content_verified"],
                    )

                if workers > 1 and len(runnable) > 1:
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        pov_results.extend(pool.map(run, runnable))
                else:
                    pov_results.extend(run(pov) for pov in runnable)
                # Keep manifest order regardless of which POVs were skipped.
                order = {pov["id"]: index for index, pov in enumerate(povs)}
                pov_results.sort(key=lambda record: order.get(record["id"], 0))
    finally:
        cleanup_stage(checkout_path, stage_parts)

    return summarize(manifest, pov_results, setup_results)


def redact_for_run_artifact(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Strip the CVE and project identity from a summary bound for a run directory.

    Everything else a run writes is deliberately de-identified — ``verdict.json``
    redacts ``alert_path`` and the project goes through
    ``to_agent_json_dict`` — but this summary carried ``cve_id`` and
    ``project_slug`` verbatim, so a run exported as an anonymized ZIP named the
    vulnerability it was about. The dashboard maps a run back to its CVE through
    its own ground-truth CVE index (``dashboard/backend/groundtruth.py``, a different concept) and never
    reads these two fields, so dropping them from the artifact costs nothing.
    ``fixpov validate`` output is not a run artifact and keeps them.
    """
    return {key: value for key, value in summary.items() if key not in ("cve_id", "project_slug")}


def summarize(
    manifest: dict,
    pov_results: List[Dict[str, Any]],
    setup_results: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    total = len(pov_results)
    blocked = sum(1 for r in pov_results if r["outcome"] == BLOCKED)
    reproduced = sum(1 for r in pov_results if r["outcome"] == REPRODUCED)
    errored = sum(1 for r in pov_results if r["outcome"] == ERRORED)
    # Score = fraction of fixPOV exploits the patch blocked, over the POVs
    # that produced a conclusive result (errored/timed-out POVs are excluded so a
    # flaky container run neither rewards nor penalises the patch).
    conclusive = blocked + reproduced
    score = (blocked / conclusive) if conclusive else None
    return {
        "project_slug": manifest.get("project_slug", ""),
        "cve_id": manifest.get("cve_id", ""),
        "cwe_id": manifest.get("cwe_id", ""),
        "generated_at": _now_iso(),
        "total": total,
        "blocked": blocked,
        "reproduced": reproduced,
        "errored": errored,
        "score": score,
        # "every fixPOV exploit was blocked" must mean every one of them was
        # actually *tried*: with errored/skipped POVs in the set the claim is not
        # supported, so it stays false rather than quietly ranging over survivors.
        "all_blocked": total > 0 and blocked == total,
        "conclusive": conclusive,
        "setup_results": setup_results or [],
        "povs": pov_results,
    }
