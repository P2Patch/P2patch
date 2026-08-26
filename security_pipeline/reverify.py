"""Independent re-execution of residual POVs, on trees we choose.

Why this exists, given ``respov validate`` already runs every POV:

1. **Certification is self-reported into the artifact it certifies.** ``respov
   validate`` writes its own verdict back into ``manifest.json``, so the file that
   claims "certified" is the file the certifying process edited. That is fine for
   the pipeline (the ``content_hash`` fingerprint stops a POV being edited after
   the fact) but it is the wrong shape for an audit: an auditor wants a record
   produced by a *separate* run, written somewhere the manifest cannot reach.
   Everything here therefore writes to ``residual_povs/verification/<slug>.json``
   and **never touches a manifest**.

2. **The residual oracle has no negative control.** Certification proves
   reproduce-on-buggy and reproduce-after-the-official-fix. Nothing in it requires
   the POV to be blocked by anything, ever — so a POV asserting a reachable
   capability rather than a violated property certifies just as cleanly as a real
   gap, and then scores every patch as "did not beat upstream" for a reason that
   has nothing to do with the patch. The control certification structurally cannot
   provide is: run the POV on a tree where the gap is *known closed* — the later
   upstream commit that fixed it — and require it to flip to ``blocked``.

3. **The certified "after" tree never shipped.** It is ``buggy_commit +
   official_fix.patch``, a synthetic tree; the release that carried the fix also
   carried everything else between the buggy revision and the tag. ``--at <ref>``
   runs the POV against a *real* tree — a release tag or the fix commit itself.

Trees, and what each one proves:

===================  ===================================  ==========================
tree                 expectation                          a contradiction means
===================  ===================================  ==========================
``unpatched``        reproduces (exit 0)                   the POV no longer works at
                                                           the recorded base — the
                                                           oracle has drifted
``official-fix``     reproduces                            the gap is not residual;
                                                           the official fix closes it
                                                           (it belongs in
                                                           fix_povs/)
``at:<ref>``         **blocked**, when ``<ref>`` is a tree  the "fixed later" claim is
                     upstream is claimed to have fixed     wrong, or the POV is
                                                           unfalsifiable
===================  ===================================  ==========================

``errored`` is never evidence for either side. A POV authored against a 2018
revision usually will not compile against a 2026 tree, and the harness's reserved
exit 2 plus the staging-failure guard classify that as ``errored``; the record
says ``inconclusive`` and names porting as the next step, rather than crediting
a build failure as "the fix blocked it".

The ``--at`` checkout is a **private clone**, never the shared
``dataset/project-sources/<slug>`` tree: that checkout is what every run,
every certification and every baseline reads, it is ``--depth 1``, and fetching a
new revision into it would silently move the ground everyone else stands on.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import paths
from . import residual as res
from .docker_runner import EVALUATION_NETWORK, DockerRunner
from .metadata import MetadataError, ProjectMetadata, resolve_project_metadata_by_slug

VERIFICATION_DIRNAME = "verification"
WORKDIR_NAME = ".respov_verify"

# What each tree is supposed to show. Anything else is a finding about the POV,
# not about the tree.
EXPECT_REPRODUCE = "reproduce"
EXPECT_BLOCK = "block"

AS_EXPECTED = "as_expected"
# A tree's expectation may not apply to every POV in the suite. DependencyCheck is
# the worked example: one commit closed the sink `archiveanalyzer_sibling_prefix`
# drives while leaving `extractfiles_sibling_prefix`'s untouched, so running both
# against that commit with one blanket "must be blocked" expectation reported the
# second as a contradiction when it was in fact confirming our claim. Scope the
# expectation instead of widening it.
NOT_APPLICABLE = "not_applicable"
CONTRADICTS = "contradicts"
INCONCLUSIVE = "inconclusive"


@dataclass
class TreeSpec:
    """One tree to run the suite against."""

    key: str                      # "unpatched" | "official-fix" | "at:<ref>"
    label: str
    expectation: str              # EXPECT_REPRODUCE | EXPECT_BLOCK
    revision: Optional[str] = None      # for at:<ref>
    repo: Optional[str] = None          # owner/name, overrides the dataset's github_url
    image: Optional[str] = None         # stock docker image to run this tree in
    povs: Optional[Sequence[str]] = None  # restrict the expectation to these POV ids
    apply_official_fix: bool = False
    notes: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


def verification_dir(workspace_root: Path) -> Path:
    return paths.residual_povs_dir(workspace_root) / VERIFICATION_DIRNAME


def verification_path(workspace_root: Path, project_slug: str) -> Path:
    return verification_dir(workspace_root) / f"{project_slug}.json"


def _run(args: Sequence[str], *, cwd: Optional[Path] = None, timeout: int = 1800):
    return subprocess.run(
        list(args), cwd=str(cwd) if cwd else None, capture_output=True,
        text=True, errors="replace", timeout=timeout, check=False,
    )


def clone_at_revision(
    project: ProjectMetadata,
    revision: str,
    dest: Path,
    *,
    repo: Optional[str] = None,
    timeout: int = 1800,
) -> None:
    """Full-clone the project's upstream repo and check ``revision`` out.

    Deliberately a fresh clone under the verification workdir rather than a fetch
    into ``dataset/project-sources``: that tree is shared by every run and
    every certification, is ``--depth 1``, and must not be deepened or moved by a
    verification pass. A tag, branch or SHA all work because the clone is
    complete.

    ``repo`` (``owner/name``) overrides the dataset's recorded ``github_url``, and
    the reason it exists is not cosmetic: at least one row
    (``srikanth-lingala__zip4j``) records ``https://github.com/iris-sast/zip4j``,
    a **mirror**, whose history is not upstream's. Cloning it makes every upstream
    revision — the later-fix commit, the release tag — unresolvable, which
    surfaces as a bare "pathspec did not match" and would otherwise read as a
    missing commit rather than the wrong repository. Pass ``--repo`` whenever the
    control revision comes from upstream history.
    """
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # `repo` is either "owner/name" (GitHub shorthand) or a full clone URL. The URL
    # form is not a convenience: libtiff's canonical home is GitLab and its GitHub
    # repo is an archived mirror, and binutils' dataset URL 404s outright, so a
    # control revision often exists only somewhere the shorthand cannot name.
    if repo:
        url = repo if "://" in repo else f"https://github.com/{repo}"
    else:
        url = (project.github_url or "").strip()
    if not url:
        raise MetadataError(f"no github_url recorded for {project.project_slug}")
    proc = _run(["git", "clone", "--quiet", url, str(dest)], timeout=timeout)
    if proc.returncode != 0:
        raise MetadataError(f"clone of {url} failed: {proc.stderr.strip()[:400]}")
    proc = _run(["git", "-C", str(dest), "checkout", "--quiet", revision], timeout=300)
    if proc.returncode != 0:
        # A tag that only exists peeled, or a ref the clone did not bring down.
        fetch = _run(["git", "-C", str(dest), "fetch", "--quiet", "origin", revision], timeout=timeout)
        retry = _run(["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"], timeout=300)
        if fetch.returncode != 0 or retry.returncode != 0:
            raise MetadataError(
                f"revision {revision!r} could not be checked out: {proc.stderr.strip()[:300]}"
            )
    head = _run(["git", "-C", str(dest), "rev-parse", "HEAD"], timeout=60)
    if head.returncode == 0:
        (dest / ".respov_revision").write_text(head.stdout.strip() + "\n", encoding="utf-8")


def _prepare_tree(
    spec: TreeSpec, project: ProjectMetadata, workdir: Path, patch_path: Optional[Path]
) -> Path:
    """Materialise the tree ``spec`` describes and return its path."""
    dest = workdir / "trees" / spec.key.replace(":", "_").replace("/", "_")
    if spec.revision:
        clone_at_revision(project, spec.revision, dest, repo=spec.repo)
    else:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(project.source_path, dest)

    if spec.apply_official_fix:
        if not (patch_path and patch_path.exists()):
            raise MetadataError(
                f"{spec.key} needs the official fix patch but none is recorded"
            )
        proc = _run(["git", "-C", str(dest), "apply", "--whitespace=nowarn", str(patch_path)])
        if proc.returncode != 0:
            raise MetadataError(
                f"official fix did not apply to {spec.key}: {proc.stderr.strip()[:300]}"
            )
    return dest


def _tree_rank(tree: Optional[dict]) -> int:
    """How much a tree-level record tells us. A tree that never ran tells us nothing."""
    if not tree:
        return -1
    return {"setup_failed": 0, "image_build_failed": 0}.get(tree.get("state", ""), 2)


def _outcome_rank(entry: Optional[dict]) -> int:
    """How much a per-POV result tells us. `errored` ranks below any real outcome."""
    if not entry:
        return -1
    return 0 if entry.get("outcome") == res.ERRORED else 2


def _summarize_pov(trees: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute a POV's rollup from whatever set of trees survived the merge."""
    verdicts = [t["verdict"] for t in trees.values() if t.get("verdict") != NOT_APPLICABLE]
    control = [k for k, t in trees.items()
               if t.get("expectation") == EXPECT_BLOCK and t.get("outcome") != res.ERRORED]
    return {
        "summary": (CONTRADICTS if CONTRADICTS in verdicts
                    else AS_EXPECTED if verdicts and all(v == AS_EXPECTED for v in verdicts)
                    else INCONCLUSIVE),
        "falsifiability_control": (
            "passed" if any(trees[k].get("outcome") == res.BLOCKED for k in control)
            else "failed" if control else "not_run"),
    }


def _verdict(expectation: str, outcome: str) -> str:
    if outcome == res.ERRORED:
        return INCONCLUSIVE
    if expectation == EXPECT_REPRODUCE:
        return AS_EXPECTED if outcome == res.REPRODUCED else CONTRADICTS
    return AS_EXPECTED if outcome == res.BLOCKED else CONTRADICTS


def default_trees(include_official_fix: bool = True) -> List[TreeSpec]:
    trees = [TreeSpec(
        key="unpatched", label="project source at the recorded buggy commit",
        expectation=EXPECT_REPRODUCE,
        notes="re-proves the oracle: a POV that no longer reproduces here has drifted",
    )]
    if include_official_fix:
        trees.append(TreeSpec(
            key="official-fix", label="buggy commit + official_fix.patch",
            expectation=EXPECT_REPRODUCE, apply_official_fix=True,
            notes="the residual contract: the gap must survive the official fix",
        ))
    return trees


def verify_project(
    *,
    workspace_root: Path,
    project_slug: str,
    trees: Sequence[TreeSpec],
    command_timeout: Optional[int] = None,
    build_timeout: Optional[int] = None,
    skip_docker_build: bool = False,
    keep_workdir: bool = False,
) -> Dict[str, Any]:
    """Run one suite's POVs against every tree in ``trees``; return the record.

    Never raises for an unexpected POV outcome — an unexpected outcome is the
    result. Only setup problems (missing manifest, unresolvable revision, image
    build failure) raise, and a tree that fails to materialise is recorded as
    ``setup_failed`` so the other trees still run.
    """
    project = resolve_project_metadata_by_slug(project_slug, workspace_root)
    manifest = res.load_manifest(workspace_root, project_slug)
    if manifest is None:
        raise MetadataError(f"No residual manifest for {project_slug}")

    res_dir = res.project_dir(workspace_root, project_slug)
    patch_name = (manifest.get("fix_reference", {}) or {}).get(
        "official_fix_patch", res.OFFICIAL_FIX_DEFAULT
    )
    patch_path = res_dir / patch_name if patch_name else None

    workdir = workspace_root / WORKDIR_NAME / project_slug
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    tree_records: Dict[str, Any] = {}
    per_pov: Dict[str, Dict[str, Any]] = {
        pov["id"]: {"pov_id": pov["id"], "trees": {}} for pov in manifest.get("povs", [])
    }

    for spec in trees:
        tree_started = time.time()
        record: Dict[str, Any] = {
            "key": spec.key, "label": spec.label, "expectation": spec.expectation,
            "revision": spec.revision, "notes": spec.notes,
            "repo": spec.repo or (project.github_url or "").replace("https://github.com/", ""),
        }
        try:
            checkout = _prepare_tree(spec, project, workdir, patch_path)
        except Exception as exc:                       # noqa: BLE001 - recorded, not raised
            record.update(state="setup_failed", error=str(exc)[:600],
                          duration_s=round(time.time() - tree_started, 1))
            tree_records[spec.key] = record
            continue

        resolved = (checkout / ".respov_revision")
        record["resolved_commit"] = (
            resolved.read_text(encoding="utf-8").strip() if resolved.exists()
            else project.buggy_commit_id
        )

        # EVALUATION_NETWORK, not the agent default: no agent ever touches these
        # containers (the commands are ours and the POVs are curated), and the
        # staging build legitimately fetches -- `mvn dependency:build-classpath`
        # and `mvn install` pull plugins the project's own `package` never used,
        # and the coreutils harness clones gnulib. Under `--network none` those
        # fail and every POV is recorded `errored`, which is evidence for nothing.
        docker = DockerRunner(
            project, checkout, workdir, image_key=project_slug,
            network=EVALUATION_NETWORK,
        )
        if spec.image:
            # A control tree can be years newer than the CVE's base revision, and the
            # per-CVE builder image is pinned to that era: measured, plexus-utils'
            # 2025 tree needs Maven >= 3.6.3 and a parent POM the image's warm offline
            # ~/.m2 has never seen, so the control came back `errored` — a toolchain
            # failure that says nothing about the gap. Pointing the tree at a stock
            # image (e.g. maven:3.9-eclipse-temurin-17) lets the control actually run.
            # It is opt-in per tree: the baseline trees must keep the project's own
            # image, or "reproduces on the unpatched tree" would stop meaning what the
            # certification meant by it.
            docker.image_tag = spec.image
            record["image"] = spec.image
        elif not skip_docker_build:
            build = docker.build_image(build_timeout)
            if not build.ok:
                record.update(state="image_build_failed",
                              duration_s=round(time.time() - tree_started, 1))
                tree_records[spec.key] = record
                continue

        summary = res.evaluate_manifest(
            manifest=manifest, project_res_dir=res_dir, docker=docker,
            checkout_path=checkout, timeout_seconds=command_timeout,
            name_prefix=f"respov_verify_{spec.key.replace(':', '_')}",
            enforce_certification=False,
        )
        record.update(
            state="ran",
            duration_s=round(time.time() - tree_started, 1),
            staging_ok=not summary.get("staging_failed", False),
            totals={
                "reproduced": sum(1 for p in summary["povs"] if p["outcome"] == res.REPRODUCED),
                "blocked": sum(1 for p in summary["povs"] if p["outcome"] == res.BLOCKED),
                "errored": sum(1 for p in summary["povs"] if p["outcome"] == res.ERRORED),
            },
        )
        for pov in summary["povs"]:
            pov_id = pov["id"]
            in_scope = spec.povs is None or pov_id in spec.povs
            per_pov.setdefault(pov_id, {"pov_id": pov_id, "trees": {}})
            per_pov[pov_id]["trees"][spec.key] = {
                "outcome": pov["outcome"],
                "exit_code": pov.get("exit_code"),
                "expectation": spec.expectation if in_scope else "none",
                "verdict": _verdict(spec.expectation, pov["outcome"]) if in_scope else NOT_APPLICABLE,
                "command": pov.get("command"),
                "log": pov.get("log"),
                "revision": record.get("resolved_commit"),
            }
        tree_records[spec.key] = record

    for pov_record in per_pov.values():
        pov_record.update(_summarize_pov(pov_record["trees"]))

    record = {
        "project_slug": project_slug,
        "cve_id": manifest.get("cve_id", ""),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.time() - started, 1),
        "harness": "security_pipeline.reverify",
        "note": (
            "Independent re-execution record. Written by `respov reverify`; never "
            "written by anything that also edits manifest.json. 'errored' is a "
            "harness/build failure and is evidence for nothing."
        ),
        "trees": tree_records,
        "povs": per_pov,
    }

    out_path = verification_path(workspace_root, project_slug)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Merge, and merge by INFORMATIVENESS rather than recency. A run covering only
    # some trees must not erase earlier ones — but neither may a *worse* run of the
    # same tree overwrite a better one. That is not hypothetical: hutool's control
    # came back `blocked` in the project image, and a retry in a stock Maven image
    # errored and destroyed the passing result. `errored` is a toolchain failure and
    # is evidence for nothing, so it never displaces a conclusive outcome.
    if out_path.exists():
        try:
            prior = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prior = {}
        merged_trees = dict(prior.get("trees") or {})
        for key, tree in tree_records.items():
            if _tree_rank(tree) >= _tree_rank(merged_trees.get(key)):
                merged_trees[key] = tree
        merged_povs = dict(prior.get("povs") or {})
        for pov_id, pov_record in per_pov.items():
            existing = dict(merged_povs.get(pov_id) or {"pov_id": pov_id, "trees": {}})
            trees = dict(existing.get("trees") or {})
            for key, entry in pov_record["trees"].items():
                if _outcome_rank(entry) >= _outcome_rank(trees.get(key)):
                    trees[key] = entry
            existing["trees"] = trees
            existing.update(_summarize_pov(trees))
            merged_povs[pov_id] = existing
        record["trees"] = merged_trees
        record["povs"] = merged_povs
    out_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    if not keep_workdir:
        shutil.rmtree(workdir, ignore_errors=True)
    return record
