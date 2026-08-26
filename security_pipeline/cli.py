from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, List, Optional, Tuple

from . import paths
from . import retrofit
from .fetch import FetchError, fetch_project, fetch_projects
from .metadata import MetadataError, choose_alerts, load_alert, load_project_info
from .models import RunOptions
from .openrouter import (
    OpenRouterConfigError,
    describe_openrouter_config,
    is_openrouter_model,
)
from .pipeline import SecurityPipeline, existing_run_dirs, make_finding_id
from .stages import (
    EVALUATION_ONLY_STAGES,
    PROFILES,
    ExperimentConfigError,
    resolve_experiment,
)
from .zai import ZaiConfigError, describe_zai_config, is_zai_model


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run the exploiter -> patcher -> verifier pipeline")
    target = run.add_mutually_exclusive_group(required=False)
    target.add_argument("--alert", type=Path, help="Path to a finder alert JSON file")
    target.add_argument("--cve", help="CVE ID to run from the alerts directory")
    target.add_argument("--all", action="store_true", help="Run every alert in the alerts directory (default when no target is given)")
    run.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    run.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    run.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Run output directory")
    run.add_argument("--model", help="Claude alias/name or configured provider model ID")
    run.add_argument("--effort", default="high", help="Claude effort level")
    run.add_argument("--claude-bin", default="claude", help="Claude Code executable")
    run.add_argument("--permission-mode", default="bypassPermissions", help="Claude permission mode")
    run.add_argument("--agent-timeout-seconds", type=int, default=3600)
    run.add_argument("--command-timeout-seconds", type=int, default=1800)
    run.add_argument("--dry-run", action="store_true", help="Write context/state only; do not invoke Docker or Claude")
    run.add_argument("--skip-docker-build", action="store_true", help="Assume the computed Docker image already exists")
    run.add_argument(
        "--profile",
        default="full",
        help=(
            "Experiment arm / stage recipe. Choices: "
            + ", ".join(sorted(PROFILES))
            + ". 'full' runs exploiter->patcher->verifier; 'baseline' patches from the alert only; "
            "'baseline_eval' runs the exploiter to score the patch but withholds it from the patcher; "
            "'hardening' loops the patcher and exploiter to fix bypass variants (see --max-rounds)."
        ),
    )
    run.add_argument(
        "--max-rounds",
        type=int,
        default=4,
        help="Max patcher<->exploiter hardening rounds for the 'hardening' profile (minimum 1, default: 4)",
    )
    run.add_argument(
        "--max-correction-attempts",
        type=int,
        default=3,
        help=(
            "Max patcher attempts at each objective patch gate — POV-after, "
            "regressions, and each hardening round (minimum 1, default: 3). "
            "1 = one-shot gates; >1 feeds a failing check back to the patcher and "
            "re-checks. Keep equal across arms in an A/B."
        ),
    )
    run.add_argument(
        "--max-exploit-attempts",
        type=int,
        default=3,
        help=(
            "Max exploiter attempts at a POV that reproduces on the unpatched code "
            "(minimum 1, default: 3). 1 = one-shot gate; >1 feeds the failure back "
            "to the exploiter and lets it fix its POV."
        ),
    )
    run.add_argument(
        "--max-api-error-attempts",
        type=int,
        default=2,
        help=(
            "Max attempts per agent invocation when the Claude CLI dies on a "
            "transient API failure — a content-filter false positive or a dropped "
            "connection (minimum 1, default: 2). 1 = one such error kills the run; "
            ">1 re-rolls the SAME pinned model. Unrelated to the content-retry "
            "budgets above."
        ),
    )
    run.add_argument(
        "--stages",
        help="Comma-separated stage override (advanced ablations); takes precedence over --profile's stage list",
    )
    run.add_argument(
        "--patcher-evidence",
        choices=["full", "alert_only"],
        help="Override whether the patcher is shown the exploit evidence (default: derived from --profile)",
    )
    run.add_argument(
        "--label",
        default="",
        help="Free-form experiment tag (e.g. v1, new-prompt) recorded on each run for later grouping/filtering",
    )
    run.add_argument("--limit", type=int, help="Limit number of alerts to run (applied after skipping)")
    run.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=1,
        help=(
            "Run this many alerts concurrently (default: 1 = sequential, the old "
            "behavior; 0 = auto from Docker memory). Each run still executes its "
            "own stages in order."
        ),
    )
    run.add_argument(
        "--except",
        "--exclude",
        dest="exclude",
        nargs="+",
        action="extend",
        default=[],
        metavar="ID",
        help="Skip alerts whose CVE id, project slug, or alert filename matches any of these",
    )
    run.add_argument(
        "--rerun",
        "--force",
        action="store_true",
        help="Re-run alerts even if a prior run directory exists (default: skip already-run alerts)",
    )
    run.add_argument(
        "--stream",
        action="store_true",
        help="Stream agent output (stream-json) to agent_io/<name>/stream.jsonl so a live monitor can follow it token-by-token",
    )
    run.add_argument(
        "--no-fix-pov-eval",
        "--no-ground-truth-eval",  # legacy spelling, kept for existing scripts
        dest="no_fix_pov_eval",
        action="store_true",
        help="Skip the (non-gating) fixPOV evaluation stage that every profile runs last",
    )
    run.add_argument(
        "--no-residual-eval",
        dest="no_residual_eval",
        action="store_true",
        help=(
            "Skip the (non-gating) residual-gap POV stage that measures whether the "
            "patch closed holes the official upstream fix leaves open"
        ),
    )

    fetch = subparsers.add_parser("fetch", help="Fetch IRIS project sources from GitHub")
    fetch.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    fetch.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    fetch.add_argument("--projects-dir", type=Path, help="Output directory for cloned projects")
    fetch.add_argument("--project", help="Fetch a single project by dataset slug instead of walking the alerts dir")
    fetch.add_argument("--limit", type=int, help="Limit number of projects to fetch")
    fetch.add_argument("--timeout-seconds", type=int, default=300, help="Git clone timeout")

    fixpov = subparsers.add_parser(
        "fixpov",
        aliases=["gtpov"],  # legacy name, kept for existing scripts
        help="Manage curated fixPOVs (the non-gating exploit-coverage evaluator)",
    )
    gt_sub = fixpov.add_subparsers(dest="fixpov_command", required=True)

    gt_validate = gt_sub.add_parser(
        "validate",
        help="Certify a project's POVs: reproduce on unpatched source, blocked by the official fix",
    )
    gt_validate.add_argument("--project", help="Project slug to certify")
    gt_validate.add_argument("--all", action="store_true", help="Certify every project that has a manifest")
    gt_validate.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    gt_validate.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    gt_validate.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    gt_validate.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    gt_validate.add_argument("--keep-workdir", action="store_true", help="Keep the temporary before/after checkouts for debugging")
    gt_validate.add_argument(
        "--jobs", type=int, default=0,
        help="Certify this many projects concurrently (0 = auto from Docker memory). Each project still runs its own POVs internally.",
    )

    gt_replay = gt_sub.add_parser(
        "replay",
        help="Replay a project's POVs against its existing accepted pipeline runs",
    )
    gt_replay.add_argument("--project", required=True, help="Project slug whose POVs should be replayed")
    gt_replay.add_argument(
        "--run",
        dest="run_ids",
        action="append",
        metavar="RUN_ID",
        help=(
            "Replay only this matching run ID (repeatable). By default every "
            "accepted run for the project is updated."
        ),
    )
    gt_replay.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    gt_replay.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    gt_replay.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Existing pipeline run directory")
    gt_replay.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    gt_replay.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    gt_replay.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    gt_replay.add_argument(
        "--from-worktree",
        action="store_true",
        help=(
            "Score each run's preserved worktree instead of reconstructing it from "
            "the vulnerable revision plus the run's recorded patch. Reconstruction "
            "is the default because it works after worktrees are pruned and pins "
            "the base commit the fixPOVs were certified against."
        ),
    )
    gt_replay.add_argument(
        "--keep-checkout",
        action="store_true",
        help="Keep the reconstruction checkout (and its build output) for inspection",
    )
    gt_replay.add_argument(
        "--include-rejected",
        action="store_true",
        help=(
            "Also score rejected runs that still carry a product patch. Their "
            "verdict was the pipeline's own gate (e.g. a simulated POV that could "
            "never be blocked), not a judgement of the patch — so the patch can "
            "still be measured against the curated POVs. Non-gating; the run's "
            "verdict is unchanged."
        ),
    )

    gt_replay_patch = gt_sub.add_parser(
        "replay-patch",
        help=(
            "Score one caller-supplied patch (not tied to a pipeline run) against "
            "a project's curated fixPOVs"
        ),
    )
    gt_replay_patch.add_argument("--project", required=True, help="Project slug to score against")
    gt_replay_patch.add_argument(
        "--patch-file", type=Path, required=True,
        help="A git-apply-able unified diff (file headers included) to apply to the vulnerable revision",
    )
    gt_replay_patch.add_argument("--out", type=Path, required=True, help="Where to write the results JSON")
    gt_replay_patch.add_argument(
        "--base-revision", default=None,
        help=(
            "Reconstruct on this commit instead of the dataset's buggy_commit_id, for a patch "
            "written against a different pin of the same CVE. Each POV is first re-run on the "
            "UNPATCHED tree there and only counts if it still reproduces."
        ),
    )
    gt_replay_patch.add_argument(
        "--label", default=None,
        help="Distinguishes this patch's scratch reconstruction dir from others of the same project (default: 'external')",
    )
    gt_replay_patch.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    gt_replay_patch.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Where to cache the reconstruction checkout")
    gt_replay_patch.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    gt_replay_patch.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    gt_replay_patch.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    gt_replay_patch.add_argument("--keep-checkout", action="store_true", help="Keep the reconstruction checkout for inspection")

    retro = subparsers.add_parser(
        "retrofit",
        help=(
            "Replay the regression gate and the verifier against existing runs' "
            "patches, without re-patching them"
        ),
        description=(
            "Assess-only: runs the objective gates a finished run's profile did "
            "not have when it ran, and records whether its patch would have "
            "cleared them. The patch, the diff, and the run's verdict are never "
            "modified — so fixPOV and residual scores stay valid."
        ),
    )
    retro.add_argument("--project", help="Project slug to retrofit (default: every project with runs)")
    retro.add_argument(
        "--run",
        dest="run_ids",
        action="append",
        metavar="RUN_ID",
        help="Retrofit only this run ID (repeatable). Requires --project.",
    )
    retro.add_argument(
        "--profile",
        default="baseline",
        help=(
            "Only retrofit runs recorded under this profile (default: baseline). "
            "Pass 'any' to retrofit every run regardless of profile."
        ),
    )
    retro.add_argument(
        "--gates",
        default=",".join(retrofit.RETROFIT_GATES),
        help=(
            f"Comma-separated gates to replay (default: {','.join(retrofit.RETROFIT_GATES)}; "
            f"available: {','.join(retrofit.AVAILABLE_GATES)}). A gate the run "
            "already ran natively is skipped, so its original result is never "
            "overwritten."
        ),
    )
    retro.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    retro.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    retro.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Existing pipeline run directory")
    retro.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-command timeout")
    retro.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    retro.add_argument("--agent-timeout-seconds", type=int, default=3600, help="Verifier agent timeout")
    retro.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    retro.add_argument("--model", default=None, help="Model for the verifier agent (default: the pipeline default)")
    retro.add_argument("--effort", default="high", help="Reasoning effort for the verifier agent")
    retro.add_argument("--claude-bin", default="claude", help="Path to the claude binary")
    retro.add_argument(
        "--from-worktree",
        action="store_true",
        help=(
            "Assess each run's preserved worktree instead of reconstructing it "
            "from the vulnerable revision plus the run's recorded patch."
        ),
    )
    retro.add_argument(
        "--keep-checkout",
        action="store_true",
        help="Keep the reconstruction checkouts (and their build output) for inspection",
    )
    retro.add_argument(
        "--include-rejected",
        action="store_true",
        help="Also assess rejected runs that still carry a product patch",
    )
    retro.add_argument(
        "--force",
        action="store_true",
        help=(
            "Re-assess gates the run already ran, replacing the retrofit's own "
            "recorded outcome. A gate the retrofit previously ERRORED on is "
            "retried automatically and needs no --force."
        ),
    )
    retro.add_argument(
        "--dry-run",
        action="store_true",
        help="List the runs that would be retrofitted and exit, without Docker or agents",
    )

    rerunv = subparsers.add_parser(
        "rerun-verifier",
        help="Re-run the verifier for a run whose verifier crashed; flip it to accepted if it now passes",
        description=(
            "For a run rejected only because the verifier AGENT crashed (an expired "
            "OAuth session, structured-output-retry exhaustion, a transient API "
            "error) while every objective gate passed. Re-runs the verifier on the "
            "run's saved review task and, ONLY if it accepts, flips the run to "
            "accepted. A genuine 'rejected' verdict is left as a rejection."
        ),
    )
    rerunv.add_argument("--run", required=True, help="Run ID to re-verify")
    rerunv.add_argument("--project", help="Project slug (informational; not required)")
    rerunv.add_argument("--model", default=None, help="Model for the verifier agent (default: the pipeline default)")
    rerunv.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    rerunv.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    rerunv.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Existing pipeline run directory")

    gt_status = gt_sub.add_parser("status", help="Show fixPOV coverage per project")
    gt_status.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")

    gt_list = gt_sub.add_parser(
        "list-projects",
        help="List project slugs with local source available (candidates for POV generation/validation)",
    )
    gt_list.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")

    respov = subparsers.add_parser(
        "respov",
        help=(
            "Manage residual-gap POVs (exploits the OFFICIAL fix leaves open; "
            "scores whether a patch beat upstream)"
        ),
    )
    res_sub = respov.add_subparsers(dest="respov_command", required=True)

    res_validate = res_sub.add_parser(
        "validate",
        help=(
            "Certify residual POVs with the inverted oracle: reproduce on unpatched "
            "source AND still reproduce after the official fix"
        ),
    )
    res_validate.add_argument("--project", help="Project slug to certify")
    res_validate.add_argument("--all", action="store_true", help="Certify every project that has a residual manifest")
    res_validate.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    res_validate.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    res_validate.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    res_validate.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    res_validate.add_argument("--keep-workdir", action="store_true", help="Keep the temporary before/after checkouts for debugging")
    res_validate.add_argument(
        "--jobs", type=int, default=0,
        help="Certify this many projects concurrently (0 = auto from Docker memory)",
    )

    res_reverify = res_sub.add_parser(
        "reverify",
        help=(
            "Independently re-execute a suite's residual POVs and record the result "
            "outside the manifest (audit trail + the falsifiability control)"
        ),
    )
    res_reverify.add_argument("--project", help="Project slug to re-verify")
    res_reverify.add_argument("--all", action="store_true", help="Re-verify every project with a residual manifest")
    res_reverify.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    res_reverify.add_argument(
        "--at", dest="at_revisions", action="append", metavar="REF", default=[],
        help=(
            "Also run the POVs against this upstream revision (commit, tag or branch), "
            "expecting them to be BLOCKED there. Repeatable. This is the negative "
            "control the residual oracle lacks: point it at the later commit that "
            "upstream fixed the gap in."
        ),
    )
    res_reverify.add_argument(
        "--still-open", dest="still_open_revisions", action="append", metavar="REF", default=[],
        help=(
            "Also run the POVs against this upstream revision expecting them to still "
            "REPRODUCE there. The mirror of --at: use it to execute an 'open at head' "
            "claim (point it at the default branch) instead of asserting it from source "
            "reading. A POV that comes back blocked refutes the claim."
        ),
    )
    res_reverify.add_argument(
        "--at-pov", dest="tree_pov_scope", action="append", metavar="POV_ID", default=[],
        help=(
            "Apply the --at / --still-open expectation only to these POV ids "
            "(repeatable). Needed when one suite's POVs have different statuses — "
            "e.g. one upstream commit closed one sink and left the other open, where "
            "a suite-wide expectation would report the untouched POV as a "
            "contradiction while it is actually confirming the claim."
        ),
    )
    res_reverify.add_argument(
        "--control-image", metavar="IMAGE",
        help=(
            "Run the --at / --still-open trees in this stock docker image (e.g. "
            "maven:3.9-eclipse-temurin-17) instead of the CVE's pinned builder image. "
            "Use when a control tree is too new for that image's toolchain, which "
            "otherwise reports `errored` and loses the control. Baseline trees always "
            "keep the project image."
        ),
    )
    res_reverify.add_argument(
        "--repo", metavar="OWNER/NAME|URL",
        help=(
            "Clone --at revisions from this repository instead of the dataset's "
            "recorded github_url. Accepts owner/name or a full clone URL. Needed "
            "wherever the dataset's URL is not upstream: zip4j is recorded as "
            "iris-sast/zip4j (a synthetic decompiled-source repo), binutils' URL "
            "404s, and libtiff's canonical home is GitLab while its GitHub repo is "
            "an archived mirror."
        ),
    )
    res_reverify.add_argument(
        "--skip-baseline", action="store_true",
        help="Skip the unpatched / official-fix trees and run only the --at revisions",
    )
    res_reverify.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    res_reverify.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    res_reverify.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    res_reverify.add_argument("--keep-workdir", action="store_true", help="Keep the checkouts for debugging")

    res_replay = res_sub.add_parser(
        "replay",
        help="Replay a project's residual POVs against its existing accepted pipeline runs",
    )
    res_replay.add_argument("--project", required=True, help="Project slug whose residual POVs should be replayed")
    res_replay.add_argument(
        "--run", dest="run_ids", action="append", metavar="RUN_ID",
        help="Replay only this matching run ID (repeatable). Default: every accepted run for the project.",
    )
    res_replay.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    res_replay.add_argument("--alerts-dir", type=Path, default=Path("finder_results_filtered"), help="Filtered alerts directory")
    res_replay.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Existing pipeline run directory")
    res_replay.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    res_replay.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    res_replay.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    res_replay.add_argument(
        "--from-worktree", action="store_true",
        help=(
            "Score each run's preserved worktree instead of reconstructing it from "
            "the vulnerable revision plus the run's recorded patch (the default)."
        ),
    )
    res_replay.add_argument(
        "--keep-checkout", action="store_true",
        help="Keep the reconstruction checkout (and its build output) for inspection",
    )
    res_replay.add_argument(
        "--include-rejected", action="store_true",
        help=(
            "Also score rejected runs that still carry a product patch (verdict "
            "unchanged; non-gating). See fixpov replay --include-rejected."
        ),
    )

    res_replay_patch = res_sub.add_parser(
        "replay-patch",
        help=(
            "Score one caller-supplied patch (not tied to a pipeline run) against "
            "a project's curated residual POVs"
        ),
    )
    res_replay_patch.add_argument("--project", required=True, help="Project slug to score against")
    res_replay_patch.add_argument(
        "--patch-file", type=Path, required=True,
        help="A git-apply-able unified diff (file headers included) to apply to the vulnerable revision",
    )
    res_replay_patch.add_argument("--out", type=Path, required=True, help="Where to write the results JSON")
    res_replay_patch.add_argument(
        "--base-revision", default=None,
        help=(
            "Reconstruct on this commit instead of the dataset's buggy_commit_id, for a patch "
            "written against a different pin of the same CVE. Each POV is first re-run on the "
            "UNPATCHED tree there and only counts if it still reproduces."
        ),
    )
    res_replay_patch.add_argument(
        "--label", default=None,
        help="Distinguishes this patch's scratch reconstruction dir from others of the same project (default: 'external')",
    )
    res_replay_patch.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")
    res_replay_patch.add_argument("--runs-dir", type=Path, default=Path("security_pipeline_runs"), help="Where to cache the reconstruction checkout")
    res_replay_patch.add_argument("--command-timeout-seconds", type=int, default=1800, help="Per-POV command timeout")
    res_replay_patch.add_argument("--build-timeout-seconds", type=int, default=3600, help="Docker image build timeout")
    res_replay_patch.add_argument("--skip-docker-build", action="store_true", help="Assume the project image already exists")
    res_replay_patch.add_argument("--keep-checkout", action="store_true", help="Keep the reconstruction checkout for inspection")

    res_status = res_sub.add_parser("status", help="Show residual-gap POV certification per project")
    res_status.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")

    res_list = res_sub.add_parser(
        "list-projects",
        help="List project slugs that have a residual-gap POV manifest",
    )
    res_list.add_argument("--workspace-root", type=Path, default=Path.cwd(), help="Workspace root")

    return parser


def _resolve_under_workspace(path: Path, workspace_root: Path) -> Path:
    if path.is_absolute():
        return path
    candidate = workspace_root / path
    if candidate.exists():
        return candidate
    return Path.cwd() / path


def _load_project_rows(workspace_root: Path) -> dict:
    try:
        return load_project_info(paths.project_info_csv(workspace_root))
    except (OSError, KeyError):
        return {}


def _read_verdict(run_dir: Path) -> Optional[dict]:
    verdict_path = run_dir / "verdict.json"
    if not verdict_path.exists():
        return None
    try:
        return json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _is_dry_run_only(run_dir: Path) -> bool:
    """A run directory that only recorded a --dry-run should not block real runs."""
    verdict = _read_verdict(run_dir)
    return bool(verdict) and verdict.get("status") == "dry_run"


def _run_profile(run_dir: Path) -> str:
    """Experiment arm a prior run belonged to. Runs written before profiles
    existed have no field and are treated as 'full'."""
    verdict = _read_verdict(run_dir)
    return (verdict or {}).get("profile", "full")


def plan_alerts(
    alerts: List[Path],
    *,
    workspace_root: Path,
    runs_dir: Path,
    exclude: List[str],
    rerun: bool,
    profile: str = "full",
) -> List[Tuple[Path, Optional[str]]]:
    """Pair each alert with a skip reason, or None if it should run.

    A prior run only blocks a new run when it belongs to the *same* profile, so
    the baseline arm can be run over projects the full pipeline already covered.
    """
    exclude_set = {token.strip() for token in exclude if token and token.strip()}
    need_rows = bool(exclude_set) or not rerun
    project_rows = _load_project_rows(workspace_root) if need_rows else {}

    plan: List[Tuple[Path, Optional[str]]] = []
    for alert_path in alerts:
        try:
            alert = load_alert(alert_path)
        except (OSError, json.JSONDecodeError):
            plan.append((alert_path, None))  # let the pipeline surface the load error
            continue

        cve_id = alert.get("cve_id")
        row = project_rows.get(cve_id) if cve_id else None
        project_slug = row.get("project_slug") if row else None

        tokens = {token for token in (cve_id, project_slug, alert_path.name, alert_path.stem) if token}
        matched = exclude_set & tokens
        if matched:
            plan.append((alert_path, f"excluded ({', '.join(sorted(matched))})"))
            continue

        if not rerun and project_slug and cve_id:
            finding_id = make_finding_id(alert_path, SimpleNamespace(project_slug=project_slug, cve_id=cve_id))
            prior = [
                d
                for d in existing_run_dirs(runs_dir, finding_id)
                if not _is_dry_run_only(d) and _run_profile(d) == profile
            ]
            if prior:
                plan.append((alert_path, f"already ran ({prior[-1].name}); use --rerun to force"))
                continue

        plan.append((alert_path, None))
    return plan


def run_command(args: argparse.Namespace) -> int:
    workspace_root = args.workspace_root.resolve()
    alerts_dir = _resolve_under_workspace(args.alerts_dir, workspace_root).resolve()
    runs_dir = _resolve_under_workspace(args.runs_dir, workspace_root).resolve()
    alert_path = _resolve_under_workspace(args.alert, workspace_root).resolve() if args.alert else None

    run_all = bool(args.all) or not (args.alert or args.cve)
    try:
        alerts = choose_alerts(alerts_dir, alert_path, args.cve, run_all)
    except MetadataError as exc:
        print(f"security-pipeline: {exc}", file=sys.stderr)
        return 2

    if args.max_rounds < 1:
        print("security-pipeline: --max-rounds must be at least 1", file=sys.stderr)
        return 2

    if args.max_correction_attempts < 1:
        print("security-pipeline: --max-correction-attempts must be at least 1", file=sys.stderr)
        return 2

    if args.max_exploit_attempts < 1:
        print("security-pipeline: --max-exploit-attempts must be at least 1", file=sys.stderr)
        return 2

    # Alternate-provider models route every agent through a gateway. Validate
    # credentials before Docker does any work, rather than surfacing an opaque
    # authentication failure several minutes into the first agent.
    if is_zai_model(args.model) and not args.dry_run:
        try:
            summary = describe_zai_config(args.model)
        except ZaiConfigError as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2
        print(
            f"security-pipeline: routing {summary['model']} through "
            f"{summary['base_url']} (from {summary['settings_file']})",
            file=sys.stderr,
        )
    elif is_openrouter_model(args.model) and not args.dry_run:
        try:
            summary = describe_openrouter_config(args.model)
        except OpenRouterConfigError as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2
        print(
            f"security-pipeline: routing {summary['model']} as "
            f"{summary['request_model']} through "
            f"{summary['base_url']} (credential: {summary['credential_source']})",
            file=sys.stderr,
        )

    if args.max_api_error_attempts < 1:
        print("security-pipeline: --max-api-error-attempts must be at least 1", file=sys.stderr)
        return 2

    stages_override = (
        [token for token in args.stages.split(",") if token.strip()] if args.stages else None
    )
    try:
        experiment = resolve_experiment(
            profile=args.profile,
            stages=stages_override,
            patcher_evidence=args.patcher_evidence,
        )
    except ExperimentConfigError as exc:
        print(f"security-pipeline: {exc}", file=sys.stderr)
        return 2

    # Each flag drops only its own stage: they are independent measurements, and
    # --no-fix-pov-eval silently disabling the residual score too would be a
    # surprise. EVALUATION_ONLY_STAGES stays the authority on which stages are
    # droppable at all.
    skip_stages = {
        name
        for name, requested in (
            ("fix_pov_eval", getattr(args, "no_fix_pov_eval", False)),
            ("residual_eval", getattr(args, "no_residual_eval", False)),
        )
        if requested and name in EVALUATION_ONLY_STAGES
    }
    if skip_stages:
        trimmed = [s for s in experiment.stages if s not in skip_stages]
        if trimmed != list(experiment.stages):
            try:
                experiment = resolve_experiment(
                    profile=experiment.profile,
                    stages=trimmed,
                    patcher_evidence=experiment.patcher_evidence,
                )
            except ExperimentConfigError as exc:
                print(f"security-pipeline: {exc}", file=sys.stderr)
                return 2

    plan = plan_alerts(
        alerts,
        workspace_root=workspace_root,
        runs_dir=runs_dir,
        exclude=args.exclude or [],
        rerun=args.rerun,
        profile=experiment.profile,
    )

    summaries = []
    exit_code = 0

    runnable: List[Path] = []
    for planned_alert, skip_reason in plan:
        if skip_reason is None:
            runnable.append(planned_alert)
            continue
        summary = {
            "alert": str(planned_alert),
            "run_id": "",
            "status": "skipped",
            "reason": skip_reason,
            "run_dir": "",
        }
        summaries.append(summary)
        print(json.dumps(summary, sort_keys=True))

    if args.limit is not None:
        runnable = runnable[: args.limit]

    if not runnable:
        if len(summaries) > 1:
            print(json.dumps({"runs": summaries}, indent=2, sort_keys=True))
        return exit_code

    options = RunOptions(
        workspace_root=workspace_root,
        alerts_dir=alerts_dir,
        runs_dir=runs_dir,
        model=args.model,
        effort=args.effort,
        claude_bin=args.claude_bin,
        permission_mode=args.permission_mode,
        agent_timeout_seconds=args.agent_timeout_seconds,
        command_timeout_seconds=args.command_timeout_seconds,
        dry_run=args.dry_run,
        skip_docker_build=args.skip_docker_build,
        label=(args.label or "").strip(),
        stream=args.stream,
        max_hardening_rounds=args.max_rounds,
        max_correction_attempts=args.max_correction_attempts,
        max_exploit_attempts=args.max_exploit_attempts,
        max_api_error_attempts=args.max_api_error_attempts,
    )
    pipeline = SecurityPipeline(options, experiment)

    def _run_one(alert: Path) -> dict:
        """Run one alert and reduce it to a printable summary.

        Returns the summary instead of printing it so the parallel path can emit
        results in input order rather than completion order. An exception before
        any run state exists is reported as an ``error`` summary — one bad alert
        must not take down the rest of the batch.
        """
        try:
            state = pipeline.run_alert(alert)
        except Exception as exc:  # noqa: BLE001 - report and keep going
            return {"alert": str(alert), "error": str(exc)}
        return {
            "alert": str(alert),
            "run_id": state.run_id,
            "status": state.status,
            "reason": state.reason,
            "run_dir": str(state.run_dir) if state.run_dir else "",
        }

    jobs = args.jobs if args.jobs > 0 else _auto_docker_jobs(len(runnable))
    jobs = max(1, min(jobs, len(runnable) or 1))
    if jobs == 1:
        results = [_run_one(alert) for alert in runnable]
    else:
        # Threads, not processes: run_alert spends its whole life waiting on
        # `claude` and `docker` subprocesses, so the GIL is never the limit.
        # SecurityPipeline holds no per-run mutable state (run-dir allocation is
        # locked in pipeline.claim_run_dir), so one instance is safe to share.
        from concurrent.futures import ThreadPoolExecutor

        print(f"security-pipeline: running {len(runnable)} alerts, {jobs} at a time", file=sys.stderr)
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(_run_one, runnable))

    for summary in results:
        summaries.append(summary)
        print(json.dumps(summary, sort_keys=True))
        if "error" in summary:
            print(
                f"security-pipeline: failed before run state for {summary['alert']}: {summary['error']}",
                file=sys.stderr,
            )
            exit_code = 1
        elif summary["status"] not in {"accepted", "dry_run"}:
            exit_code = 1

    if len(summaries) > 1:
        print(json.dumps({"runs": summaries}, indent=2, sort_keys=True))
    return exit_code


def fetch_command(args: argparse.Namespace) -> int:
    workspace_root = args.workspace_root.resolve()

    if args.project:
        try:
            target_dir = fetch_project(
                workspace_root=workspace_root,
                project_slug=args.project,
                projects_dir=args.projects_dir,
                timeout_seconds=args.timeout_seconds,
            )
        except FetchError as exc:
            print(f"security-pipeline: fetch failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"fetched": 1, "project_slug": args.project, "path": str(target_dir)}, indent=2))
        return 0

    alerts_dir = _resolve_under_workspace(args.alerts_dir, workspace_root).resolve()

    if not alerts_dir.exists():
        print(f"security-pipeline: alerts directory does not exist: {alerts_dir}", file=sys.stderr)
        return 2

    results = fetch_projects(
        workspace_root=workspace_root,
        alerts_dir=alerts_dir,
        projects_dir=args.projects_dir,
        limit=args.limit,
        timeout_seconds=args.timeout_seconds,
    )

    ok_count = sum(1 for r in results if r["status"] == "ok")
    fail_count = sum(1 for r in results if r["status"] == "failed")
    print(json.dumps({"fetched": ok_count, "failed": fail_count, "total": len(results)}, indent=2))
    return 0 if fail_count == 0 else 1


def _certify_one_project(
    project_slug: str,
    workspace_root: Path,
    *,
    command_timeout: int,
    build_timeout: int,
    skip_docker_build: bool,
    keep_workdir: bool,
) -> dict:
    """Build the project, run every POV against the unpatched source and against
    the source with the official fix applied, and record the reproduce→blocked
    certification back into the manifest. Returns a per-project summary dict."""
    import shutil
    import subprocess

    from . import fix_pov as gt
    from .docker_runner import EVALUATION_NETWORK, DockerRunner
    from .logging_io import write_json
    from .metadata import resolve_project_metadata_by_slug

    project = resolve_project_metadata_by_slug(project_slug, workspace_root)
    manifest = gt.load_manifest(workspace_root, project_slug)
    if manifest is None:
        raise MetadataError(f"No fixPOV manifest for {project_slug}")

    gt_dir = gt.project_dir(workspace_root, project_slug)
    fix_ref = manifest.get("fix_reference", {}) or {}
    patch_name = fix_ref.get("official_fix_patch", gt.OFFICIAL_FIX_DEFAULT)
    patch_path = gt_dir / patch_name if patch_name else None

    workdir = workspace_root / ".fixpov_validate" / project_slug
    before_dir = workdir / "before"
    after_dir = workdir / "after"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    before_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(project.source_path, before_dir)
    shutil.copytree(project.source_path, after_dir)

    patched = False
    if patch_path and patch_path.exists():
        proc = subprocess.run(
            ["git", "-C", str(after_dir), "apply", "--whitespace=nowarn", str(patch_path)],
            capture_output=True, text=True, errors="replace", check=False,
        )
        if proc.returncode != 0:
            raise MetadataError(
                f"official fix patch did not apply to {project_slug}: {proc.stderr.strip()}"
            )
        patched = True

    docker = DockerRunner(project, before_dir, workdir, image_key=project_slug)
    if not skip_docker_build:
        build = docker.build_image(build_timeout)
        if not build.ok:
            raise MetadataError(f"docker image build failed for {project_slug}")

    # Certification is what this command *produces*, so it cannot also require it.
    before_docker = DockerRunner(
        project, before_dir, workdir, image_key=project_slug,
        network=EVALUATION_NETWORK,
    )
    before = gt.evaluate_manifest(
        manifest=manifest, project_gt_dir=gt_dir, docker=before_docker,
        checkout_path=before_dir, timeout_seconds=command_timeout, name_prefix="fixpov_before",
        enforce_certification=False,
    )

    after = None
    if patched:
        after_docker = DockerRunner(
            project, after_dir, workdir, image_key=project_slug,
            network=EVALUATION_NETWORK,
        )
        after = gt.evaluate_manifest(
            manifest=manifest, project_gt_dir=gt_dir, docker=after_docker,
            checkout_path=after_dir, timeout_seconds=command_timeout, name_prefix="fixpov_after",
            enforce_certification=False,
        )

    before_by_id = {pov["id"]: pov for pov in before["povs"]}
    after_by_id = {pov["id"]: pov for pov in (after["povs"] if after else [])}
    certified_count = 0
    for pov in manifest["povs"]:
        pov_id = pov["id"]
        b = before_by_id.get(pov_id)
        a = after_by_id.get(pov_id)
        validation = {
            "before": None if b is None else {
                "exit_code": b["exit_code"], "reproduced": b["outcome"] == gt.REPRODUCED,
                "outcome": b["outcome"], "at": "unpatched-source",
            },
            "after": None if a is None else {
                "exit_code": a["exit_code"], "reproduced": a["outcome"] == gt.REPRODUCED,
                "outcome": a["outcome"], "at": f"official-fix ({patch_name})",
            },
            "certified": bool(b and b["outcome"] == gt.REPRODUCED and a and a["outcome"] == gt.BLOCKED),
            # Binds the certification to what was certified: the POV sources, the
            # command/exit-code contract, the official fix, and the revision. An
            # edit to any of them makes the recorded hash stop matching and the
            # POV is excluded from scoring until it is re-certified.
            "content_hash": gt.content_fingerprint(gt_dir, manifest, pov),
            "ran_at": before["generated_at"],
        }
        pov["validation"] = validation
        if validation["certified"]:
            certified_count += 1

    write_json(gt.manifest_path(workspace_root, project_slug), manifest)

    if not keep_workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    return {
        "project_slug": project_slug,
        "povs": len(manifest["povs"]),
        "certified": certified_count,
        "before_reproduced": before["reproduced"],
        "before_total": before["total"],
        "after_blocked": None if after is None else after["blocked"],
        "after_total": None if after is None else after["total"],
        "official_fix_applied": patched,
        "fully_certified": certified_count == len(manifest["povs"]) and patched,
    }


def _certify_one_residual_project(
    project_slug: str,
    workspace_root: Path,
    *,
    command_timeout: int,
    build_timeout: int,
    skip_docker_build: bool,
    keep_workdir: bool,
) -> dict:
    """Certify residual-gap POVs with the **inverted** oracle.

    Same two checkouts as ``_certify_one_project`` — pristine source, and source
    with ``official_fix.patch`` applied — but the passing condition flips: a
    residual POV is certified when it reproduces on the unpatched tree AND *still
    reproduces* after the official fix, which is what proves the gap is genuinely
    one upstream left open.

    Applying the official fix is mandatory here, not optional as it is for ground
    truth: without the "after" run there is nothing to distinguish a residual POV
    from an ordinary one, so a project whose patch does not apply certifies
    nothing rather than certifying on the "before" run alone.
    """
    import shutil
    import subprocess

    from . import residual as res
    from .docker_runner import EVALUATION_NETWORK, DockerRunner
    from .logging_io import write_json
    from .metadata import resolve_project_metadata_by_slug

    project = resolve_project_metadata_by_slug(project_slug, workspace_root)
    manifest = res.load_manifest(workspace_root, project_slug)
    if manifest is None:
        raise MetadataError(f"No residual manifest for {project_slug}")

    res_dir = res.project_dir(workspace_root, project_slug)
    fix_ref = manifest.get("fix_reference", {}) or {}
    patch_name = fix_ref.get("official_fix_patch", res.OFFICIAL_FIX_DEFAULT)
    patch_path = res_dir / patch_name if patch_name else None
    if not (patch_path and patch_path.exists()):
        raise MetadataError(
            f"residual certification for {project_slug} requires {patch_name} "
            "(the official fix these POVs must survive)"
        )

    workdir = workspace_root / ".respov_validate" / project_slug
    before_dir = workdir / "before"
    after_dir = workdir / "after"
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    before_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(project.source_path, before_dir)
    shutil.copytree(project.source_path, after_dir)

    proc = subprocess.run(
        ["git", "-C", str(after_dir), "apply", "--whitespace=nowarn", str(patch_path)],
        capture_output=True, text=True, errors="replace", check=False,
    )
    if proc.returncode != 0:
        raise MetadataError(
            f"official fix patch did not apply to {project_slug}: {proc.stderr.strip()}"
        )

    docker = DockerRunner(project, before_dir, workdir, image_key=project_slug)
    if not skip_docker_build:
        build = docker.build_image(build_timeout)
        if not build.ok:
            raise MetadataError(f"docker image build failed for {project_slug}")

    before_docker = DockerRunner(
        project, before_dir, workdir, image_key=project_slug,
        network=EVALUATION_NETWORK,
    )
    before = res.evaluate_manifest(
        manifest=manifest, project_res_dir=res_dir, docker=before_docker,
        checkout_path=before_dir, timeout_seconds=command_timeout,
        name_prefix="respov_before", enforce_certification=False,
    )
    after_docker = DockerRunner(
        project, after_dir, workdir, image_key=project_slug,
        network=EVALUATION_NETWORK,
    )
    after = res.evaluate_manifest(
        manifest=manifest, project_res_dir=res_dir, docker=after_docker,
        checkout_path=after_dir, timeout_seconds=command_timeout,
        name_prefix="respov_after", enforce_certification=False,
    )

    before_by_id = {pov["id"]: pov for pov in before["povs"]}
    after_by_id = {pov["id"]: pov for pov in after["povs"]}
    certified_count = 0
    for pov in manifest["povs"]:
        pov_id = pov["id"]
        b = before_by_id.get(pov_id)
        a = after_by_id.get(pov_id)
        validation = {
            "before": None if b is None else {
                "exit_code": b["exit_code"], "reproduced": b["outcome"] == res.REPRODUCED,
                "outcome": b["outcome"], "at": "unpatched-source",
            },
            "after": None if a is None else {
                "exit_code": a["exit_code"], "reproduced": a["outcome"] == res.REPRODUCED,
                "outcome": a["outcome"], "at": f"official-fix ({patch_name})",
            },
            # The inverted contract: reproduces BEFORE and STILL reproduces AFTER.
            "certified": bool(
                b and a and res.certifies(b["outcome"], a["outcome"])
            ),
            "content_hash": res.content_fingerprint(res_dir, manifest, pov),
            "ran_at": before["generated_at"],
        }
        pov["validation"] = validation
        if validation["certified"]:
            certified_count += 1

    write_json(res.manifest_path(workspace_root, project_slug), manifest)

    if not keep_workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    return {
        "project_slug": project_slug,
        "povs": len(manifest["povs"]),
        "certified": certified_count,
        "before_reproduced": before["matches_official_fix"],
        "before_total": before["total"],
        "after_still_reproduced": after["matches_official_fix"],
        "after_total": after["total"],
        "residual_of": manifest.get("residual_of", ""),
        "fully_certified": certified_count == len(manifest["povs"]),
    }


def manifest_path_for(workspace_root: Path, project_slug: str):
    from . import fix_pov as gt

    return gt.manifest_path(workspace_root, project_slug)


def _auto_docker_jobs(project_count: int) -> int:
    """Pick a safe default for how many pipeline/certification runs go at once.

    The limiter is Docker memory, not cores: each concurrent unit peaks at ~one
    Maven/JVM build (~1.5-2 GB). Budget ~3 GB per concurrent unit against
    Docker's memory (read from ``docker info``; assume 8 GB if unknown), clamped
    to [1, 4] and to the number of units. Shared by ``run --jobs 0`` and
    ``fixpov validate --jobs 0``, which are limited by the same resource.
    """
    import subprocess

    mem_gb = 8.0
    try:
        out = subprocess.run(
            ["docker", "info", "--format", "{{.MemTotal}}"],
            capture_output=True, text=True, errors="replace", timeout=15, check=False,
        )
        total = int((out.stdout or "").strip())
        if total > 0:
            mem_gb = total / (1024 ** 3)
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    by_mem = int(mem_gb // 3)
    return max(1, min(4, by_mem, project_count or 1))


# A rejected run's recorded patch is only worth reconstructing if it actually
# contains a product fix. Two things disqualify one: an empty patch (the run died
# before the patcher edited anything — a content-filter crash pre-edit, or
# `unable_to_patch` with nothing produced), and a runaway patch. The latter is
# real: a patcher that went off the rails bundled whole vendored source trees or
# build output into the diff (one dolphinscheduler run recorded a 144 MB
# patch_only.diff, a DependencyCheck run 70 MB), which will not apply during
# reconstruction anyway. A real fix here is kilobytes; the cap is generous.
_REJECTED_PATCH_MAX_BYTES = 1_000_000


def _rejected_run_has_scoreable_patch(run_dir: Path) -> bool:
    diff = run_dir / "git" / "patch_only.diff"
    try:
        size = diff.stat().st_size
    except OSError:
        return False
    if size == 0 or size > _REJECTED_PATCH_MAX_BYTES:
        return False
    # A diff that touches only the POV tree (no product change) is not a fix.
    try:
        text = diff.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines():
        if line.startswith("+++ b/") and ".security-pipeline/" not in line:
            return True
    return False


def _run_dirs_for_project(
    *,
    project,
    alerts_dir: Path,
    runs_dir: Path,
    include_rejected: bool = False,
) -> List[Path]:
    """Find run artifacts belonging to ``project`` worth replaying.

    Accepted runs always qualify. With ``include_rejected`` a rejected run also
    qualifies **if it still carries a scoreable product patch** — its verdict was
    the pipeline's own gate (e.g. an exploiter POV that could never be stopped),
    not a statement about the patch, so its diff can still be measured against the
    curated POVs. Runs whose patch is empty or runaway are skipped (and logged by
    the caller), never silently.

    Run JSON deliberately redacts the project slug and CVE. Reconstruct the
    finding IDs from the project's alert files instead of weakening that
    redaction contract just to support post-hoc evaluation.
    """
    from .metadata import alert_paths_for_cve

    matches = set()
    for alert_path in alert_paths_for_cve(alerts_dir, project.cve_id):
        finding_id = make_finding_id(alert_path, project)
        for run_dir in existing_run_dirs(runs_dir, finding_id):
            verdict = _read_verdict(run_dir)
            status = verdict.get("status") if verdict else None
            if status == "accepted":
                matches.add(run_dir)
            elif include_rejected and status == "rejected" and _rejected_run_has_scoreable_patch(run_dir):
                matches.add(run_dir)
    return sorted(matches)


def _select_replay_run_dirs(
    *,
    project,
    alerts_dir: Path,
    runs_dir: Path,
    requested_run_ids: Optional[List[str]],
    include_rejected: bool = False,
) -> List[Path]:
    available = _run_dirs_for_project(
        project=project, alerts_dir=alerts_dir, runs_dir=runs_dir,
        include_rejected=include_rejected,
    )
    if not requested_run_ids:
        return available

    by_id = {run_dir.name: run_dir for run_dir in available}
    selected = []
    for run_id in requested_run_ids:
        # RUN_ID is intentionally a basename, not an arbitrary path: replay
        # writes results into the selected run directory.
        if not run_id or Path(run_id).name != run_id:
            raise MetadataError(f"Invalid run ID {run_id!r}; pass a run directory name")
        run_dir = by_id.get(run_id)
        if run_dir is None:
            qualifier = "accepted or patch-bearing rejected" if include_rejected else "accepted"
            raise MetadataError(
                f"Run {run_id!r} is not an {qualifier} run for {project.project_slug}"
            )
        if run_dir not in selected:
            selected.append(run_dir)
    return selected


@dataclass(frozen=True)
class _ReplayFamily:
    """What distinguishes replaying one POV family from another.

    The reconstruction machinery (``_ReplayCheckout``, run selection, the
    reconstruct-or-fall-back-to-worktree loop) is identical for fixPOV and
    residual POVs — only the manifest, the evaluator, and the names of the
    artifacts differ. This descriptor carries exactly those differences so the
    driver (``_replay_eval``) stays single-sourced.
    """

    label: str            # human name for error messages ("fixPOV" / "residual")
    results_subdir: str   # run_dir/<here>/results.json  ("fix_pov" / "residual")
    replay_dirname: str   # runs_dir/<here>/<slug>       (".fixpov_replay" / ".respov_replay")
    command_prefix: str   # stale-command name prefix to purge ("fixpov" / "respov")
    step_name: str        # state.json step to replace ("fix_pov_eval" / "residual_eval")
    load_manifest: "Callable"
    project_dir: "Callable"
    evaluate: "Callable"  # (manifest, project_dir, docker, checkout, timeout) -> summary
    redact: "Callable"
    summary_fields: "Callable"  # summary -> family-specific numeric fields for row/step
    # (manifest, pov_results, setup_results) -> summary. Re-aggregates after a
    # POV's outcome has been rewritten, so the counts and the score stay derived
    # from the records rather than being patched up by hand -- see
    # ``_apply_oracle_revalidation``.
    summarize: "Callable"
    # Names the family wrote before it was renamed (runs recorded on the server
    # still carry them). A replay purges these too, so a legacy run comes out
    # with exactly one eval step and one set of POV commands, under the new names.
    legacy_command_prefixes: tuple = ()
    legacy_step_names: tuple = ()


def _fix_pov_summary_fields(summary: dict) -> dict:
    return {
        "total": summary["total"],
        "blocked": summary["blocked"],
        "reproduced": summary["reproduced"],
        "errored": summary["errored"],
        "score": summary["score"],
        "all_blocked": summary["all_blocked"],
    }


def _residual_summary_fields(summary: dict) -> dict:
    return {
        "total": summary["total"],
        "hardened_beyond_fix": summary["hardened_beyond_fix"],
        "matches_official_fix": summary["matches_official_fix"],
        "errored": summary["errored"],
        "score": summary["score"],
        "all_hardened": summary["all_hardened"],
    }


def _fix_pov_family() -> _ReplayFamily:
    from . import fix_pov as gt

    return _ReplayFamily(
        label="fixPOV",
        results_subdir="fix_pov",
        replay_dirname=".fixpov_replay",
        command_prefix="fixpov",
        step_name="fix_pov_eval",
        legacy_command_prefixes=("gtpov",),
        legacy_step_names=("ground_truth_eval",),
        load_manifest=gt.load_manifest,
        project_dir=gt.project_dir,
        evaluate=lambda manifest, project_dir, docker, checkout, timeout: gt.evaluate_manifest(
            manifest=manifest, project_gt_dir=project_dir, docker=docker,
            checkout_path=checkout, timeout_seconds=timeout, name_prefix="fixpov",
        ),
        redact=gt.redact_for_run_artifact,
        summary_fields=_fix_pov_summary_fields,
        summarize=gt.summarize,
    )


def _residual_family() -> _ReplayFamily:
    from . import residual as res

    return _ReplayFamily(
        label="residual",
        results_subdir="residual",
        replay_dirname=".respov_replay",
        command_prefix="respov",
        step_name="residual_eval",
        load_manifest=res.load_manifest,
        project_dir=res.project_dir,
        evaluate=lambda manifest, project_dir, docker, checkout, timeout: res.evaluate_manifest(
            manifest=manifest, project_res_dir=project_dir, docker=docker,
            checkout_path=checkout, timeout_seconds=timeout, name_prefix="respov",
        ),
        redact=res.redact_for_run_artifact,
        summary_fields=_residual_summary_fields,
        summarize=res.summarize,
    )


def _record_replayed_eval(run_dir: Path, summary: dict, family: _ReplayFamily) -> bool:
    """Refresh a run's POV artifacts and dashboard-facing state for one family.

    Returns whether ``state.json`` could also be updated. The authoritative
    ``<subdir>/results.json`` is written even for legacy runs whose state is
    absent or unreadable.
    """
    from .logging_io import ensure_dir, write_json

    results_path = ensure_dir(run_dir / family.results_subdir) / "results.json"
    write_json(results_path, family.redact(summary))

    state_path = run_dir / "state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(state, dict):
        return False

    # A replay supersedes the previous evaluation. Remove stale POV commands
    # and the old skipped/ok step so deleted or renamed POVs do not linger.
    command_prefixes = tuple(
        f"{prefix}_" for prefix in (family.command_prefix, *family.legacy_command_prefixes)
    )
    commands = state.get("commands")
    if not isinstance(commands, list):
        commands = []
    state["commands"] = [
        command
        for command in commands
        if not isinstance(command, dict)
        or not str(command.get("name", "")).startswith(command_prefixes)
    ]
    # A POV that never ran (uncertified, stale fingerprint, or skipped after a
    # failed staging build) has no command_result; appending its None would put a
    # null into state.commands that every reader has to defend against.
    state["commands"].extend(
        pov["command_result"] for pov in summary["povs"] if pov.get("command_result")
    )

    steps = state.get("steps")
    if not isinstance(steps, list):
        steps = []
    step_names = (family.step_name, *family.legacy_step_names)
    state["steps"] = [
        step
        for step in steps
        if not isinstance(step, dict) or step.get("name") not in step_names
    ]
    step = {
        "name": family.step_name,
        "status": "ok",
        "replayed": True,
        # Which tree produced this score: "reconstructed" (base commit + the
        # run's recorded diff) or "worktree" (the run's preserved tree). The
        # base commit itself is not recorded here — see _replay_eval.
        "evaluation_mode": summary.get("evaluation_mode", ""),
        "results_path": str(results_path),
    }
    step.update(family.summary_fields(summary))
    state["steps"].append(step)
    write_json(state_path, state)
    return True


def _record_replayed_fix_pov(run_dir: Path, summary: dict) -> bool:
    """Back-compat shim: record a fixPOV replay. See ``_record_replayed_eval``."""
    return _record_replayed_eval(run_dir, summary, _fix_pov_family())


def _same_revision(left: Optional[str], right: Optional[str]) -> bool:
    """Whether two revision strings name the same commit, allowing abbreviation.

    Benchmarks record abbreviated SHAs (``03de3be``) while ``project_info.csv``
    records full ones, so equality has to be prefix-wise. It is deliberately
    *not* a resolution: two names that only a repository could be shown to be
    equal (a tag versus its peeled commit) are reported as different here and
    resolved by the caller, which has a clone to ask.
    """
    left, right = (left or "").strip(), (right or "").strip()
    if not left or not right:
        return False
    return left.startswith(right) or right.startswith(left)


def _clone_for_revision(project, revision: str, parent_dir: Path) -> Path:
    """A private clone of the project that contains ``revision``.

    Reached only when scoring a third-party patch whose benchmark pinned a
    different commit than our dataset. The shared ``dataset/project-sources``
    checkout is ``--depth 1``, so it will not have that commit — and it is
    emphatically not the place to go get it: our own pipeline runs, every POV
    certification and every other baseline's scoring read that checkout, and a
    fetch there would deepen a repository other people's results depend on being
    stable. A separate clone under the replay directory costs a few MB and is
    reused across every case of the project.

    Note this needs the network exactly once per project, unlike the rest of
    replay. ``git fetch --depth 1 origin <abbreviated-sha>`` is not an option:
    a short SHA cannot be fetched (see CLAUDE.md), which is why this is a clone
    rather than a deepen.
    """
    from .workspace import has_revision, run_local_command

    target = parent_dir / "altbase-src"
    if target.is_dir() and has_revision(target, revision):
        return target
    if not project.github_url:
        raise MetadataError(
            f"base commit {revision[:12]} is not in the local clone and "
            f"project_info.csv has no github_url to obtain it from"
        )
    if not target.is_dir():
        target.parent.mkdir(parents=True, exist_ok=True)
        clone = run_local_command(
            "git_clone_altbase",
            ["git", "clone", "--quiet", "--no-checkout", project.github_url, str(target)],
            cwd=parent_dir,
            timeout_seconds=1800,
        )
        if clone.exit_code != 0:
            raise MetadataError(
                f"could not clone {project.github_url} to obtain base commit "
                f"{revision[:12]}: {(clone.stderr or clone.stdout).strip()[:200]}"
            )
    if not has_revision(target, revision):
        raise MetadataError(
            f"base commit {revision[:12]} is not in {project.github_url} "
            f"(the benchmark may pin a rewritten or unpushed commit)"
        )
    return target


class _ReplayCheckout:
    """A reusable checkout of the project's vulnerable revision for replay.

    Reconstruction — export ``buggy_commit_id``, apply the run's recorded
    ``patch_only.diff``, score the fixPOVs there — is preferred over
    scoring the run's preserved ``worktree/`` for three reasons:

      * ``security_pipeline_runs/`` is gitignored and can be GBs. Once worktrees
        are pruned the old path fails with "worktree is missing" and those runs
        become permanently unscoreable; a diff plus a commit id is a few KB.
      * The base is pinned. The shared ``project-sources`` checkout can drift off
        the dataset's ``buggy_commit_id`` (several are sitting on upstream main),
        and a POV certified against the vulnerable revision says nothing about a
        tree years newer. Reconstruction scores the revision the certification
        was actually about.
      * The run's worktree is mutable and unhashed; a commit id plus a diff is a
        reproducible description of what is being scored.

    One checkout is reused across every run of a project: between runs it is
    reset to the baseline commit, which keeps ignored build output (``target/``)
    so only the first replay in a batch pays for a cold build.

    ``revision`` overrides the dataset's ``buggy_commit_id``. That is only ever
    passed when scoring a *third-party* patch whose benchmark pinned a different
    commit for the same CVE (``baselines/score_patches.py``); a pipeline run's own
    replay always uses the dataset revision, because that is the tree the run was
    produced on. When the override is not in the shared project clone — which is
    the normal case, those are ``--depth 1`` — the commit is obtained through a
    **private clone under ``parent_dir``**, never by fetching into
    ``dataset/project-sources/``: that checkout is shared with our own
    pipeline runs and with every other baseline's scoring, and a comparison
    harness has no business mutating it.
    """

    def __init__(self, project, parent_dir: Path, revision: Optional[str] = None) -> None:
        import shutil

        from .workspace import create_worktree, has_revision

        self.project = project
        self.revision = revision or project.buggy_commit_id
        self.is_dataset_revision = _same_revision(self.revision, project.buggy_commit_id)
        self.parent_dir = parent_dir
        self.path: Optional[Path] = None
        self.unavailable: Optional[str] = None
        self.source_repo: Path = project.source_path

        if not self.revision:
            self.unavailable = "project_info.csv has no buggy_commit_id"
            return
        if not has_revision(self.source_repo, self.revision):
            if self.is_dataset_revision:
                self.unavailable = (
                    f"base commit {self.revision[:12]} is not in the local clone "
                    f"(shallow fetch) — run `python -m security_pipeline fetch`"
                )
                return
            try:
                self.source_repo = _clone_for_revision(project, self.revision, parent_dir)
            except MetadataError as exc:
                self.unavailable = str(exc)
                return
        try:
            shutil.rmtree(parent_dir / "checkout", ignore_errors=True)
            self.path = create_worktree(
                self.source_repo, parent_dir, revision=self.revision, dirname="checkout"
            )
        except Exception as exc:  # noqa: BLE001 - reconstruction is best-effort
            self.unavailable = f"could not export base commit: {exc}"

    @property
    def image_tag(self) -> str:
        from .docker_runner import IMAGE_PREFIX, dockerfile_hash, sanitize_docker_component

        return (
            f"{IMAGE_PREFIX}{sanitize_docker_component(self.project.project_slug)}:"
            f"{dockerfile_hash(self.project.dockerfile_path)}"
        )

    @staticmethod
    def _chown_in_container(path: Path, image_tag: str, uid: int, gid: int) -> bool:
        """Reassign ``path``'s ownership through a helper container.

        The eval containers run as root, and Ubuntu's git (CVE-2022-24765
        backport even on 22.04's 2.34.1) refuses to operate on a repository whose
        files it does not own ("detected dubious ownership"), so a
        ``bash -lc git config submodule...`` in a build_command dies the moment
        the mounted checkout belongs to the unprivileged host user. The host
        user cannot ``chown`` to root directly (EPERM), but a container running
        as root can — exactly what ``DockerRunner.reclaim_ownership`` uses to
        hand files back. So the checkout is chowned to root immediately before
        an eval and back to the host user immediately after, keeping the window
        where the dashboard user cannot touch it confined to the eval itself.
        """
        from .workspace import run_local_command

        if not path.exists():
            return False
        result = run_local_command(
            "docker_chown_checkout",
            [
                "docker", "run", "--rm",
                "-v", f"{path}:/workspace/repo",
                image_tag,
                "chown", "-R", f"{uid}:{gid}", "/workspace/repo",
            ],
            cwd=path.parent,
            timeout_seconds=600,
        )
        return result.exit_code == 0

    def prepare(self, run_dir: Path) -> Path:
        """Reset to the base commit and apply this run's patch. Raises on failure."""
        from .workspace import apply_patch_file, reset_checkout

        # Unavailability first: "the base commit is not in the local clone" is a
        # more useful thing to report than a missing diff, and a caller that only
        # sees the latter would go looking in the wrong place.
        if self.path is None:
            raise MetadataError(self.unavailable or "reconstruction unavailable")
        patch_path = run_dir / "git" / "patch_only.diff"
        if not patch_path.is_file() or not patch_path.stat().st_size:
            raise MetadataError("run has no patch_only.diff to reconstruct from")
        reset_checkout(self.path)
        applied = apply_patch_file(self.path, patch_path)
        if applied.exit_code != 0:
            raise MetadataError(
                f"patch does not apply to {self.revision[:12]}: "
                f"{(applied.stderr or applied.stdout).strip().splitlines()[0] if (applied.stderr or applied.stdout).strip() else 'git apply failed'}"
            )
        # Deliberately AFTER the patch, matching the original single-method
        # ordering exactly. Registering gitlinks into the index first would put
        # `git apply` in front of an index this code path has never handed it,
        # and retrofit and both replay drivers share this method — the alternate
        # base is not a licence to perturb them.
        self._restore(run_dir)
        return self._hand_to_container()

    def prepare_unpatched(self, run_dir: Path) -> Path:
        """Reset to the base commit and stop there — the tree with no patch on it.

        Used only to re-prove the oracle at a non-dataset base revision: a POV
        that does not reproduce here is not evidence about any patch, so nothing
        may be concluded from how it behaves on the patched tree.

        Note this leaves build output behind for ``prepare`` to reuse — replay
        never ``git clean -x``es, so the patched pass that follows is an
        incremental rebuild rather than a second cold ASan build.
        """
        from .workspace import reset_checkout

        if self.path is None:
            raise MetadataError(self.unavailable or "reconstruction unavailable")
        reset_checkout(self.path)
        self._restore(run_dir)
        return self._hand_to_container()

    def _restore(self, run_dir: Path) -> None:
        _restore_submodules(
            self.path, run_dir, self.project, self.parent_dir,
            source_repo=self.source_repo, revision=self.revision,
        )

    def _hand_to_container(self) -> Path:
        # The eval container runs as root and its git refuses ownership it does
        # not have (CVE-2022-24765 backport): hand the tree to root for the
        # duration of the eval, reclaiming (below) once the eval is done.
        if os.stat(self.path).st_uid != 0:
            # .security-pipeline/ must stay with the host user: the evaluator
            # stages POVs into it on the host, as the unprivileged user, and a
            # root-owned staging dir is exactly the PermissionError a staged
            # eval dies on.
            security_dir = self.path / ".security-pipeline"
            if not security_dir.is_dir():
                security_dir.mkdir()
            self._chown_in_container(self.path, self.image_tag, 0, 0)
            self._chown_in_container(security_dir, self.image_tag, os.getuid(), os.getgid())
        return self.path

    def reclaim(self) -> None:
        """Hand the reconstruction tree back to the invoking host user."""
        if self.path is None or not self.path.exists():
            return
        uid, gid = os.getuid(), os.getgid()
        if os.stat(self.path).st_uid != uid:
            self._chown_in_container(self.path, self.image_tag, uid, gid)

    def cleanup(self) -> None:
        import shutil

        self.reclaim()
        if self.path is not None:
            shutil.rmtree(self.path, ignore_errors=True)
            self.path = None


def _restore_submodules(
    checkout: Path, run_dir: Path, project, replay_dir: Path,
    source_repo: Optional[Path] = None, revision: Optional[str] = None,
) -> List[str]:
    """Make the reconstruction's submodule dirs usable for a build.

    ``source_repo``/``revision`` default to the project's dataset checkout and
    ``buggy_commit_id``; they are non-default only when reconstructing at a
    baseline's own base commit, where the gitlinks have to be read from the tree
    that is actually being exported.

    Reconstruction exports the base commit with ``git archive``, which emits a
    submodule gitlink (e.g. coreutils' ``gnulib``) as an **empty directory** — the
    gitlink itself is not in the exported tree, so ``git ls-files -s`` shows
    nothing to restore and ``git submodule init`` fails with "pathspec did not
    match". Submodule paths come from ``.gitmodules``; the pinned commit is read
    from the *source* clone at ``buggy_commit_id`` and registered back into the
    reconstruction's index. Content is then restored from the best available
    exact source:

      1. the project's built Docker image — the Dockerfile runs
         ``git submodule update --init`` while building it, so
         ``/workspace/repo/<submodule>`` inside the image is the submodule at
         exactly the pinned commit (the one piece of state git archive cannot
         reproduce), with its ``.git`` intact. Extracted once into the replay
         dir and copied in per run; fully offline and exact.
      2. ``git submodule update --init`` over the network (requires the gitlink
         registered above).
      3. the run's preserved worktree copy — best effort only: its commit is
         not verified against the pin, and for coreutils it is a *different*
         gnulib commit whose content made bootstrap fail (missing
         ``.gnulib-tool.py``), which is why it is a last resort.

    Returns the restored submodule paths.
    """
    import shutil

    from .docker_runner import IMAGE_PREFIX, dockerfile_hash, sanitize_docker_component
    from .workspace import run_local_command

    source_repo = source_repo or project.source_path
    revision = revision or project.buggy_commit_id

    modules_file = checkout / ".gitmodules"
    if modules_file.is_file():
        modules = run_local_command(
            "git_submodule_paths",
            [
                "git", "-C", str(checkout), "config", "-f", str(modules_file),
                "--get-regexp", r"^submodule\..*\.path$",
            ],
            cwd=checkout,
        )
        rels = [
            Path(line.split(" ", 1)[1].strip())
            for line in modules.stdout.splitlines()
            if " " in line and line.split(" ", 1)[1].strip()
        ]
    else:
        # No .gitmodules: fall back to scanning for gitlink entries (the archive
        # export normally drops them, but a repo whose submodule has no metadata
        # file can still export one in some git versions).
        result = run_local_command(
            "git_ls_submodules", ["git", "-C", str(checkout), "ls-files", "-s"], cwd=checkout
        )
        if result.exit_code != 0:
            return []
        rels = [
            Path(parts[1])
            for line in result.stdout.splitlines()
            if len(parts := line.split("\t")) == 2 and parts[0].startswith("160000 ")
        ]
    if not rels:
        return []

    pinned: Dict[Path, str] = {}
    for rel in rels:
        tree = run_local_command(
            "git_ls_tree_submodule",
            ["git", "-C", str(source_repo), "ls-tree", revision, "--", rel.as_posix()],
            cwd=source_repo,
        )
        entry = next(
            (line for line in tree.stdout.splitlines() if line.startswith("160000 commit ")),
            "",
        )
        if not entry:
            continue
        sha = entry.split()[2]
        pinned[rel] = sha
        run_local_command(
            "git_update_index_gitlink",
            [
                "git", "-C", str(checkout), "update-index", "--add", "--cacheinfo",
                f"160000,{sha},{rel.as_posix()}",
            ],
            cwd=checkout,
        )

    image_tag = (
        f"{IMAGE_PREFIX}{sanitize_docker_component(project.project_slug)}:"
        f"{dockerfile_hash(project.dockerfile_path)}"
    )

    def _head_matches(rel: Path, sha: str) -> bool:
        head = run_local_command(
            "git_submodule_head", ["git", "-C", str(checkout / rel), "rev-parse", "HEAD"],
            cwd=checkout, timeout_seconds=30,
        )
        return head.exit_code == 0 and head.stdout.strip() == sha

    def _network_restore(rel: Path) -> bool:
        shutil.rmtree(checkout / rel, ignore_errors=True)
        update = run_local_command(
            "git_submodule_update",
            ["git", "-C", str(checkout), "submodule", "update", "--init", "--", rel.as_posix()],
            cwd=checkout,
            timeout_seconds=600,
        )
        return update.exit_code == 0

    restored = []
    for rel in rels:
        sha = pinned.get(rel)
        if sha is None:
            # .gitmodules names it but this revision has no gitlink entry: not a
            # real submodule at the reconstructed commit — leave the build to
            # decide what the directory is.
            continue
        target = checkout / rel
        if (target / ".git").is_dir() and _head_matches(rel, sha):
            continue
        exact = _extract_submodule_from_image(image_tag, rel, replay_dir)
        if exact is not None:
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(exact, target)
            # The working tree's `.git` is only a `gitdir:` pointer (relative
            # one level up, e.g. `../.git/modules/<rel>`) into the object
            # store cached alongside it -- but `checkout` is itself one level
            # below `replay_dir` (`replay_dir/checkout`), so that cached
            # store must be copied in fresh under `checkout/.git/modules/`
            # each time; it is never reachable at its cached location.
            cached_modules = replay_dir / ".git" / "modules" / rel.name
            if cached_modules.is_dir():
                modules_target = checkout / ".git" / "modules" / rel.name
                if modules_target.exists():
                    shutil.rmtree(modules_target, ignore_errors=True)
                modules_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(cached_modules, modules_target)
            restored.append(rel.as_posix())
            continue
        if _network_restore(rel):
            restored.append(rel.as_posix())
            continue
        raw = run_dir / "worktree" / rel
        if raw.is_dir() and any(raw.iterdir()):
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(raw, target, dirs_exist_ok=True)
            restored.append(rel.as_posix())
    return restored


def _extract_submodule_from_image(
        image_tag: str, rel: Path, replay_dir: Optional[Path]
    ) -> Optional[Path]:
        """Return a cached copy of a submodule as checked out inside ``image_tag``.

        The Dockerfile runs ``git submodule update --init <rel>`` while building
        the project image, so ``/workspace/repo/<rel>`` inside it is the
        submodule at exactly the commit the base revision pins — the state ``git
        archive`` cannot reproduce. Two paths are extracted, because a submodule
        checkout in a superproject keeps its objects in the parent's
        ``.git/modules/<rel>`` with only a ``gitdir:`` file inside the submodule
        dir: the working tree **and** the module objects, so the relative
        ``gitdir:`` pointer resolves and ``git submodule update`` sees a valid,
        already-checked-out submodule. Both land in ``replay_dir/.submodule_cache``
        (fresh per project, so the first replay in a batch pays the extraction
        and the rest just copy). Returns None when the image or the path is
        unavailable; callers then fall back to a network fetch.
        """
        import shutil

        from .workspace import run_local_command

        if replay_dir is None:
            return None
        cache_dir = replay_dir / ".submodule_cache" / rel
        # The working tree's `.git` is only a `gitdir:` pointer into this sibling
        # object store -- a cache is only usable if both halves are present, not
        # just the pointer file (see the rollback below for how a stale
        # pointer-only cache can otherwise get left behind).
        modules_dir = replay_dir / ".git" / "modules" / rel.name
        if cache_dir.is_dir() and (cache_dir / ".git").exists() and modules_dir.is_dir():
            return cache_dir
        cache_dir.parent.mkdir(parents=True, exist_ok=True)
        modules_dir.parent.mkdir(parents=True, exist_ok=True)
        cid = ""
        try:
            created = run_local_command(
                "docker_create",
                ["docker", "create", "--entrypoint", "true", image_tag],
                cwd=replay_dir,
                timeout_seconds=120,
            )
            if created.exit_code != 0:
                return None
            cid = created.stdout.strip().splitlines()[-1]
            for source, dest in (
                (f"/workspace/repo/{rel.as_posix()}", cache_dir.parent),
                (f"/workspace/repo/.git/modules/{rel.as_posix()}", modules_dir.parent),
            ):
                copied = run_local_command(
                    "docker_cp",
                    ["docker", "cp", f"{cid}:{source}", str(dest)],
                    cwd=replay_dir,
                    timeout_seconds=600,
                )
                if copied.exit_code != 0:
                    # Don't leave a half-extracted cache_dir behind: it already
                    # carries a `.git` pointer file (copied as part of the
                    # working tree) that would pass the cache check above on
                    # the next replay even though it resolves to nothing.
                    shutil.rmtree(cache_dir, ignore_errors=True)
                    shutil.rmtree(modules_dir, ignore_errors=True)
                    return None
            if not (cache_dir / ".git").exists() or not modules_dir.is_dir():
                shutil.rmtree(cache_dir, ignore_errors=True)
                shutil.rmtree(modules_dir, ignore_errors=True)
                return None
            return cache_dir
        finally:
            if cid:
                run_local_command("docker_rm", ["docker", "rm", "-f", cid], cwd=replay_dir)


@contextlib.contextmanager
def _replay_lock(replay_dir: Path):
    """Serialize replays of one project behind an advisory file lock.

    Every replay of a project shares one reconstruction checkout under
    ``replay_dir`` (reused and reset between runs) and one docker build log, and
    ``_ReplayCheckout.__init__`` throws the checkout away on every construction.
    Two concurrent replays of the same project therefore race on rmtree/create —
    observed with two dashboard replay jobs: one eval's container was mid-build
    when the sibling rebuilt the checkout, and every POV then failed with
    ``cd: po: No such file or directory``. Serializing the whole project replay
    behind one ``flock`` means the second job simply waits. Degrades to a no-op
    on hosts without ``fcntl`` (non-POSIX), where concurrent replays are already
    unsafe and callers stay single-run.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return
    lock_file = open(replay_dir / ".replay.lock", "a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


def _replay_eval(
    args: argparse.Namespace, workspace_root: Path, family: _ReplayFamily
) -> int:
    """Re-score a project's POVs (of one ``family``) against already-patched runs.

    Each run is reconstructed from ``buggy_commit_id`` + its recorded patch; the
    run's preserved worktree is the fallback when that is not possible (no diff,
    base commit absent, patch does not apply). ``--from-worktree`` forces the
    old worktree-only behaviour. This is the shared driver behind both
    ``fixpov replay`` and ``respov replay`` — only ``family`` differs.
    """
    from .docker_runner import EVALUATION_NETWORK, DockerRunner
    from .logging_io import ensure_dir
    from .metadata import resolve_project_metadata_by_slug

    alerts_dir = _resolve_under_workspace(args.alerts_dir, workspace_root).resolve()
    runs_dir = _resolve_under_workspace(args.runs_dir, workspace_root).resolve()
    project = resolve_project_metadata_by_slug(args.project, workspace_root)
    manifest = family.load_manifest(workspace_root, args.project)
    if manifest is None:
        raise MetadataError(f"No {family.label} manifest for {args.project}")

    include_rejected = getattr(args, "include_rejected", False)
    run_dirs = _select_replay_run_dirs(
        project=project,
        alerts_dir=alerts_dir,
        runs_dir=runs_dir,
        requested_run_ids=args.run_ids,
        include_rejected=include_rejected,
    )
    if not run_dirs:
        scope = "accepted or patch-bearing rejected" if include_rejected else "accepted"
        raise MetadataError(f"No {scope} pipeline runs found for {args.project}")
    if include_rejected:
        rejected = [d for d in run_dirs if (_read_verdict(d) or {}).get("status") == "rejected"]
        if rejected:
            print(
                f"security-pipeline: including {len(rejected)} rejected run(s) with a "
                f"scoreable patch: {', '.join(d.name for d in rejected)}",
                file=sys.stderr,
            )

    # Every checkout uses the same project Dockerfile, so build one reusable image
    # before replaying. Keep its log separate from each run's original build log.
    image_key = project.project_slug
    replay_dir = ensure_dir(runs_dir / family.replay_dirname / project.project_slug)
    # One project = one shared reconstruction checkout and one docker build log,
    # so concurrent replays of the same project (e.g. two dashboard jobs) must
    # serialize or each rmtree/re-create corrupts the other mid-build.
    with _replay_lock(replay_dir):
        if not args.skip_docker_build:
            builder = DockerRunner(
                project, project.source_path, replay_dir, image_key=image_key
            )
            build = builder.build_image(args.build_timeout_seconds)
            if not build.ok:
                raise MetadataError(
                    f"Docker image build failed for {args.project}; see {build.log_path}"
                )

        # getattr: the dashboard invokes this through argparse, but the flags are
        # optional for programmatic callers that build a Namespace directly.
        from_worktree = getattr(args, "from_worktree", False)
        keep_checkout = getattr(args, "keep_checkout", False)
        checkout = None if from_worktree else _ReplayCheckout(project, replay_dir)
        project_dir = family.project_dir(workspace_root, args.project)

        exit_code = 0
        summaries = []
        try:
            for run_dir in run_dirs:
                # Reconstruct from the pinned base commit + this run's patch. Anything
                # that makes that impossible falls back to the run's preserved
                # worktree, and the mode is recorded either way so a score is never
                # ambiguous about which tree produced it.
                checkout_path: Optional[Path] = None
                mode = "reconstructed"
                fallback_reason = ""
                if checkout is not None:
                    try:
                        checkout_path = checkout.prepare(run_dir)
                    except Exception as exc:  # noqa: BLE001 - fall back, do not fail the batch
                        fallback_reason = str(exc)
                else:
                    fallback_reason = "--from-worktree"

                if checkout_path is None:
                    mode = "worktree"
                    worktree = run_dir / "worktree"
                    if worktree.is_dir():
                        checkout_path = worktree
                    else:
                        row = {
                            "run_id": run_dir.name,
                            "status": "error",
                            "error": (
                                f"cannot reconstruct ({fallback_reason}) and the run's "
                                "worktree is missing"
                            ),
                        }
                        exit_code = 1
                        summaries.append(row)
                        print(json.dumps(row, sort_keys=True))
                        continue

                try:
                    docker = DockerRunner(
                        project, checkout_path, run_dir, image_key=image_key,
                        network=EVALUATION_NETWORK,
                    )
                    try:
                        summary = family.evaluate(
                            manifest, project_dir, docker, checkout_path,
                            args.command_timeout_seconds,
                        )
                    finally:
                        # The eval container writes root-owned build output all
                        # over the tree and chowns nothing back: return the tree
                        # to the host user unconditionally (even when the eval
                        # raised), so the next run can reset it — the dashboard
                        # user cannot chown itself.
                        if checkout is not None and mode == "reconstructed":
                            checkout.reclaim()
                    # Deliberately NOT recorded in the summary: the base revision.
                    # `buggy_commit_id` identifies the CVE (DockerRunner already
                    # redacts it from every docker log), and results.json ships in
                    # anonymized run exports. The mode is enough — the base is
                    # re-derivable from the run's finding_id through project_info.csv,
                    # which is exactly how the dashboard maps a run to its CVE.
                    summary["evaluation_mode"] = mode
                    if fallback_reason and mode == "worktree":
                        summary["reconstruction_skipped"] = fallback_reason
                    state_updated = _record_replayed_eval(run_dir, summary, family)
                    row = {
                        "run_id": run_dir.name,
                        "status": "ok",
                        "evaluation_mode": mode,
                        "state_updated": state_updated,
                        "results_path": str(run_dir / family.results_subdir / "results.json"),
                    }
                    row.update(family.summary_fields(summary))
                    if fallback_reason and mode == "worktree":
                        row["reconstruction_skipped"] = fallback_reason
                    if summary["errored"]:
                        exit_code = 1
                except Exception as exc:  # noqa: BLE001 - report one run and continue the batch
                    row = {"run_id": run_dir.name, "status": "error", "error": str(exc)}
                    exit_code = 1
                summaries.append(row)
                print(json.dumps(row, sort_keys=True))
        finally:
            if checkout is not None and not keep_checkout:
                checkout.cleanup()

        if len(summaries) > 1:
            print(json.dumps({"replays": summaries}, indent=2, sort_keys=True))
        return exit_code


# --------------------------------------------------------------------------- #
# retrofit: replay the objective gates against runs that predate them
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _RetrofitTarget:
    project: object
    alert_path: Path
    run_dir: Path
    gates: Tuple[str, ...]   # the gates still missing from this run
    profile: str


def _retrofit_targets(
    *,
    workspace_root: Path,
    alerts_dir: Path,
    runs_dir: Path,
    project_slug: Optional[str],
    run_ids: Optional[List[str]],
    profile: str,
    gates: Tuple[str, ...],
    include_rejected: bool,
    force: bool = False,
) -> List[_RetrofitTarget]:
    """Runs worth retrofitting, walked from the alerts rather than the run dirs.

    Run JSON redacts the project slug and the CVE, so an alert is the only thing
    that maps a run back to a project without weakening that contract — the same
    reason ``_run_dirs_for_project`` reconstructs finding IDs this way. Walking
    alerts also hands us the alert JSON itself, which the verifier needs as the
    only description of the vulnerability it is judging the patch against.

    A gate the run already ran natively is dropped from its target, so retrofitting
    can never overwrite a real verifier verdict or a real regression result —
    unless ``force``, which re-assesses regardless (it still cannot rewrite the
    patch; only the retrofit's own recorded outcome changes).
    """
    from .metadata import all_alert_paths, alert_paths_for_cve
    from .metadata import resolve_project_metadata

    requested_runs = set(run_ids or [])
    if requested_runs and not project_slug:
        raise MetadataError("--run requires --project")

    alert_paths: List[Path]
    if project_slug:
        project = resolve_project_metadata_by_slug_cached(project_slug, workspace_root)
        alert_paths = alert_paths_for_cve(alerts_dir, project.cve_id)
    else:
        alert_paths = all_alert_paths(alerts_dir)

    targets: List[_RetrofitTarget] = []
    for alert_path in alert_paths:
        try:
            project = resolve_project_metadata(alert_path, workspace_root)
        except MetadataError:
            continue  # an alert with no local project cannot be assessed
        if project_slug and project.project_slug != project_slug:
            continue
        finding_id = make_finding_id(alert_path, project)
        for run_dir in existing_run_dirs(runs_dir, finding_id):
            if requested_runs and run_dir.name not in requested_runs:
                continue
            verdict = _read_verdict(run_dir) or {}
            status = verdict.get("status")
            if status == "accepted":
                pass
            elif include_rejected and status == "rejected" and _rejected_run_has_scoreable_patch(run_dir):
                pass
            else:
                continue
            run_profile = str(verdict.get("profile") or "")
            if profile != "any" and run_profile != profile:
                continue
            already = set(verdict.get("stages") or ())
            prior = verdict.get("retrofit_gates") or {}
            # A gate the retrofit could not complete — the verifier agent
            # crashed, the container died — was never actually assessed, but
            # recording the attempt still added its stage to the run. Without
            # this it could never be retried: the next invocation would see the
            # stage present and skip the run as already gated.
            already -= set(prior.get("gates_errored") or ())
            missing = gates if force else tuple(g for g in gates if g not in already)
            if not missing:
                continue
            targets.append(
                _RetrofitTarget(
                    project=project,
                    alert_path=alert_path,
                    run_dir=run_dir,
                    gates=missing,
                    profile=run_profile or "baseline",
                )
            )

    if requested_runs:
        found = {target.run_dir.name for target in targets}
        for run_id in sorted(requested_runs - found):
            raise MetadataError(
                f"Run {run_id!r} is not an eligible run for {project_slug} "
                "(wrong profile/status, or it already ran the requested gates)"
            )
    targets.sort(key=lambda target: (target.project.project_slug, target.run_dir.name))
    return targets


def resolve_project_metadata_by_slug_cached(slug: str, workspace_root: Path):
    from .metadata import resolve_project_metadata_by_slug

    return resolve_project_metadata_by_slug(slug, workspace_root)


def rerun_verifier_command(args: argparse.Namespace) -> int:
    """Re-run the verifier for one run whose verifier crashed; flip if it accepts.

    Prints a one-line JSON result. Exit 0 when the run was flipped to accepted,
    1 when the re-run verifier rejected or errored (a real, displayable outcome —
    the background job treats both 0 and 1 as a successful job), 2 when the
    re-run could not be attempted at all.
    """
    from . import verifier_rerun

    run_dir = (args.runs_dir / args.run).resolve()
    if not run_dir.is_dir():
        print(json.dumps({"status": "error", "reason": f"run not found: {args.run}", "run_id": args.run}))
        return 2
    try:
        result = verifier_rerun.rerun_verifier(
            run_dir,
            workspace_root=args.workspace_root,
            alerts_dir=args.alerts_dir,
            runs_dir=args.runs_dir,
            model=args.model,
        )
    except verifier_rerun.VerifierRerunError as exc:
        print(json.dumps({"status": "error", "reason": str(exc), "run_id": args.run}))
        return 2
    result["run_id"] = args.run
    print(json.dumps(result))
    return 0 if result.get("status") == "accepted" else 1


def retrofit_command(args: argparse.Namespace) -> int:
    """Replay the regression gate and the verifier against already-finished runs.

    Assess-only by construction — see ``security_pipeline/retrofit.py``. Runs are
    grouped by project so one Docker image build and one pair of checkouts (the
    patched tree, and the pristine base the regression triage compares against)
    are amortized across every run of that project.
    """
    from .claude_agents import ClaudeAgentRunner
    from .docker_runner import DockerRunner
    from .logging_io import ensure_dir
    from .metadata import load_alert as _load_alert

    workspace_root = args.workspace_root.resolve()
    alerts_dir = _resolve_under_workspace(args.alerts_dir, workspace_root).resolve()
    runs_dir = _resolve_under_workspace(args.runs_dir, workspace_root).resolve()

    gates = tuple(part.strip() for part in str(args.gates).split(",") if part.strip())
    if not gates:
        raise MetadataError("--gates was empty")
    unknown = [gate for gate in gates if gate not in retrofit.AVAILABLE_GATES]
    if unknown:
        raise MetadataError(
            f"unknown gate(s) {', '.join(unknown)}; known: {', '.join(retrofit.AVAILABLE_GATES)}"
        )

    targets = _retrofit_targets(
        workspace_root=workspace_root,
        alerts_dir=alerts_dir,
        runs_dir=runs_dir,
        project_slug=args.project,
        run_ids=args.run_ids,
        profile=args.profile,
        gates=gates,
        include_rejected=args.include_rejected,
        force=args.force,
    )
    if not targets:
        raise MetadataError(
            f"No runs to retrofit (profile={args.profile}, gates={','.join(gates)}). "
            "Runs that already ran these gates are skipped."
        )

    if args.dry_run:
        print(json.dumps({
            "targets": [
                {
                    "run_id": target.run_dir.name,
                    "project_slug": target.project.project_slug,
                    "profile": target.profile,
                    "gates": list(target.gates),
                }
                for target in targets
            ],
            "count": len(targets),
        }, indent=2, sort_keys=True))
        return 0

    options = RunOptions(
        workspace_root=workspace_root,
        alerts_dir=alerts_dir,
        runs_dir=runs_dir,
        model=args.model,
        effort=args.effort,
        claude_bin=args.claude_bin,
        agent_timeout_seconds=args.agent_timeout_seconds,
        command_timeout_seconds=args.command_timeout_seconds,
        skip_docker_build=args.skip_docker_build,
        # Structural: nothing in the retrofit path re-invokes the patcher, and
        # this makes that true of the machinery it borrows as well.
        max_correction_attempts=1,
    )
    agent_runner = ClaudeAgentRunner(options, Path(__file__).resolve().parent)

    by_project: dict = {}
    for target in targets:
        by_project.setdefault(target.project.project_slug, []).append(target)

    exit_code = 0
    rows: List[dict] = []
    for slug, group in by_project.items():
        project = group[0].project
        retro_dir = ensure_dir(runs_dir / ".retrofit" / slug)
        if not args.skip_docker_build:
            builder = DockerRunner(project, project.source_path, retro_dir, image_key=slug)
            build = builder.build_image(args.build_timeout_seconds)
            if not build.ok:
                for target in group:
                    row = {
                        "run_id": target.run_dir.name, "status": "error",
                        "error": f"docker image build failed; see {build.log_path}",
                    }
                    rows.append(row)
                    print(json.dumps(row, sort_keys=True))
                exit_code = 1
                continue

        # Two trees: the run's patch applied to the pinned vulnerable revision,
        # and that same revision left alone. The second is what the regression
        # gate replays a failing command against to tell a genuine regression
        # from the scaffold noise that dominates these failures — a reconstructed
        # checkout carries the patch in its working tree, so the gate's usual
        # `git archive HEAD` would export the *patched* code as the "baseline".
        patched = None if args.from_worktree else _ReplayCheckout(project, retro_dir)
        pristine = (
            None if args.from_worktree
            else _ReplayCheckout(project, ensure_dir(retro_dir / "pristine"))
        )
        try:
            for target in group:
                rows.append(
                    _retrofit_one(
                        target=target,
                        project=project,
                        slug=slug,
                        patched=patched,
                        pristine=pristine,
                        options=options,
                        agent_runner=agent_runner,
                        load_alert_fn=_load_alert,
                        docker_cls=DockerRunner,
                    )
                )
                print(json.dumps(rows[-1], sort_keys=True))
                if rows[-1]["status"] != "ok":
                    exit_code = 1
        finally:
            if not args.keep_checkout:
                for checkout in (patched, pristine):
                    if checkout is not None:
                        checkout.cleanup()

    passed = sum(1 for row in rows if row.get("all_gates_passed") is True)
    print(json.dumps({
        "retrofits": rows,
        "count": len(rows),
        "all_gates_passed": passed,
    }, indent=2, sort_keys=True))
    return exit_code


def _retrofit_one(
    *, target: _RetrofitTarget, project, slug: str, patched, pristine,
    options: RunOptions, agent_runner, load_alert_fn, docker_cls,
) -> dict:
    """Assess one run. Never raises: one bad run must not end the batch."""
    run_dir = target.run_dir
    checkout_path: Optional[Path] = None
    baseline_path: Optional[Path] = None
    mode = "reconstructed"
    fallback_reason = "--from-worktree" if patched is None else ""

    if patched is not None:
        try:
            checkout_path = patched.prepare(run_dir)
            baseline_path = pristine.path if pristine is not None else None
        except Exception as exc:  # noqa: BLE001 - fall back, do not fail the batch
            fallback_reason = str(exc)
            checkout_path = None

    if checkout_path is None:
        mode = "worktree"
        worktree = run_dir / "worktree"
        if not worktree.is_dir():
            return {
                "run_id": run_dir.name, "status": "error",
                "error": f"cannot reconstruct ({fallback_reason}) and the run's worktree is missing",
            }
        checkout_path = worktree
        # The run's worktree is a real git repo whose HEAD is the untouched
        # source, so the regression gate can export its own baseline (None lets
        # it do exactly that).
        baseline_path = None

    try:
        alert = load_alert_fn(target.alert_path)
        finding_id = make_finding_id(target.alert_path, project)
        docker = docker_cls(project, checkout_path, run_dir, image_key=slug)
        try:
            summary = retrofit.retrofit_run(
                run_dir=run_dir,
                project=project,
                alert=alert,
                finding_id=finding_id,
                checkout_path=checkout_path,
                baseline_checkout_path=baseline_path,
                docker=docker,
                options=options,
                agent_runner=agent_runner,
                gates=target.gates,
                profile=target.profile,
            )
        finally:
            docker.reclaim_ownership()
        summary["evaluation_mode"] = mode
        if fallback_reason and mode == "worktree":
            summary["reconstruction_skipped"] = fallback_reason
        # The headline is cumulative across retrofits of this run, not just this
        # invocation: replaying only the verifier still reports the regression
        # result an earlier pass recorded, so the row reads as the run's standing
        # rather than as a delta.
        headline = retrofit.record_retrofit(run_dir, summary, target.gates)
        row = {
            "run_id": run_dir.name,
            "status": "ok",
            "project_slug": slug,
            "profile": target.profile,
            "evaluation_mode": mode,
            "state_updated": headline["state_updated"],
            "gates_assessed": list(target.gates),
            "gates": headline["gates"],
            "gates_passed": headline["gates_passed"],
            "gates_failed": headline["gates_failed"],
            "gates_errored": headline["gates_errored"],
            "all_gates_passed": headline["all_gates_passed"],
            "results_path": str(run_dir / retrofit.RESULTS_SUBDIR / "results.json"),
        }
        if fallback_reason and mode == "worktree":
            row["reconstruction_skipped"] = fallback_reason
        return row
    except Exception as exc:  # noqa: BLE001 - report one run and continue the batch
        return {"run_id": run_dir.name, "status": "error", "error": f"{type(exc).__name__}: {exc}"}


def _replay_fix_pov(args: argparse.Namespace, workspace_root: Path) -> int:
    """Back-compat entry point for ``fixpov replay``. See ``_replay_eval``."""
    return _replay_eval(args, workspace_root, _fix_pov_family())


def _replay_residual(args: argparse.Namespace, workspace_root: Path) -> int:
    """Entry point for ``respov replay``. See ``_replay_eval``."""
    return _replay_eval(args, workspace_root, _residual_family())


def _replay_patch_eval(
    args: argparse.Namespace, workspace_root: Path, family: _ReplayFamily
) -> int:
    """Score one caller-supplied patch (not tied to a pipeline run) against a
    project's curated POVs of ``family``.

    Entry point for ``fixpov replay-patch`` / ``respov replay-patch``, used by
    the dashboard to score a baseline tool's patch against the same certified
    manifests a pipeline run is scored against. The only pipeline-run-shaped
    thing ``_ReplayCheckout.prepare`` needs is a directory containing
    ``git/patch_only.diff`` -- everything else (the checkout, ``family.evaluate``)
    is exactly what ``_replay_eval`` already uses, just pointed at a patch file
    the caller provides instead of a run's own recorded diff. The caller's
    patch must already be a proper ``git apply``-able unified diff (file
    headers included) -- synthesizing one from a bare hunk is the caller's
    business (e.g. LoopRepair's raw output has no file header at all).
    """
    from .docker_runner import EVALUATION_NETWORK, DockerRunner
    from .logging_io import ensure_dir, write_json
    from .metadata import resolve_project_metadata_by_slug

    runs_dir = _resolve_under_workspace(args.runs_dir, workspace_root).resolve()
    project = resolve_project_metadata_by_slug(args.project, workspace_root)
    manifest = family.load_manifest(workspace_root, args.project)
    if manifest is None:
        raise MetadataError(f"No {family.label} manifest for {args.project}")

    patch_file = args.patch_file.resolve()
    if not patch_file.is_file() or not patch_file.stat().st_size:
        raise MetadataError(f"patch file is missing or empty: {patch_file}")

    label = args.label or "external"
    image_key = project.project_slug
    replay_dir = ensure_dir(runs_dir / family.replay_dirname / project.project_slug)
    # A scratch "run dir" that holds nothing but the patch _ReplayCheckout.prepare
    # expects at git/patch_only.diff -- reused across replays of the same label so
    # a re-run overwrites rather than accumulates.
    work_dir = ensure_dir(replay_dir / "external" / label)
    staged_patch = ensure_dir(work_dir / "git") / "patch_only.diff"
    staged_patch.write_bytes(patch_file.read_bytes())

    # Same per-project serialization _replay_eval uses: one shared reconstruction
    # checkout under replay_dir, so an external replay and a pipeline-run replay
    # of the same project cannot race on rmtree/create.
    with _replay_lock(replay_dir):
        if not args.skip_docker_build:
            builder = DockerRunner(project, project.source_path, replay_dir, image_key=image_key)
            build = builder.build_image(args.build_timeout_seconds)
            if not build.ok:
                raise MetadataError(
                    f"Docker image build failed for {args.project}; see {build.log_path}"
                )

        keep_checkout = getattr(args, "keep_checkout", False)
        base_revision = (getattr(args, "base_revision", None) or "").strip() or None
        checkout = _ReplayCheckout(project, replay_dir, revision=base_revision)
        project_dir = family.project_dir(workspace_root, args.project)
        try:
            # A patch pinned to a different commit than our dataset is scored on
            # *its* commit -- but our POVs were only ever certified against ours,
            # so before the score means anything the oracle has to be re-proven
            # there. See _apply_oracle_revalidation.
            revalidation = None
            if not checkout.is_dataset_revision:
                try:
                    unpatched_path = checkout.prepare_unpatched(work_dir)
                except Exception as exc:  # noqa: BLE001
                    raise MetadataError(
                        f"could not reconstruct {args.project} at {checkout.revision[:12]}: {exc}"
                    ) from exc
                try:
                    docker = DockerRunner(
                        project, unpatched_path, work_dir, image_key=image_key,
                        network=EVALUATION_NETWORK,
                    )
                    revalidation = family.evaluate(
                        manifest, project_dir, docker, unpatched_path,
                        args.command_timeout_seconds,
                    )
                finally:
                    checkout.reclaim()

            try:
                checkout_path = checkout.prepare(work_dir)
            except Exception as exc:  # noqa: BLE001 - surface as a clear failure, not a crash
                raise MetadataError(
                    f"could not apply patch to a reconstruction of {args.project}: {exc}"
                ) from exc
            try:
                docker = DockerRunner(
                    project, checkout_path, work_dir, image_key=image_key,
                    network=EVALUATION_NETWORK,
                )
                summary = family.evaluate(
                    manifest, project_dir, docker, checkout_path,
                    args.command_timeout_seconds,
                )
            finally:
                checkout.reclaim()
            if revalidation is not None:
                summary = _apply_oracle_revalidation(
                    family, manifest, summary, revalidation, checkout.revision
                )
            summary["evaluation_mode"] = "reconstructed"
            summary["evaluation_revision"] = checkout.revision
            summary["dataset_revision"] = project.buggy_commit_id
            summary["base_revision_matches_dataset"] = checkout.is_dataset_revision
        finally:
            if not keep_checkout:
                checkout.cleanup()

    out_path = args.out.resolve()
    ensure_dir(out_path.parent)
    write_json(out_path, summary)
    row = {"project_slug": args.project, "status": "ok", "results_path": str(out_path)}
    row.update(family.summary_fields(summary))
    print(json.dumps(row, sort_keys=True))
    return 1 if summary["errored"] else 0


def _apply_oracle_revalidation(
    family: _ReplayFamily, manifest: dict, summary: dict, unpatched: dict, revision: str,
) -> dict:
    """Demote any POV that is not a valid oracle at ``revision``.

    Scoring a patch at a base commit other than the dataset's is only honest if
    the vulnerability is genuinely present there. ``unpatched`` is this family's
    evaluation of the same POVs on the **unpatched** tree at that commit: a POV
    that reproduces there is exploiting a real hole, and how the patch changes
    its outcome is evidence. A POV that does *not* reproduce there tells us
    nothing — most importantly it does not tell us the patch blocked anything,
    which is exactly what the raw ``blocked`` count would otherwise claim.

    This is the whole reason a base override is safe to offer. Two of San2Patch's
    zziplib cases are pinned to the commit of upstream's *first, incomplete* fix
    for the same CVE; that a benchmark chose such a commit is normal, but if one
    of them had closed our POV's path, replaying there would have handed the tool
    a free 1.00 for a hole that was already shut. Note the certification
    machinery cannot catch this on its own: ``content_fingerprint`` hashes the
    revision the *manifest declares*, not the tree the POV is run against, so a
    certification stays "valid" no matter which commit we check out.

    Demotion is to ERRORED rather than to a failure, because that is what
    ERRORED already means everywhere in these summaries: inconclusive, and out of
    the score's denominator. The counts are then re-derived from the records by
    the family's own ``summarize`` rather than adjusted by hand.
    """
    from . import fix_pov as gt

    valid = {
        pov["id"] for pov in unpatched.get("povs", [])
        if pov.get("outcome") == gt.REPRODUCED
    }
    invalid = []
    for pov in summary.get("povs", []):
        pov["oracle_valid_at_revision"] = pov["id"] in valid
        if pov["id"] in valid:
            continue
        invalid.append(pov["id"])
        pov["outcome"] = gt.ERRORED
        pov["reason"] = (
            f"oracle invalid at base {revision[:12]}: this POV did not reproduce on the "
            "unpatched tree at the commit the patch is written for, so its outcome on the "
            "patched tree is not evidence about the patch"
        )
    out = family.summarize(manifest, summary["povs"], summary.get("setup_results") or [])
    out["oracle_revalidation"] = {
        "revision": revision,
        "ran_at": unpatched.get("generated_at", ""),
        "valid_pov_ids": sorted(valid),
        "invalid_pov_ids": sorted(invalid),
        # A staging failure on the unpatched pass invalidates every POV at once;
        # keeping its reason is the difference between "the bug is fixed here"
        # and "the tree did not build".
        "unpatched_setup_failed": bool(
            unpatched.get("errored") and not unpatched.get("conclusive")
        ),
    }
    return out


def _replay_patch_fix_pov(args: argparse.Namespace, workspace_root: Path) -> int:
    """Entry point for ``fixpov replay-patch``. See ``_replay_patch_eval``."""
    return _replay_patch_eval(args, workspace_root, _fix_pov_family())


def _replay_patch_residual(args: argparse.Namespace, workspace_root: Path) -> int:
    """Entry point for ``respov replay-patch``. See ``_replay_patch_eval``."""
    return _replay_patch_eval(args, workspace_root, _residual_family())


def fixpov_command(args: argparse.Namespace) -> int:
    from . import fix_pov as gt

    workspace_root = args.workspace_root.resolve()

    if args.fixpov_command == "list-projects":
        sources_dir = paths.project_sources_dir(workspace_root)
        local = sorted(p.name for p in sources_dir.iterdir() if p.is_dir()) if sources_dir.exists() else []
        with_manifest = set(gt.available_project_slugs(workspace_root))
        rows = [{"project_slug": slug, "has_manifest": slug in with_manifest} for slug in local]
        print(json.dumps({"local_project_sources": rows, "count": len(rows)}, indent=2, sort_keys=True))
        return 0

    if args.fixpov_command == "status":
        rows = []
        for slug in gt.available_project_slugs(workspace_root):
            try:
                manifest = gt.load_manifest(workspace_root, slug)
            except gt.FixPovError as exc:
                rows.append({"project_slug": slug, "error": str(exc)})
                continue
            povs = manifest.get("povs", [])
            gt_dir = gt.project_dir(workspace_root, slug)
            certified = sum(1 for p in povs if (p.get("validation") or {}).get("certified"))
            # A `certified` flag alone no longer settles it: report how many POVs
            # are still eligible to score once the content fingerprint is checked,
            # so a POV edited after certification shows up here instead of
            # silently keeping the badge.
            states = [gt.certification_state(gt_dir, manifest, p) for p in povs]
            eligible = sum(1 for s in states if s["eligible"])
            unsealed = sum(1 for s in states if s["eligible"] and not s["content_verified"])
            rows.append({
                "project_slug": slug,
                "cve_id": manifest.get("cve_id", ""),
                "povs": len(povs),
                "certified": certified,
                "eligible": eligible,
                "stale_certification": certified - eligible,
                "unsealed": unsealed,
                "fully_certified": len(povs) > 0 and eligible == len(povs),
            })
        print(json.dumps({"projects": rows, "count": len(rows)}, indent=2, sort_keys=True))
        return 0

    if args.fixpov_command == "validate":
        if bool(args.project) == bool(args.all):
            print("security-pipeline: choose exactly one of --project or --all", file=sys.stderr)
            return 2
        slugs = [args.project] if args.project else gt.available_project_slugs(workspace_root)
        if not slugs:
            print("security-pipeline: no projects with a fixPOV manifest to validate", file=sys.stderr)
            return 2

        def _certify(slug: str) -> dict:
            try:
                return _certify_one_project(
                    slug, workspace_root,
                    command_timeout=args.command_timeout_seconds,
                    build_timeout=args.build_timeout_seconds,
                    skip_docker_build=args.skip_docker_build,
                    keep_workdir=args.keep_workdir,
                )
            except Exception as exc:  # noqa: BLE001 - report and keep going to the next project
                return {"project_slug": slug, "error": str(exc)}

        jobs = args.jobs if args.jobs > 0 else _auto_docker_jobs(len(slugs))
        jobs = max(1, min(jobs, len(slugs)))

        summaries: List[dict] = []
        exit_code = 0
        if jobs == 1:
            results = [(slug, _certify(slug)) for slug in slugs]
        else:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=jobs) as pool:
                # Preserve input order in the output regardless of completion order.
                results = list(zip(slugs, pool.map(_certify, slugs)))

        for _slug, summary in results:
            summaries.append(summary)
            print(json.dumps(summary, sort_keys=True))
            if "error" in summary or not summary.get("fully_certified"):
                exit_code = 1
        if len(summaries) > 1:
            print(json.dumps({"validations": summaries}, indent=2, sort_keys=True))
        return exit_code

    if args.fixpov_command == "replay":
        try:
            return _replay_fix_pov(args, workspace_root)
        except (MetadataError, gt.FixPovError) as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2

    if args.fixpov_command == "replay-patch":
        try:
            return _replay_patch_fix_pov(args, workspace_root)
        except (MetadataError, gt.FixPovError) as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2

    print(f"security-pipeline: unknown fixpov command: {args.fixpov_command}", file=sys.stderr)
    return 2



def _reverify_residual(args: argparse.Namespace, workspace_root: Path) -> int:
    """Entry point for ``respov reverify``. See ``security_pipeline.reverify``.

    Exit code reflects the *audit*, not the patches: 0 when every POV behaved as
    the tree expects, 1 when any tree contradicted its expectation (a POV that
    stopped reproducing on the buggy tree, a gap the official fix actually closes,
    or a "fixed later" claim the later tree refutes), 2 for setup failures.
    """
    from . import residual as res
    from . import reverify as rv

    if bool(args.project) == bool(args.all):
        print("security-pipeline: choose exactly one of --project or --all", file=sys.stderr)
        return 2
    slugs = [args.project] if args.project else res.available_project_slugs(workspace_root)
    if not slugs:
        print("security-pipeline: no projects with a residual manifest", file=sys.stderr)
        return 2
    if (args.at_revisions or args.still_open_revisions) and len(slugs) > 1:
        print(
            "security-pipeline: --at names a revision of one project's repository, "
            "so it cannot be combined with --all",
            file=sys.stderr,
        )
        return 2

    trees = [] if args.skip_baseline else rv.default_trees()
    for ref in args.at_revisions:
        trees.append(rv.TreeSpec(
            key=f"at:{ref}", label=f"upstream tree at {ref}",
            expectation=rv.EXPECT_BLOCK, revision=ref, repo=args.repo, image=args.control_image,
            povs=args.tree_pov_scope or None,
            notes="falsifiability control: a genuine gap upstream closed here must be blocked",
        ))
    for ref in args.still_open_revisions:
        trees.append(rv.TreeSpec(
            key=f"open:{ref}", label=f"upstream tree at {ref}, claimed still vulnerable",
            expectation=rv.EXPECT_REPRODUCE, revision=ref, repo=args.repo, image=args.control_image,
            povs=args.tree_pov_scope or None,
            notes="executes an 'open at head' claim: the gap is asserted to survive here",
        ))
    if not trees:
        print(
            "security-pipeline: nothing to run (--skip-baseline with no --at/--still-open)",
            file=sys.stderr,
        )
        return 2

    exit_code = 0
    for slug in slugs:
        try:
            record = rv.verify_project(
                workspace_root=workspace_root, project_slug=slug, trees=trees,
                command_timeout=args.command_timeout_seconds,
                build_timeout=args.build_timeout_seconds,
                skip_docker_build=args.skip_docker_build,
                keep_workdir=args.keep_workdir,
            )
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(json.dumps({"project_slug": slug, "error": str(exc)}, sort_keys=True))
            exit_code = max(exit_code, 2)
            continue
        contradicted = [p for p, v in record["povs"].items() if v.get("summary") == rv.CONTRADICTS]
        print(json.dumps({
            "project_slug": slug,
            "trees": {k: v.get("state") for k, v in record["trees"].items()},
            "povs": len(record["povs"]),
            "contradicts": contradicted,
            "controls_passed": sum(
                1 for v in record["povs"].values()
                if v.get("falsifiability_control") == "passed"
            ),
            "record": str(rv.verification_path(workspace_root, slug).relative_to(workspace_root)),
        }, sort_keys=True))
        if contradicted:
            exit_code = max(exit_code, 1)
    return exit_code


def respov_command(args: argparse.Namespace) -> int:
    from . import residual as res

    workspace_root = args.workspace_root.resolve()

    if args.respov_command == "list-projects":
        rows = [
            {"project_slug": slug}
            for slug in res.available_project_slugs(workspace_root)
        ]
        print(json.dumps({"residual_projects": rows, "count": len(rows)}, indent=2, sort_keys=True))
        return 0

    if args.respov_command == "status":
        rows = []
        for slug in res.available_project_slugs(workspace_root):
            try:
                manifest = res.load_manifest(workspace_root, slug)
            except res.ResidualError as exc:
                rows.append({"project_slug": slug, "error": str(exc)})
                continue
            povs = manifest.get("povs", [])
            res_dir = res.project_dir(workspace_root, slug)
            certified = sum(1 for p in povs if (p.get("validation") or {}).get("certified"))
            states = [res.certification_state(res_dir, manifest, p) for p in povs]
            eligible = sum(1 for s in states if s["eligible"])
            unsealed = sum(1 for s in states if s["eligible"] and not s["content_verified"])
            rows.append({
                "project_slug": slug,
                "cve_id": manifest.get("cve_id", ""),
                "residual_of": manifest.get("residual_of", ""),
                "povs": len(povs),
                "certified": certified,
                "eligible": eligible,
                "stale_certification": certified - eligible,
                "unsealed": unsealed,
                "fully_certified": len(povs) > 0 and eligible == len(povs),
            })
        print(json.dumps({"projects": rows, "count": len(rows)}, indent=2, sort_keys=True))
        return 0

    if args.respov_command == "validate":
        if bool(args.project) == bool(args.all):
            print("security-pipeline: choose exactly one of --project or --all", file=sys.stderr)
            return 2
        slugs = [args.project] if args.project else res.available_project_slugs(workspace_root)
        if not slugs:
            print("security-pipeline: no projects with a residual manifest to validate", file=sys.stderr)
            return 2

        def _certify(slug: str) -> dict:
            try:
                return _certify_one_residual_project(
                    slug, workspace_root,
                    command_timeout=args.command_timeout_seconds,
                    build_timeout=args.build_timeout_seconds,
                    skip_docker_build=args.skip_docker_build,
                    keep_workdir=args.keep_workdir,
                )
            except Exception as exc:  # noqa: BLE001 - report and keep going
                return {"project_slug": slug, "error": str(exc)}

        jobs = args.jobs if args.jobs > 0 else _auto_docker_jobs(len(slugs))
        jobs = max(1, min(jobs, len(slugs)))

        if jobs == 1:
            results = [_certify(slug) for slug in slugs]
        else:
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=jobs) as pool:
                results = list(pool.map(_certify, slugs))

        exit_code = 0
        for summary in results:
            print(json.dumps(summary, sort_keys=True))
            if "error" in summary or not summary.get("fully_certified"):
                exit_code = 1
        if len(results) > 1:
            print(json.dumps({"validations": results}, indent=2, sort_keys=True))
        return exit_code

    if args.respov_command == "reverify":
        return _reverify_residual(args, workspace_root)

    if args.respov_command == "replay":
        try:
            return _replay_residual(args, workspace_root)
        except (MetadataError, res.ResidualError) as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2

    if args.respov_command == "replay-patch":
        try:
            return _replay_patch_residual(args, workspace_root)
        except (MetadataError, res.ResidualError) as exc:
            print(f"security-pipeline: {exc}", file=sys.stderr)
            return 2

    print(f"security-pipeline: unknown respov command: {args.respov_command}", file=sys.stderr)
    return 2


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return run_command(args)
    if args.command == "fetch":
        return fetch_command(args)
    if args.command in ("fixpov", "gtpov"):
        return fixpov_command(args)
    if args.command == "respov":
        return respov_command(args)
    if args.command == "retrofit":
        return retrofit_command(args)
    if args.command == "rerun-verifier":
        return rerun_verifier_command(args)
    parser.error(f"unknown command: {args.command}")
    return 2
