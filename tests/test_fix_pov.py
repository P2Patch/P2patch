from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from security_pipeline import fix_pov as gt
from security_pipeline.cli import (
    _apply_oracle_revalidation,
    _fix_pov_family,
    _record_replayed_fix_pov,
    _rejected_run_has_scoreable_patch,
    _replay_fix_pov,
    _residual_family,
    _run_dirs_for_project,
    _same_revision,
    _select_replay_run_dirs,
)
from security_pipeline.models import (
    CommandResult,
    ExperimentConfig,
    PipelineState,
    ProjectMetadata,
    RunOptions,
)
from security_pipeline.metadata import MetadataError
from security_pipeline.stages import (
    EVALUATION_ONLY_STAGES,
    PROFILES,
    STAGE_REGISTRY,
    FixPovEvalStage,
    StageContext,
    resolve_experiment,
)
from security_pipeline.pipeline import finding_id_from_parts

SLUG = "example__proj_CVE-0000-0001_1.0"


class _FakeDocker:
    """Returns queued CommandResults in call order and records the names run."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def run_project_command(self, command, name, timeout, env_overrides=None):
        self.calls.append(name)
        result = self._results.pop(0)
        return CommandResult(
            name=name, command=[command], exit_code=result.exit_code,
            stdout=result.stdout, stderr=result.stderr, timed_out=result.timed_out,
        )


def _result(exit_code, timed_out=False):
    return CommandResult(name="", command=["c"], exit_code=exit_code, stdout="", stderr="", timed_out=timed_out)


def _write_manifest(
    workspace: Path, slug: str, povs, setup_commands=None,
    build_command=None, pov_parallelism=None,
) -> None:
    project_gt = gt.project_dir(workspace, slug)
    (project_gt / "povs").mkdir(parents=True)
    (project_gt / "povs" / "run.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    manifest = {"project_slug": slug, "cve_id": "CVE-0000-0001", "povs": povs}
    if setup_commands is not None:
        manifest["setup_commands"] = setup_commands
    if build_command is not None:
        manifest["build_command"] = build_command
    if pov_parallelism is not None:
        manifest["pov_parallelism"] = pov_parallelism
    (project_gt / "manifest.json").write_text(json.dumps(manifest))


def _povs(*ids, certified=True):
    # Only a certified POV is eligible to score, so the default here mirrors a
    # manifest that has been through `fixpov validate`.
    return [
        {"id": pov_id, "description": pov_id, "command": f"bash .security-pipeline/FIXPOVKEEP/run.sh {pov_id}",
         "reproduces_exit_code": 0, "validation": {"certified": certified}}
        for pov_id in ids
    ]


def _ctx(workspace: Path, run_dir: Path, worktree: Path, docker) -> StageContext:
    project = ProjectMetadata(
        project_slug=SLUG, cve_id="CVE-0000-0001", cwe_id="", cwe_name="", github_url="",
        github_tag="", buggy_commit_id="", fix_commit_ids="", source_path=worktree,
        dockerfile_path=worktree, build_system="maven", build_command="", test_command="",
    )
    options = RunOptions(
        workspace_root=workspace, alerts_dir=workspace, runs_dir=run_dir, command_timeout_seconds=10,
    )
    ctx = StageContext(
        options=options, experiment=ExperimentConfig(), agent_runner=None, alert={},
        project=project, finding_id="finding-1", run_dir=run_dir, worktree_path=worktree,
        state=PipelineState(run_id="t", alert_path=Path("a")), persist=lambda: None,
    )
    ctx.docker = docker
    return ctx


class ManifestLoadingTests(unittest.TestCase):
    def test_missing_manifest_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(gt.load_manifest(Path(tmp), SLUG))

    def test_malformed_manifest_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project_gt = gt.project_dir(Path(tmp), SLUG)
            project_gt.mkdir(parents=True)
            (project_gt / "manifest.json").write_text("{ not json")
            with self.assertRaises(gt.FixPovError):
                gt.load_manifest(Path(tmp), SLUG)

    def test_manifest_without_povs_raises(self) -> None:
        with self.assertRaises(gt.FixPovError):
            gt.validate_manifest_shape({"project_slug": SLUG, "povs": []})

    def test_duplicate_pov_id_raises(self) -> None:
        with self.assertRaises(gt.FixPovError):
            gt.validate_manifest_shape({"project_slug": SLUG, "povs": _povs("a", "a")})

    def test_pov_id_must_be_a_safe_basename(self) -> None:
        # The id names a docker log file; `../` in one wrote outside docker/.
        for bad in ("../../escape", "a/b", "with space", ".hidden", ""):
            with self.assertRaises(gt.FixPovError, msg=bad):
                gt.validate_manifest_shape({"project_slug": SLUG, "povs": _povs(bad)})

    def test_shipped_manifests_all_parse(self) -> None:
        root = Path(__file__).resolve().parents[1]
        slugs = gt.available_project_slugs(root)
        self.assertTrue(slugs)
        for slug in slugs:
            gt.load_manifest(root, slug)  # raises on a malformed/unsafe manifest


class CertificationTests(unittest.TestCase):
    """Only a POV whose certification still stands may count toward a score."""

    def _project(self, tmp: str, povs):
        root = Path(tmp)
        _write_manifest(root, SLUG, povs)
        return root, gt.load_manifest(root, SLUG), gt.project_dir(root, SLUG)

    def test_uncertified_pov_is_not_eligible(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest, gt_dir = self._project(tmp, _povs("p1", certified=False))
            state = gt.certification_state(gt_dir, manifest, manifest["povs"][0])
            self.assertFalse(state["eligible"])
            self.assertIn("not certified", state["reason"])

    def test_certified_without_a_hash_still_runs_but_is_unsealed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest, gt_dir = self._project(tmp, _povs("p1"))
            state = gt.certification_state(gt_dir, manifest, manifest["povs"][0])
            self.assertTrue(state["eligible"])
            self.assertFalse(state["content_verified"])

    def test_editing_a_pov_after_certification_invalidates_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest, gt_dir = self._project(tmp, _povs("p1"))
            pov = manifest["povs"][0]
            pov["validation"]["content_hash"] = gt.content_fingerprint(gt_dir, manifest, pov)
            self.assertTrue(gt.certification_state(gt_dir, manifest, pov)["content_verified"])

            (gt_dir / "povs" / "run.sh").write_text("#!/usr/bin/env bash\nexit 1\n")
            state = gt.certification_state(gt_dir, manifest, pov)
            self.assertFalse(state["eligible"])
            self.assertIn("changed since", state["reason"])

    def test_changing_the_pov_command_invalidates_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, manifest, gt_dir = self._project(tmp, _povs("p1"))
            pov = manifest["povs"][0]
            pov["validation"]["content_hash"] = gt.content_fingerprint(gt_dir, manifest, pov)
            pov["command"] = "bash .security-pipeline/FIXPOVKEEP/run.sh something-else"
            self.assertFalse(gt.certification_state(gt_dir, manifest, pov)["eligible"])

    def test_uncertified_pov_is_never_executed_and_scores_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", certified=False) + _povs("p2"))
            worktree = root / "wt"
            worktree.mkdir()
            docker = _FakeDocker([_result(1)])  # only p2 should run

            summary = gt.evaluate_manifest(
                manifest=gt.load_manifest(root, SLUG), project_gt_dir=gt.project_dir(root, SLUG),
                docker=docker, checkout_path=worktree, timeout_seconds=5,
            )

            self.assertEqual(docker.calls, ["fixpov_p2"])
            self.assertEqual(summary["blocked"], 1)
            self.assertEqual(summary["errored"], 1)
            self.assertEqual(summary["score"], 1.0)  # over conclusive POVs only
            self.assertFalse(summary["all_blocked"])  # p1 was never tried
            skipped = next(p for p in summary["povs"] if p["id"] == "p1")
            self.assertEqual(skipped["outcome"], gt.ERRORED)
            self.assertIsNone(skipped["command_result"])

    def test_validate_may_run_uncertified_povs(self) -> None:
        # `fixpov validate` is what creates certifications, so it opts out.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", certified=False))
            worktree = root / "wt"
            worktree.mkdir()
            docker = _FakeDocker([_result(0)])
            summary = gt.evaluate_manifest(
                manifest=gt.load_manifest(root, SLUG), project_gt_dir=gt.project_dir(root, SLUG),
                docker=docker, checkout_path=worktree, timeout_seconds=5,
                enforce_certification=False,
            )
            self.assertEqual(docker.calls, ["fixpov_p1"])
            self.assertEqual(summary["reproduced"], 1)


class StagingFailureTests(unittest.TestCase):
    """A score is only meaningful if the code under test actually built."""

    def _evaluate(self, root: Path, docker, **manifest_kwargs):
        worktree = root / "wt"
        worktree.mkdir()
        return gt.evaluate_manifest(
            manifest=gt.load_manifest(root, SLUG), project_gt_dir=gt.project_dir(root, SLUG),
            docker=docker, checkout_path=worktree, timeout_seconds=5,
        )

    def test_failed_build_makes_every_pov_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", "p2"), build_command="false", pov_parallelism=1)
            # Build fails; the POVs would each have exited 1 ("missing class"),
            # which the old reading counted as two blocked exploits: a 100%
            # coverage score off a build that never produced a class file.
            docker = _FakeDocker([_result(1)])

            summary = self._evaluate(root, docker)

            self.assertEqual(docker.calls, ["fixpov_build"])  # no POV was run
            self.assertEqual(summary["blocked"], 0)
            self.assertEqual(summary["errored"], 2)
            self.assertIsNone(summary["score"])
            self.assertFalse(summary["all_blocked"])
            self.assertIn("build command failed", summary["povs"][0]["reason"])

    def test_failed_setup_command_makes_every_pov_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1"), setup_commands=["false"])
            summary = self._evaluate(root, _FakeDocker([_result(3)]))
            self.assertEqual(summary["errored"], 1)
            self.assertIsNone(summary["score"])

    def test_successful_build_still_scores_normally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", "p2"), build_command="ok", pov_parallelism=1)
            docker = _FakeDocker([_result(0), _result(1), _result(1)])
            summary = self._evaluate(root, docker)
            self.assertEqual(docker.calls, ["fixpov_build", "fixpov_p1", "fixpov_p2"])
            self.assertEqual(summary["blocked"], 2)
            self.assertEqual(summary["score"], 1.0)


class ClassifyAndSummarizeTests(unittest.TestCase):
    def test_classify_outcomes(self) -> None:
        self.assertEqual(gt.classify_outcome(_result(0), 0), gt.REPRODUCED)
        self.assertEqual(gt.classify_outcome(_result(1), 0), gt.BLOCKED)
        self.assertEqual(gt.classify_outcome(_result(0, timed_out=True), 0), gt.ERRORED)

    def test_error_exit_code_is_errored_not_blocked(self) -> None:
        # A harness/build failure (reserved code 2) must not count as "blocked".
        self.assertEqual(gt.classify_outcome(_result(2), 0), gt.ERRORED)
        self.assertEqual(gt.classify_outcome(_result(2), 0, error_exit_code=2), gt.ERRORED)
        # Disabling the reserved code makes any non-zero a block again.
        self.assertEqual(gt.classify_outcome(_result(2), 0, error_exit_code=None), gt.BLOCKED)

    def test_score_excludes_errored(self) -> None:
        pov_results = [
            {"id": "a", "outcome": gt.BLOCKED},
            {"id": "b", "outcome": gt.REPRODUCED},
            {"id": "c", "outcome": gt.ERRORED},
        ]
        summary = gt.summarize({"project_slug": SLUG}, pov_results)
        self.assertEqual(summary["blocked"], 1)
        self.assertEqual(summary["reproduced"], 1)
        self.assertEqual(summary["errored"], 1)
        self.assertEqual(summary["score"], 0.5)  # 1 blocked / (1 blocked + 1 reproduced)
        self.assertFalse(summary["all_blocked"])

    def test_all_blocked_scores_one(self) -> None:
        summary = gt.summarize(
            {"project_slug": SLUG}, [{"id": "a", "outcome": gt.BLOCKED}, {"id": "b", "outcome": gt.BLOCKED}]
        )
        self.assertEqual(summary["score"], 1.0)
        self.assertTrue(summary["all_blocked"])


class BuildOnceAndParallelismTests(unittest.TestCase):
    def test_worker_count_is_one_without_build_command(self) -> None:
        # Without a shared build step every POV self-compiles against the mounted
        # repo, so they must stay sequential (no target/ write race).
        self.assertEqual(gt._pov_worker_count({"povs": _povs("a", "b", "c")}, 3), 1)

    def test_worker_count_defaults_capped_with_build_command(self) -> None:
        m = {"build_command": "bash .../build.sh", "povs": _povs("a", "b")}
        self.assertEqual(gt._pov_worker_count(m, 2), 2)  # min(4, count)
        self.assertEqual(gt._pov_worker_count({**m}, 9), 4)  # capped at 4

    def test_worker_count_honors_pov_parallelism_override(self) -> None:
        m = {"build_command": "b", "pov_parallelism": 1, "povs": _povs("a", "b")}
        self.assertEqual(gt._pov_worker_count(m, 5), 1)
        m2 = {"build_command": "b", "pov_parallelism": 3, "povs": _povs("a")}
        self.assertEqual(gt._pov_worker_count(m2, 5), 3)

    def test_build_command_runs_once_before_povs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(
                root, SLUG, _povs("p1", "p2"),
                build_command="bash .security-pipeline/FIXPOVKEEP/build.sh",
                pov_parallelism=1,  # keep the stub docker deterministic
            )
            manifest = gt.load_manifest(root, SLUG)
            worktree = root / "wt"
            worktree.mkdir()
            # queue: one result for the build, then one per POV
            docker = _FakeDocker([_result(0), _result(0), _result(1)])
            summary = gt.evaluate_manifest(
                manifest=manifest, project_gt_dir=gt.project_dir(root, SLUG),
                docker=docker, checkout_path=worktree, timeout_seconds=5,
            )
            self.assertEqual(docker.calls[0], "fixpov_build")
            self.assertEqual(docker.calls[1:], ["fixpov_p1", "fixpov_p2"])
            self.assertEqual(summary["total"], 2)  # build call is not a POV result
            self.assertEqual(summary["reproduced"], 1)
            self.assertEqual(summary["blocked"], 1)


class FixPovStageTests(unittest.TestCase):
    def test_missing_manifest_skips_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            worktree = root / "worktree"
            worktree.mkdir()
            docker = _FakeDocker([])
            ctx = _ctx(root, root / "run", worktree, docker)
            FixPovEvalStage().run(ctx)  # must not raise
            steps = ctx.state.steps
            self.assertEqual(steps[-1]["name"], "fix_pov_eval")
            self.assertEqual(steps[-1]["status"], "skipped")
            self.assertIsNone(ctx.fix_pov_results)

    def test_all_blocked_records_ok_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", "p2"))
            worktree = root / "worktree"
            worktree.mkdir()
            docker = _FakeDocker([_result(1), _result(1)])  # both blocked
            ctx = _ctx(root, root / "run", worktree, docker)

            FixPovEvalStage().run(ctx)

            self.assertEqual(docker.calls, ["fixpov_p1", "fixpov_p2"])
            self.assertEqual(ctx.fix_pov_results["blocked"], 2)
            self.assertEqual(ctx.fix_pov_results["score"], 1.0)
            step = ctx.state.steps[-1]
            self.assertEqual(step["status"], "ok")
            self.assertTrue(step["all_blocked"])
            # results.json written
            results = json.loads((root / "run" / "fix_pov" / "results.json").read_text())
            self.assertEqual(results["total"], 2)
            # staged POVs cleaned up
            self.assertFalse((worktree / ".security-pipeline" / "fixpov").exists())

    def test_reproduced_pov_is_recorded_but_not_gated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", "p2"))
            worktree = root / "worktree"
            worktree.mkdir()
            docker = _FakeDocker([_result(0), _result(1)])  # p1 still reproduces
            ctx = _ctx(root, root / "run", worktree, docker)

            FixPovEvalStage().run(ctx)  # non-gating: must NOT raise

            self.assertEqual(ctx.fix_pov_results["reproduced"], 1)
            self.assertEqual(ctx.fix_pov_results["blocked"], 1)
            self.assertEqual(ctx.fix_pov_results["score"], 0.5)
            self.assertEqual(ctx.state.steps[-1]["status"], "ok")

    def test_build_failure_exit_counts_as_errored_excluded_from_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1", "p2"))
            worktree = root / "worktree"
            worktree.mkdir()
            # p1 blocked (exit 1), p2 build failure (reserved code 2 -> errored).
            docker = _FakeDocker([_result(1), _result(2)])
            ctx = _ctx(root, root / "run", worktree, docker)
            FixPovEvalStage().run(ctx)
            self.assertEqual(ctx.fix_pov_results["blocked"], 1)
            self.assertEqual(ctx.fix_pov_results["errored"], 1)
            # Score is over conclusive POVs only, so the build failure neither
            # rewards nor penalises the patch: 1 blocked / 1 conclusive == 1.0.
            self.assertEqual(ctx.fix_pov_results["score"], 1.0)

    def test_evaluation_error_records_errored_not_raise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, SLUG, _povs("p1"))
            worktree = root / "worktree"
            worktree.mkdir()
            ctx = _ctx(root, root / "run", worktree, _FakeDocker([_result(1)]))
            with mock.patch.object(gt, "evaluate_manifest", side_effect=RuntimeError("boom")):
                FixPovEvalStage().run(ctx)  # must not raise
            self.assertEqual(ctx.state.steps[-1]["status"], "errored")


class FixPovReplayTests(unittest.TestCase):
    def test_selects_only_accepted_runs_for_the_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alerts = root / "alerts"
            runs = root / "runs"
            alerts.mkdir()
            runs.mkdir()
            (alerts / "ALERT.json").write_text(json.dumps({"cve_id": "CVE-0000-0001"}))
            project = SimpleNamespace(project_slug=SLUG, cve_id="CVE-0000-0001")
            finding_id = finding_id_from_parts("ALERT.json", SLUG, project.cve_id)

            accepted = runs / f"20200101_000000_{finding_id}"
            rejected = runs / f"20200102_000000_{finding_id}"
            unrelated = runs / "20200101_000000_finding-aaaaaaaaaaaa"
            for run_dir, status in (
                (accepted, "accepted"),
                (rejected, "rejected"),
                (unrelated, "accepted"),
            ):
                run_dir.mkdir()
                (run_dir / "verdict.json").write_text(json.dumps({"status": status}))

            self.assertEqual(
                _run_dirs_for_project(
                    project=project, alerts_dir=alerts, runs_dir=runs
                ),
                [accepted],
            )
            self.assertEqual(
                _select_replay_run_dirs(
                    project=project,
                    alerts_dir=alerts,
                    runs_dir=runs,
                    requested_run_ids=[accepted.name, accepted.name],
                ),
                [accepted],
            )
            with self.assertRaisesRegex(MetadataError, "not an accepted run"):
                _select_replay_run_dirs(
                    project=project,
                    alerts_dir=alerts,
                    runs_dir=runs,
                    requested_run_ids=[rejected.name],
                )

    def test_include_rejected_admits_only_runs_with_a_product_patch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            alerts = root / "alerts"
            runs = root / "runs"
            alerts.mkdir()
            runs.mkdir()
            (alerts / "ALERT.json").write_text(json.dumps({"cve_id": "CVE-0000-0001"}))
            project = SimpleNamespace(project_slug=SLUG, cve_id="CVE-0000-0001")
            finding_id = finding_id_from_parts("ALERT.json", SLUG, project.cve_id)

            def _run(name, status, diff=None):
                d = runs / f"{name}_{finding_id}"
                (d / "git").mkdir(parents=True)
                (d / "verdict.json").write_text(json.dumps({"status": status}))
                if diff is not None:
                    (d / "git" / "patch_only.diff").write_text(diff)
                return d

            accepted = _run("20200101_000000", "accepted")
            good = _run("20200102_000000", "rejected",
                        "diff --git a/src/A.java b/src/A.java\n+++ b/src/A.java\n+fix\n")
            povonly = _run("20200103_000000", "rejected",
                           "+++ b/.security-pipeline/pov/Pov.java\n+x\n")
            empty = _run("20200104_000000", "rejected", "")
            huge = _run("20200105_000000", "rejected",
                        "+++ b/src/B.java\n" + ("x" * 1_000_001))

            self.assertTrue(_rejected_run_has_scoreable_patch(good))
            self.assertFalse(_rejected_run_has_scoreable_patch(povonly))
            self.assertFalse(_rejected_run_has_scoreable_patch(empty))
            self.assertFalse(_rejected_run_has_scoreable_patch(huge))

            self.assertEqual(
                _run_dirs_for_project(project=project, alerts_dir=alerts, runs_dir=runs),
                [accepted],
            )
            self.assertEqual(
                _run_dirs_for_project(
                    project=project, alerts_dir=alerts, runs_dir=runs, include_rejected=True
                ),
                sorted([accepted, good]),
            )
            self.assertEqual(
                _select_replay_run_dirs(
                    project=project, alerts_dir=alerts, runs_dir=runs,
                    requested_run_ids=[good.name], include_rejected=True,
                ),
                [good],
            )

    def test_record_replay_replaces_stale_eval_but_preserves_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            state = {
                "status": "accepted",
                "steps": [
                    {"name": "metadata", "status": "ok"},
                    {"name": "fix_pov_eval", "status": "skipped"},
                ],
                "commands": [
                    {"name": "regression_1", "exit_code": 0},
                    {"name": "fixpov_old", "exit_code": 1},
                ],
            }
            (run_dir / "state.json").write_text(json.dumps(state))
            (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))
            summary = gt.summarize(
                {"project_slug": SLUG},
                [
                    {
                        "id": "new",
                        "outcome": gt.REPRODUCED,
                        "command_result": {"name": "fixpov_new", "exit_code": 0},
                    }
                ],
            )
            summary["evaluation_mode"] = "posthoc_replay"

            self.assertTrue(_record_replayed_fix_pov(run_dir, summary))

            saved_state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(saved_state["status"], "accepted")
            self.assertEqual(
                [command["name"] for command in saved_state["commands"]],
                ["regression_1", "fixpov_new"],
            )
            eval_steps = [
                step for step in saved_state["steps"] if step["name"] == "fix_pov_eval"
            ]
            self.assertEqual(len(eval_steps), 1)
            self.assertTrue(eval_steps[0]["replayed"])
            saved_results = json.loads((run_dir / "fix_pov/results.json").read_text())
            self.assertEqual(saved_results["evaluation_mode"], "posthoc_replay")
            self.assertEqual(
                json.loads((run_dir / "verdict.json").read_text())["status"], "accepted"
            )

    def test_record_replay_migrates_a_legacy_ground_truth_run(self) -> None:
        """A run recorded before the fixPOV rename carries a ``ground_truth_eval``
        step and ``gtpov_*`` commands; a replay must replace those too, so the run
        ends up with exactly one eval step and one set of POV commands."""
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            state = {
                "status": "accepted",
                "steps": [
                    {"name": "metadata", "status": "ok"},
                    {"name": "ground_truth_eval", "status": "ok", "score": 0.5},
                ],
                "commands": [
                    {"name": "regression_1", "exit_code": 0},
                    {"name": "gtpov_setup", "exit_code": 0},
                    {"name": "gtpov_old", "exit_code": 1},
                ],
            }
            (run_dir / "state.json").write_text(json.dumps(state))
            summary = gt.summarize(
                {"project_slug": SLUG},
                [
                    {
                        "id": "new",
                        "outcome": gt.BLOCKED,
                        "command_result": {"name": "fixpov_new", "exit_code": 1},
                    }
                ],
            )
            summary["evaluation_mode"] = "reconstructed"

            self.assertTrue(_record_replayed_fix_pov(run_dir, summary))

            self.assertTrue((run_dir / "fix_pov" / "results.json").is_file())
            saved_state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(
                [command["name"] for command in saved_state["commands"]],
                ["regression_1", "fixpov_new"],
            )
            self.assertEqual(
                [step["name"] for step in saved_state["steps"]],
                ["metadata", "fix_pov_eval"],
            )

    def test_replay_updates_existing_run_without_gating_on_reproduction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "benchmark/dataset/project-sources" / SLUG
            dockerfiles = root / "benchmark/dataset/Dockerfiles" / SLUG / "1"
            alerts = root / "finder_results_filtered"
            runs = root / "runs"
            source.mkdir(parents=True)
            dockerfiles.mkdir(parents=True)
            alerts.mkdir()
            runs.mkdir()
            (source / "pom.xml").write_text("<project />")
            (dockerfiles / "Dockerfile").write_text("FROM scratch\n")
            (root / "benchmark/dataset/project_info.csv").write_text(
                "project_slug,cve_id,cwe_id\n"
                f"{SLUG},CVE-0000-0001,CWE-000\n"
            )
            (root / "benchmark/dataset/build_info.csv").write_text(
                "project_slug,jdk_version\n" f"{SLUG},8\n"
            )
            (alerts / "ALERT.json").write_text(
                json.dumps({"cve_id": "CVE-0000-0001"})
            )
            _write_manifest(root, SLUG, _povs("new"))

            finding_id = finding_id_from_parts("ALERT.json", SLUG, "CVE-0000-0001")
            run_dir = runs / f"20200101_000000_{finding_id}"
            (run_dir / "worktree").mkdir(parents=True)
            (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))
            (run_dir / "state.json").write_text(
                json.dumps(
                    {
                        "status": "accepted",
                        "steps": [{"name": "fix_pov_eval", "status": "skipped"}],
                        "commands": [],
                    }
                )
            )
            summary = gt.summarize(
                {"project_slug": SLUG},
                [
                    {
                        "id": "new",
                        "outcome": gt.REPRODUCED,
                        "command_result": {"name": "fixpov_new", "exit_code": 0},
                    }
                ],
            )
            args = Namespace(
                project=SLUG,
                alerts_dir=Path("finder_results_filtered"),
                runs_dir=Path("runs"),
                run_ids=None,
                skip_docker_build=True,
                build_timeout_seconds=10,
                command_timeout_seconds=10,
            )

            stdout = StringIO()
            with mock.patch.object(gt, "evaluate_manifest", return_value=summary):
                with redirect_stdout(stdout):
                    exit_code = _replay_fix_pov(args, root)

            self.assertEqual(exit_code, 0)  # reproduced is a metric, not a gate
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["reproduced"], 1)
            self.assertEqual(output["status"], "ok")
            self.assertTrue((run_dir / "fix_pov/results.json").exists())
            # No buggy_commit_id in this fixture's project_info.csv, so
            # reconstruction is impossible and the preserved worktree is used.
            self.assertEqual(output["evaluation_mode"], "worktree")
            self.assertIn("buggy_commit_id", output["reconstruction_skipped"])


class AlternateBaseOracleTests(unittest.TestCase):
    """Scoring a third-party patch on the commit it was actually written for.

    Benchmarks do not all pin the same commit for the same CVE — VulnLoc pins two
    zziplib CVEs at upstream's *first, incomplete* fix while we pin them before any
    fix — so a patch has to be reconstructed on its own base or it will not apply.
    The danger that buys is obvious once stated: if that base already closed the
    POV's path, every POV comes back BLOCKED and the tool collects a free 1.00 for
    a hole somebody else shut. Nothing else in the system catches this —
    ``content_fingerprint`` hashes the revision the *manifest declares*, not the
    tree the POV runs against — so the unpatched re-proof is the only guard.
    """

    @staticmethod
    def _summary(family, outcomes):
        manifest = {"project_slug": SLUG, "cve_id": "CVE-0000-0001",
                    "residual_of": "deadbeef",
                    "povs": _povs(*outcomes)}
        records = [
            {"id": pov_id, "command": f"c-{pov_id}", "reproduces_exit_code": 0,
             "outcome": outcome, "reason": None, "command_result": None}
            for pov_id, outcome in outcomes.items()
        ]
        return manifest, family.summarize(manifest, records, [])

    def test_a_pov_that_still_reproduces_at_the_new_base_keeps_its_verdict(self):
        family = _fix_pov_family()
        manifest, unpatched = self._summary(family, {"p1": gt.REPRODUCED, "p2": gt.REPRODUCED})
        _, patched = self._summary(family, {"p1": gt.BLOCKED, "p2": gt.REPRODUCED})

        out = _apply_oracle_revalidation(family, manifest, patched, unpatched, "03de3beabbf5")

        self.assertEqual((out["blocked"], out["reproduced"], out["errored"]), (1, 1, 0))
        self.assertEqual(out["score"], 0.5)
        self.assertEqual(out["oracle_revalidation"]["valid_pov_ids"], ["p1", "p2"])
        self.assertTrue(all(p["oracle_valid_at_revision"] for p in out["povs"]))

    def test_a_pov_already_fixed_at_the_new_base_cannot_be_credited(self):
        """The whole point. p2 does not reproduce on the UNPATCHED tree at this
        commit, so its BLOCKED on the patched tree says nothing about the patch —
        counting it would report 1.00 for a patch that closed one hole out of one
        that was actually open."""
        family = _fix_pov_family()
        manifest, unpatched = self._summary(family, {"p1": gt.REPRODUCED, "p2": gt.BLOCKED})
        _, patched = self._summary(family, {"p1": gt.BLOCKED, "p2": gt.BLOCKED})

        out = _apply_oracle_revalidation(family, manifest, patched, unpatched, "03de3beabbf5")

        self.assertEqual((out["blocked"], out["errored"]), (1, 1))
        self.assertEqual(out["score"], 1.0)  # over the one POV that was really open
        # ...and the claim "every fixPOV exploit was blocked" is withheld,
        # because one of them was never a valid test here.
        self.assertFalse(out["all_blocked"])
        self.assertEqual(out["oracle_revalidation"]["invalid_pov_ids"], ["p2"])
        demoted = next(p for p in out["povs"] if p["id"] == "p2")
        self.assertEqual(demoted["outcome"], gt.ERRORED)
        self.assertIn("did not reproduce on the unpatched tree", demoted["reason"])

    def test_an_unpatched_tree_that_never_built_scores_nothing(self):
        """A staging failure errors every POV on the unpatched pass. That is
        indistinguishable from 'the bug is gone here' as far as evidence goes, so
        the score must be withheld rather than defaulted either way."""
        family = _fix_pov_family()
        manifest, unpatched = self._summary(family, {"p1": gt.ERRORED, "p2": gt.ERRORED})
        _, patched = self._summary(family, {"p1": gt.BLOCKED, "p2": gt.BLOCKED})

        out = _apply_oracle_revalidation(family, manifest, patched, unpatched, "33d6e9c5")

        self.assertIsNone(out["score"])
        self.assertEqual(out["errored"], 2)
        self.assertTrue(out["oracle_revalidation"]["unpatched_setup_failed"])

    def test_the_residual_family_demotes_through_its_own_vocabulary(self):
        family = _residual_family()
        manifest, unpatched = self._summary(family, {"p1": gt.REPRODUCED, "p2": gt.BLOCKED})
        _, patched = self._summary(family, {"p1": gt.BLOCKED, "p2": gt.BLOCKED})

        out = _apply_oracle_revalidation(family, manifest, patched, unpatched, "33d6e9c5")

        self.assertEqual(out["hardened_beyond_fix"], 1)
        self.assertEqual(out["errored"], 1)
        self.assertNotIn("all_blocked", out)

    def test_revision_equality_is_prefix_wise(self):
        """Benchmarks abbreviate; project_info.csv does not. Comparing them
        literally would report every case as a mismatch."""
        full = "3a4ffcdd78708c2c7bb9aa89b0a6df0aab6c9d3e"
        self.assertTrue(_same_revision("3a4ffcdd", full))
        self.assertTrue(_same_revision(full, full))
        self.assertFalse(_same_revision("03de3be", full))
        # Empty is never "the same as" anything — a project with no recorded
        # commit must not silently match whatever it is compared against.
        self.assertFalse(_same_revision("", ""))
        self.assertFalse(_same_revision(None, full))


class ReplayReconstructionTests(unittest.TestCase):
    """Replay rebuilds the patched tree from the vulnerable revision + the run's diff.

    Scoring the run's preserved ``worktree/`` still works and remains the
    fallback, but it fails once those (multi-GB, gitignored) directories are
    pruned and it inherits whatever revision the shared source checkout points at
    today. Reconstruction pins the base commit the POVs were certified against.
    """

    def _workspace(self, tmp: Path, *, base_content: str, patch: str, keep_worktree=True):
        source = tmp / "benchmark/dataset/project-sources" / SLUG
        dockerfiles = tmp / "benchmark/dataset/Dockerfiles" / SLUG / "1"
        alerts = tmp / "finder_results_filtered"
        runs = tmp / "runs"
        source.mkdir(parents=True)
        dockerfiles.mkdir(parents=True)
        alerts.mkdir()
        runs.mkdir()
        (dockerfiles / "Dockerfile").write_text("FROM scratch\n")
        (source / "pom.xml").write_text("<project />")
        (source / "App.java").write_text(base_content)

        def git(*args):
            subprocess.run(
                ["git", *args], cwd=source, check=True,
                capture_output=True, text=True, errors="replace",
            )

        git("init", "-q")
        git("config", "user.email", "t@example.invalid")
        git("config", "user.name", "t")
        git("add", "-A")
        git("commit", "-q", "--no-gpg-sign", "-m", "vulnerable")
        base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=source, capture_output=True, text=True,
        ).stdout.strip()
        # The shared checkout then moves on — exactly the drift reconstruction is
        # meant to be immune to. Replay must score `base`, not this.
        (source / "App.java").write_text("// unrelated upstream work\n")
        git("commit", "-qam", "later upstream commit", "--no-gpg-sign")

        (tmp / "benchmark/dataset/project_info.csv").write_text(
            "project_slug,cve_id,cwe_id,buggy_commit_id\n"
            f"{SLUG},CVE-0000-0001,CWE-000,{base}\n"
        )
        (tmp / "benchmark/dataset/build_info.csv").write_text("project_slug,jdk_version\n" f"{SLUG},8\n")
        (alerts / "ALERT.json").write_text(json.dumps({"cve_id": "CVE-0000-0001"}))
        _write_manifest(tmp, SLUG, _povs("p1"))

        finding_id = finding_id_from_parts("ALERT.json", SLUG, "CVE-0000-0001")
        run_dir = runs / f"20200101_000000_{finding_id}"
        (run_dir / "git").mkdir(parents=True)
        if keep_worktree:
            (run_dir / "worktree").mkdir(parents=True)
        (run_dir / "git" / "patch_only.diff").write_text(patch)
        (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))
        (run_dir / "state.json").write_text(
            json.dumps({"status": "accepted", "steps": [], "commands": []})
        )
        return run_dir, base

    @staticmethod
    def _args():
        return Namespace(
            project=SLUG,
            alerts_dir=Path("finder_results_filtered"),
            runs_dir=Path("runs"),
            run_ids=None,
            skip_docker_build=True,
            build_timeout_seconds=10,
            command_timeout_seconds=10,
            from_worktree=False,
            keep_checkout=False,
        )

    _PATCH = (
        "diff --git a/App.java b/App.java\n"
        "--- a/App.java\n"
        "+++ b/App.java\n"
        "@@ -1 +1 @@\n"
        "-vulnerable\n"
        "+patched\n"
    )

    def test_scores_the_reconstructed_tree_not_the_preserved_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir, _ = self._workspace(root, base_content="vulnerable\n", patch=self._PATCH)
            seen = {}

            def fake_eval(**kwargs):
                path = kwargs["checkout_path"]
                seen["path"] = path
                seen["content"] = (path / "App.java").read_text()
                return gt.summarize({"project_slug": SLUG}, [])

            stdout = StringIO()
            with mock.patch.object(gt, "evaluate_manifest", side_effect=fake_eval):
                with redirect_stdout(stdout):
                    exit_code = _replay_fix_pov(self._args(), root)

            self.assertEqual(exit_code, 0)
            output = json.loads(stdout.getvalue())
            self.assertEqual(output["evaluation_mode"], "reconstructed")
            # The run's patch, applied to the *vulnerable* revision — not the
            # unrelated content the shared checkout has drifted to.
            self.assertEqual(seen["content"], "patched\n")
            self.assertNotEqual(seen["path"], run_dir / "worktree")

    def test_reconstruction_works_without_a_preserved_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(
                root, base_content="vulnerable\n", patch=self._PATCH, keep_worktree=False
            )
            stdout = StringIO()
            with mock.patch.object(
                gt, "evaluate_manifest",
                side_effect=lambda **kw: gt.summarize({"project_slug": SLUG}, []),
            ):
                with redirect_stdout(stdout):
                    exit_code = _replay_fix_pov(self._args(), root)

            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["evaluation_mode"], "reconstructed")

    def test_falls_back_to_the_worktree_when_the_patch_does_not_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir, _ = self._workspace(
                root,
                base_content="something else entirely\n",
                patch=self._PATCH,  # context lines will not match
            )
            stdout = StringIO()
            with mock.patch.object(
                gt, "evaluate_manifest",
                side_effect=lambda **kw: gt.summarize({"project_slug": SLUG}, []),
            ):
                with redirect_stdout(stdout):
                    exit_code = _replay_fix_pov(self._args(), root)

            output = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 0)
            self.assertEqual(output["evaluation_mode"], "worktree")
            self.assertIn("does not apply", output["reconstruction_skipped"])
            self.assertTrue((run_dir / "fix_pov/results.json").exists())

    def test_errors_only_when_neither_tree_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(
                root,
                base_content="something else entirely\n",
                patch=self._PATCH,
                keep_worktree=False,
            )
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = _replay_fix_pov(self._args(), root)

            output = json.loads(stdout.getvalue())
            self.assertEqual(exit_code, 1)
            self.assertEqual(output["status"], "error")
            self.assertIn("worktree is missing", output["error"])

    def test_from_worktree_flag_skips_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root, base_content="vulnerable\n", patch=self._PATCH)
            args = self._args()
            args.from_worktree = True
            stdout = StringIO()
            with mock.patch.object(
                gt, "evaluate_manifest",
                side_effect=lambda **kw: gt.summarize({"project_slug": SLUG}, []),
            ):
                with redirect_stdout(stdout):
                    _replay_fix_pov(args, root)

            self.assertEqual(json.loads(stdout.getvalue())["evaluation_mode"], "worktree")

    def test_reconstruction_checkout_is_removed_afterwards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root, base_content="vulnerable\n", patch=self._PATCH)
            with mock.patch.object(
                gt, "evaluate_manifest",
                side_effect=lambda **kw: gt.summarize({"project_slug": SLUG}, []),
            ):
                with redirect_stdout(StringIO()):
                    _replay_fix_pov(self._args(), root)

            self.assertFalse((root / "runs/.fixpov_replay" / SLUG / "checkout").exists())


class ProfileWiringTests(unittest.TestCase):
    def test_every_profile_ends_in_the_evaluation_stages(self) -> None:
        """Both measurement stages run last, in order, after every gate.

        They must stay at the tail so no agent (exploiter, patcher, verifier) can
        ever see the fixPOVs, the residual POVs, or the official fix —
        any of which would leak the real CVE.
        """
        for name in PROFILES:
            exp = resolve_experiment(profile=name)
            self.assertEqual(
                list(exp.stages[-2:]), ["fix_pov_eval", "residual_eval"], name
            )

    def test_stage_registered(self) -> None:
        self.assertIn("fix_pov_eval", STAGE_REGISTRY)
        self.assertIn("residual_eval", STAGE_REGISTRY)

    def test_stripping_eval_stage_still_resolves(self) -> None:
        base = resolve_experiment(profile="full")
        trimmed = [s for s in base.stages if s not in EVALUATION_ONLY_STAGES]
        exp = resolve_experiment(profile="full", stages=trimmed)
        self.assertNotIn("fix_pov_eval", exp.stages)
        self.assertEqual(exp.stages[-1], "verifier")


if __name__ == "__main__":
    unittest.main()
