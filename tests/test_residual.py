"""Tests for residual-gap POV evaluation (``security_pipeline/residual.py``).

The invariants worth protecting here are the two that make this metric mean
something different from fixPOV:

  1. the **inverted certification oracle** — a residual POV is certified only
     when it reproduces on the unpatched tree AND still reproduces after the
     official fix. Getting this backwards would silently re-implement the
     fixPOV contract and certify nothing (or, worse, certify POVs the
     official fix actually closes);
  2. the **bonus scoring vocabulary** — ``blocked`` is credit, ``reproduced`` is
     the neutral norm, and the summary must not leak ``all_blocked`` (which any
     consumer would read as a coverage gate).
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from security_pipeline import fix_pov as gt
from security_pipeline import residual as res
from security_pipeline.cli import (
    _record_replayed_eval,
    _residual_family,
)
from security_pipeline.models import CommandResult
from security_pipeline.stages import (
    EVALUATION_ONLY_STAGES,
    PROFILES,
    STAGE_REGISTRY,
    ResidualEvalStage,
    resolve_experiment,
)

SLUG = "example__proj_CVE-0000-0001_1.0"
FIX_COMMIT = "a" * 40


class _FakeDocker:
    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def run_project_command(self, command, name, timeout, env_overrides=None):
        self.calls.append(name)
        exit_code = self._results.pop(0)
        return CommandResult(
            name=name, command=[command], exit_code=exit_code,
            stdout="", stderr="", timed_out=False,
        )


def _write_manifest(workspace: Path, povs, *, residual_of=FIX_COMMIT) -> dict:
    project_res = res.project_dir(workspace, SLUG)
    (project_res / "povs").mkdir(parents=True)
    (project_res / "povs" / "run.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    manifest = {
        "project_slug": SLUG,
        "cve_id": "CVE-0000-0001",
        "residual_of": residual_of,
        "povs": povs,
    }
    (project_res / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def _povs(*ids, certified=True):
    return [
        {
            "id": pov_id,
            "description": pov_id,
            "gap_summary": f"official fix does not close {pov_id}",
            "command": f"bash .security-pipeline/respov/run.sh {pov_id}",
            "reproduces_exit_code": 0,
            "validation": {"certified": certified},
        }
        for pov_id in ids
    ]


class CertificationOracleTests(unittest.TestCase):
    """The inverted contract — the crux of this whole module."""

    def test_reproducing_before_and_after_certifies(self) -> None:
        self.assertTrue(res.certifies(res.REPRODUCED, res.REPRODUCED))

    def test_blocked_by_official_fix_does_not_certify(self) -> None:
        """If upstream closes it, it is a fixPOV, not a residual one."""
        self.assertFalse(res.certifies(res.REPRODUCED, res.BLOCKED))

    def test_not_reproducing_on_unpatched_source_does_not_certify(self) -> None:
        """Guards a broken harness that never reproduces anywhere."""
        self.assertFalse(res.certifies(res.BLOCKED, res.BLOCKED))
        self.assertFalse(res.certifies(res.ERRORED, res.REPRODUCED))

    def test_errored_after_does_not_certify(self) -> None:
        self.assertFalse(res.certifies(res.REPRODUCED, res.ERRORED))

    def test_inverted_relative_to_fix_pov(self) -> None:
        """Belt-and-braces: the two contracts must disagree on the same inputs.

        A POV blocked by the official fix certifies as fixPOV and must NOT
        certify as residual; one that survives it is the exact opposite.
        """
        gt_contract = lambda b, a: b == gt.REPRODUCED and a == gt.BLOCKED  # noqa: E731
        for before, after in ((res.REPRODUCED, res.BLOCKED), (res.REPRODUCED, res.REPRODUCED)):
            self.assertNotEqual(
                gt_contract(before, after),
                res.certifies(before, after),
                f"contracts must differ for before={before} after={after}",
            )


class ManifestValidationTests(unittest.TestCase):
    def test_requires_residual_of(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_manifest(workspace, _povs("a"), residual_of="")
            with self.assertRaises(res.ResidualError) as caught:
                res.load_manifest(workspace, SLUG)
            self.assertIn("residual_of", str(caught.exception))

    def test_requires_gap_summary_per_pov(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            povs = _povs("a")
            del povs[0]["gap_summary"]
            _write_manifest(workspace, povs)
            with self.assertRaises(res.ResidualError) as caught:
                res.load_manifest(workspace, SLUG)
            self.assertIn("gap_summary", str(caught.exception))

    def test_missing_manifest_is_none_not_an_error(self) -> None:
        with TemporaryDirectory() as tmp:
            self.assertIsNone(res.load_manifest(Path(tmp), SLUG))

    def test_valid_manifest_loads(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            _write_manifest(workspace, _povs("a", "b"))
            manifest = res.load_manifest(workspace, SLUG)
            self.assertEqual(manifest["residual_of"], FIX_COMMIT)
            self.assertEqual(len(manifest["povs"]), 2)


class ScoringVocabularyTests(unittest.TestCase):
    def test_blocked_is_credit_reproduced_is_neutral(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a", "b", "c", "d"))
            # blocked, blocked, reproduced, reproduced -> beat upstream on half.
            docker = _FakeDocker([1, 1, 0, 0])
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=docker,
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertEqual(summary["hardened_beyond_fix"], 2)
            self.assertEqual(summary["matches_official_fix"], 2)
            self.assertEqual(summary["score"], 0.5)
            self.assertFalse(summary["all_hardened"])

    def test_matching_upstream_everywhere_scores_zero_not_an_error(self) -> None:
        """The common, acceptable case: patch is exactly as good as upstream."""
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a", "b"))
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([0, 0]),
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertEqual(summary["score"], 0.0)
            self.assertEqual(summary["hardened_beyond_fix"], 0)
            self.assertEqual(summary["errored"], 0)

    def test_all_hardened_requires_every_pov_to_have_run(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a", "b"))
            # One blocked, one timing out -> not "beat upstream everywhere".
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([1, res.DEFAULT_ERROR_EXIT_CODE]),
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertEqual(summary["hardened_beyond_fix"], 1)
            self.assertEqual(summary["errored"], 1)
            self.assertFalse(summary["all_hardened"])
            # Score ranges over conclusive results only.
            self.assertEqual(summary["score"], 1.0)

    def test_summary_does_not_leak_fix_pov_vocabulary(self) -> None:
        """``all_blocked`` here would read as a coverage gate. It must be gone."""
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a"))
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([0]),
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertNotIn("all_blocked", summary)
            self.assertIn("all_hardened", summary)
            self.assertEqual(summary["residual_of"], FIX_COMMIT)

    def test_gap_summary_is_carried_into_results(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a"))
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([0]),
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertEqual(summary["povs"][0]["gap_summary"], "official fix does not close a")


class StagingIsolationTests(unittest.TestCase):
    def test_stages_into_its_own_directory(self) -> None:
        """Must not collide with the fixPOV stage dir in the same checkout."""
        self.assertNotEqual(res.RESPOV_STAGE_PARTS, gt.FIX_POV_STAGE_PARTS)
        with TemporaryDirectory() as tmp:
            checkout = Path(tmp) / "checkout"
            self.assertNotEqual(
                gt.stage_dir_for(checkout, res.RESPOV_STAGE_PARTS),
                gt.stage_dir_for(checkout),
            )

    def test_staged_files_are_removed_after_evaluation(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            checkout = Path(tmp) / "checkout"
            manifest = _write_manifest(workspace, _povs("a"))
            res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([0]),
                checkout_path=checkout,
                timeout_seconds=None,
            )
            self.assertFalse(gt.stage_dir_for(checkout, res.RESPOV_STAGE_PARTS).exists())


class CertificationEnforcementTests(unittest.TestCase):
    def test_uncertified_pov_is_errored_not_scored(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            manifest = _write_manifest(workspace, _povs("a", certified=False))
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace, SLUG),
                docker=_FakeDocker([]),
                checkout_path=Path(tmp) / "checkout",
                timeout_seconds=None,
            )
            self.assertEqual(summary["errored"], 1)
            self.assertIsNone(summary["score"])
            self.assertIn("not certified", summary["povs"][0]["reason"])

    def test_edited_pov_loses_its_certification(self) -> None:
        with TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            res_dir = res.project_dir(workspace, SLUG)
            manifest = _write_manifest(workspace, _povs("a"))
            pov = manifest["povs"][0]
            pov["validation"]["content_hash"] = res.content_fingerprint(res_dir, manifest, pov)
            self.assertTrue(res.certification_state(res_dir, manifest, pov)["eligible"])

            (res_dir / "povs" / "run.sh").write_text("#!/usr/bin/env bash\nexit 1\n")
            state = res.certification_state(res_dir, manifest, pov)
            self.assertFalse(state["eligible"])
            self.assertIn("content changed", state["reason"])


class ProfileWiringTests(unittest.TestCase):
    def test_stage_registered_and_last_in_every_profile(self) -> None:
        self.assertIn("residual_eval", STAGE_REGISTRY)
        self.assertIs(STAGE_REGISTRY["residual_eval"], ResidualEvalStage)
        for name in PROFILES:
            self.assertEqual(resolve_experiment(profile=name).stages[-1], "residual_eval", name)

    def test_is_droppable_as_evaluation_only(self) -> None:
        self.assertIn("residual_eval", EVALUATION_ONLY_STAGES)
        base = resolve_experiment(profile="full")
        trimmed = [s for s in base.stages if s != "residual_eval"]
        exp = resolve_experiment(profile="full", stages=trimmed)
        self.assertNotIn("residual_eval", exp.stages)
        # Dropping it must not disturb the fixPOV stage beside it.
        self.assertEqual(exp.stages[-1], "fix_pov_eval")


class ReplayRecordingTests(unittest.TestCase):
    """`respov replay` refreshes a run's residual artifacts + state, in residual
    vocabulary, without disturbing its verdict or its fixPOV results."""

    def test_records_residual_results_and_state_step(self) -> None:
        with TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            state = {
                "status": "accepted",
                "steps": [
                    {"name": "verifier", "status": "ok"},
                    {"name": "residual_eval", "status": "skipped"},
                    {"name": "fix_pov_eval", "status": "ok"},
                ],
                "commands": [
                    {"name": "regression_1", "exit_code": 0},
                    {"name": "respov_old", "exit_code": 0},
                    {"name": "fixpov_keep", "exit_code": 1},
                ],
            }
            (run_dir / "state.json").write_text(json.dumps(state))
            (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))

            summary = res.summarize(
                {"project_slug": SLUG, "residual_of": FIX_COMMIT},
                [
                    {
                        "id": "gap_a",
                        "outcome": res.BLOCKED,
                        "gap_summary": "official fix leaves gap_a open",
                        "command_result": {"name": "respov_gap_a", "exit_code": 1},
                    }
                ],
            )
            summary["evaluation_mode"] = "reconstructed"

            self.assertTrue(_record_replayed_eval(run_dir, summary, _residual_family()))

            saved_state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(saved_state["status"], "accepted")
            # Stale respov_ command purged; the fixPOV command and other
            # families' commands are left untouched.
            self.assertEqual(
                [c["name"] for c in saved_state["commands"]],
                ["regression_1", "fixpov_keep", "respov_gap_a"],
            )
            eval_steps = [s for s in saved_state["steps"] if s["name"] == "residual_eval"]
            self.assertEqual(len(eval_steps), 1)
            step = eval_steps[0]
            self.assertTrue(step["replayed"])
            self.assertEqual(step["evaluation_mode"], "reconstructed")
            # Residual vocabulary in the step, not fixPOV vocabulary.
            self.assertEqual(step["hardened_beyond_fix"], 1)
            self.assertIn("matches_official_fix", step)
            self.assertNotIn("blocked", step)
            self.assertNotIn("all_blocked", step)
            # The fixPOV step is left in place.
            self.assertTrue(
                any(s["name"] == "fix_pov_eval" for s in saved_state["steps"])
            )
            saved = json.loads((run_dir / "residual/results.json").read_text())
            self.assertEqual(saved["evaluation_mode"], "reconstructed")
            self.assertEqual(saved["hardened_beyond_fix"], 1)
            # De-identified like every other run artifact.
            self.assertNotIn("project_slug", saved)

    def test_residual_and_fix_pov_results_live_in_separate_subdirs(self) -> None:
        family = _residual_family()
        self.assertEqual(family.results_subdir, "residual")
        self.assertEqual(family.replay_dirname, ".respov_replay")
        self.assertEqual(family.command_prefix, "respov")
        self.assertEqual(family.step_name, "residual_eval")


if __name__ == "__main__":
    unittest.main()
