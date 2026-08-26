"""The gated baseline profile, the POV-less verifier, and the assess-only retrofit.

Two changes are under test here and they are easy to confuse. The *profile*
change makes new `baseline` runs face the regression gate and the verifier. The
*retrofit* brings runs recorded before that change up to the same standard —
without re-patching them, which is the property most of these tests defend.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_pipeline import retrofit
from security_pipeline.models import AgentResult, CommandResult, ProjectMetadata
from security_pipeline.stages import (
    PROFILES,
    StageError,
    assess_predicates,
    build_stages,
    regressions_pass_predicate,
    render_verifier_input,
    resolve_experiment,
)

from tests.test_security_pipeline import _FakeAgentRunner, _FakeDocker, _cmd, _stage_ctx


class _RetroDocker(_FakeDocker):
    """_FakeDocker plus the attribute build_base_context reads off a real one."""

    image_tag = "img:test"


def _verifier_agent(verdict: str = "accepted", **extra) -> AgentResult:
    output = {
        "verdict": verdict, "summary": "s", "diff_review": "d", "pov_result": "p",
        "regression_result": "r", "issues": [], "commands_run": [],
    }
    output.update(extra)
    return AgentResult(
        agent_name="verifier", parsed_output=output, raw_stdout="", raw_stderr="",
        exit_code=0, input_path=Path("i"), output_path=Path("o"),
        stdout_path=Path("so"), stderr_path=Path("se"),
    )


class BaselineProfileTests(unittest.TestCase):
    """`baseline` is now reviewed by the verifier; only the evidence differs from `full`."""

    def test_baseline_includes_the_verifier(self) -> None:
        self.assertIn("verifier", PROFILES["baseline"])

    def test_baseline_has_no_separate_regression_gate(self) -> None:
        # The regression stage exists to feed a broken test back to the patcher,
        # and this arm has no self-correction loop to feed. The verifier runs the
        # project's tests itself instead — see render_verifier_input's alert-only
        # instructions, which is where that responsibility is assigned.
        self.assertNotIn("regression", PROFILES["baseline"])

    def test_baseline_still_withholds_the_exploiter(self) -> None:
        # The study's independent variable is `patcher_evidence`. Adding gates must
        # not smuggle an exploiter (and therefore a POV) into the baseline arm.
        self.assertNotIn("exploiter", PROFILES["baseline"])
        experiment = resolve_experiment(profile="baseline")
        self.assertEqual(experiment.patcher_evidence, "alert_only")

    def test_baseline_recipe_resolves_and_builds(self) -> None:
        # The dependency check must accept a verifier with no POV upstream of it.
        experiment = resolve_experiment(profile="baseline")
        names = [stage.name for stage in build_stages(experiment)]
        self.assertEqual(names, list(PROFILES["baseline"]))

    def test_full_evidence_still_requires_an_exploiter(self) -> None:
        # Relaxing VerifierStage.requires must not let a "full evidence" recipe
        # through without the exploiter that produces the evidence.
        with self.assertRaises(Exception):
            resolve_experiment(
                stages=["worktree", "docker_build", "patcher", "verifier"],
                patcher_evidence="full",
            )


class VerifierEvidenceModeTests(unittest.TestCase):
    """The verifier's task input adapts to whether a POV exists."""

    def _render(self, pov_before, pov_after):
        return render_verifier_input(
            {"run_dir": "/runs/r1"}, None, {"status": "patched"},
            pov_before, pov_after, [_cmd(0, ["mvn", "test"])],
        )

    def test_pov_mode_carries_the_pov_evidence(self) -> None:
        text = self._render(_cmd(0), _cmd(1))
        payload = json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])
        self.assertEqual(payload["evidence_mode"], "pov")
        self.assertIn("pov_before_patch", payload["orchestrator_results"])
        self.assertIn("pov_after_patch", payload["orchestrator_results"])
        self.assertIn("pov_diff", payload["diff_paths"])

    def test_alert_only_mode_omits_pov_keys_entirely(self) -> None:
        # Nulls would be read as evidence: a verifier handed a POV-shaped hole
        # reports "the POV could not be confirmed blocked" and rejects a patch it
        # was never given the means to check. The keys must be absent.
        text = self._render(None, None)
        payload = json.loads(text.split("```json\n", 1)[1].split("\n```", 1)[0])
        self.assertEqual(payload["evidence_mode"], "alert_only")
        self.assertNotIn("pov_before_patch", payload["orchestrator_results"])
        self.assertNotIn("pov_after_patch", payload["orchestrator_results"])
        self.assertNotIn("pov_diff", payload["diff_paths"])
        self.assertIn("regressions", payload["orchestrator_results"])

    def test_alert_only_instructions_forbid_rejecting_on_the_missing_pov(self) -> None:
        text = self._render(None, None)
        self.assertIn("no exploiter ran", text)
        self.assertIn("do not reject on that", text)

    def test_alert_only_instructions_hand_the_verifier_the_test_run(self) -> None:
        # `baseline` has no regression stage, so if this instruction goes missing
        # nothing checks that the patch left the project building.
        text = self._render(None, None)
        self.assertIn("Run the project's tests yourself", text)
        self.assertIn("regression_commands", text)
        self.assertIn("clean", text)  # and the no-clean rule rides along


class AssessPredicatesTests(unittest.TestCase):
    """The read-only half of the correction loop: check once, never re-patch."""

    def test_returns_the_first_failure_without_invoking_the_patcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # The project's own default build command ("mvn package") is always
            # appended as a mandatory regression check (see _ensure_build_checked),
            # so a queued result is needed for it too.
            docker = _RetroDocker([_cmd(1, ["mvn", "test"]), _cmd(0, ["mvn", "package"])])
            agents = _FakeAgentRunner([])
            ctx = _stage_ctx(tmp, docker, agents)
            ctx.patcher_output = {"status": "patched"}
            ctx.regression_commands = ["mvn test"]
            # No baseline checkout available -> a failure is treated as genuine.
            with mock.patch("security_pipeline.stages.baseline_checkout", return_value=None):
                failure = assess_predicates(ctx, [regressions_pass_predicate()])

            self.assertIsNotNone(failure)
            self.assertEqual(agents.calls, [])          # the patcher was never called
            self.assertEqual(len(ctx.state.commands), 2)  # both commands were recorded

    def test_returns_none_when_every_predicate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            docker = _RetroDocker([_cmd(0, ["mvn", "test"]), _cmd(0, ["mvn", "package"])])
            ctx = _stage_ctx(tmp, docker, _FakeAgentRunner([]))
            ctx.patcher_output = {"status": "patched"}
            ctx.regression_commands = ["mvn test"]
            self.assertIsNone(assess_predicates(ctx, [regressions_pass_predicate()]))


class RetrofitRunTests(unittest.TestCase):
    """Assessing a finished run's patch against gates it never faced."""

    def _run_dir(self, tmp: Path, *, regression_commands=("mvn test",), profile="baseline"):
        run_dir = tmp / "run1"
        run_dir.mkdir(parents=True)
        state = {
            "run_id": "run1", "profile": profile, "status": "accepted",
            "stages": ["worktree", "docker_build", "patcher"],
            "steps": [{"name": "patcher", "status": "ok"}],
            "commands": [{"name": "docker_build", "exit_code": 0}],
            "agents": [{
                "agent_name": "patcher",
                "parsed_output": {
                    "status": "patched",
                    "regression_commands": list(regression_commands),
                },
            }],
        }
        (run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        (run_dir / "verdict.json").write_text(json.dumps({
            "run_id": "run1", "profile": profile, "status": "accepted",
            "reason": "original reason",
            "stages": ["worktree", "docker_build", "patcher"],
        }), encoding="utf-8")
        return run_dir

    def _assess(self, tmp, run_dir, docker, agents, gates=("regression", "verifier")):
        ctx_holder = _stage_ctx(str(tmp / "wt"), docker, agents)
        return retrofit.retrofit_run(
            run_dir=run_dir,
            project=ctx_holder.project,
            alert={"name": "a"},
            finding_id="finding-1",
            checkout_path=ctx_holder.worktree_path,
            baseline_checkout_path=None,
            docker=docker,
            options=ctx_holder.options,
            agent_runner=agents,
            gates=gates,
        )

    def test_passing_gates_are_reported_as_passed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run_dir = self._run_dir(tmp)
            # Plus the mandatory project-build-command check (see _ensure_build_checked).
            docker = _RetroDocker([_cmd(0, ["mvn", "test"]), _cmd(0, ["mvn", "package"])])
            agents = _FakeAgentRunner([_verifier_agent("accepted")])
            summary = self._assess(tmp, run_dir, docker, agents)

            self.assertEqual(summary["gates_passed"], ["regression", "verifier"])
            self.assertEqual(summary["gates_failed"], [])
            self.assertTrue(summary["all_gates_passed"])

    def test_a_rejecting_verifier_is_recorded_not_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run_dir = self._run_dir(tmp)
            docker = _RetroDocker([_cmd(0, ["mvn", "test"]), _cmd(0, ["mvn", "package"])])
            agents = _FakeAgentRunner([_verifier_agent("rejected")])
            summary = self._assess(tmp, run_dir, docker, agents)

            self.assertEqual(summary["gates_failed"], ["verifier"])
            self.assertFalse(summary["all_gates_passed"])
            self.assertEqual(summary["gates"]["verifier"]["verdict"], "rejected")

            # The run's own verdict is untouched: it was reached under the gates
            # that existed when it ran, and this is a measurement, not a retrial.
            retrofit.record_retrofit(run_dir, summary, ("regression", "verifier"))
            verdict = json.loads((run_dir / "verdict.json").read_text())
            self.assertEqual(verdict["status"], "accepted")
            self.assertEqual(verdict["reason"], "original reason")
            self.assertEqual(verdict["retrofit_gates"]["gates_failed"], ["verifier"])

    def test_a_failing_regression_never_re_invokes_the_patcher(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run_dir = self._run_dir(tmp)
            docker = _RetroDocker([_cmd(1, ["mvn", "test"]), _cmd(0, ["mvn", "package"])])
            agents = _FakeAgentRunner([_verifier_agent("accepted")])
            with mock.patch("security_pipeline.stages.baseline_checkout", return_value=None):
                summary = self._assess(tmp, run_dir, docker, agents)

            self.assertEqual(summary["gates_failed"], ["regression"])
            # Only the verifier ran as an agent; no patcher_correction_* anywhere.
            self.assertEqual(agents.calls, ["verifier"])

    def test_missing_regression_commands_error_rather_than_fail_the_patch(self) -> None:
        # No recorded commands and no project default is a gap in the *artifact*,
        # not a defect in the patch, so it must not be scored as a gate failure.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run_dir = self._run_dir(tmp, regression_commands=())
            docker = _RetroDocker([])
            agents = _FakeAgentRunner([])
            ctx_holder = _stage_ctx(str(tmp / "wt"), docker, agents)
            ctx_holder.project = ProjectMetadata(
                project_slug="s", cve_id="", cwe_id="", cwe_name="", github_url="",
                github_tag="", buggy_commit_id="", fix_commit_ids="",
                source_path=tmp, dockerfile_path=tmp, build_system="maven",
                build_command="mvn package", test_command="",  # no default either
            )
            summary = retrofit.retrofit_run(
                run_dir=run_dir, project=ctx_holder.project, alert={},
                finding_id="f", checkout_path=ctx_holder.worktree_path,
                baseline_checkout_path=None, docker=docker,
                options=ctx_holder.options, agent_runner=agents, gates=("regression",),
            )
            self.assertEqual(summary["gates_errored"], ["regression"])
            self.assertEqual(summary["gates_failed"], [])
            self.assertFalse(summary["all_gates_passed"])

    def test_run_with_no_patcher_output_is_rejected_up_front(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            run_dir = tmp / "run1"
            run_dir.mkdir()
            (run_dir / "state.json").write_text(json.dumps({"agents": []}), encoding="utf-8")
            with self.assertRaises(retrofit.RetrofitError):
                retrofit.patcher_output_from_state(
                    retrofit.read_state(run_dir)
                )

    def test_last_patcher_wins_so_a_corrected_run_is_assessed_on_its_final_patch(self) -> None:
        state = {"agents": [
            {"agent_name": "patcher", "parsed_output": {"regression_commands": ["first"]}},
            {"agent_name": "patcher_correction_a2", "parsed_output": {"regression_commands": ["last"]}},
        ]}
        output = retrofit.patcher_output_from_state(state)
        self.assertEqual(output["regression_commands"], ["last"])


class RecordRetrofitTests(unittest.TestCase):
    """Merging an assessment into a run's artifacts."""

    def _run_dir(self, tmp: Path, state: dict) -> Path:
        run_dir = tmp / "run1"
        run_dir.mkdir(parents=True)
        (run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        (run_dir / "verdict.json").write_text(
            json.dumps({"profile": "baseline", "status": "accepted",
                        "stages": ["worktree", "docker_build", "patcher"]}),
            encoding="utf-8",
        )
        return run_dir

    def _summary(self, **over) -> dict:
        summary = {
            "run_id": "run1", "gates": {}, "gates_passed": ["regression", "verifier"],
            "gates_failed": [], "gates_errored": [], "all_gates_passed": True,
            "steps": [{"name": "patch_and_regression", "status": "ok"},
                      {"name": "verifier", "status": "accepted"}],
            "commands": [{"name": "regression_1", "exit_code": 0}],
            "agents": [{"agent_name": "verifier", "parsed_output": {"verdict": "accepted"}}],
        }
        summary.update(over)
        return summary

    def test_stages_gain_the_replayed_gates_in_profile_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp), {
                "profile": "baseline", "stages": ["worktree", "docker_build", "patcher"],
                "steps": [], "commands": [], "agents": [],
            })
            retrofit.record_retrofit(run_dir, self._summary(), ("verifier",))
            state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(
                state["stages"],
                ["worktree", "docker_build", "patcher", "verifier"],
            )
            # The rail is driven off this list, so the gate now shows up.
            self.assertEqual([s["name"] for s in state["steps"]],
                             ["patch_and_regression", "verifier"])

    def test_a_gate_outside_the_profile_sorts_after_its_declared_stages(self) -> None:
        # `regression` is no longer a baseline stage but stays replayable via
        # --gates. It must still land in the list rather than be dropped.
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp), {
                "profile": "baseline", "stages": ["worktree", "docker_build", "patcher"],
                "steps": [], "commands": [], "agents": [],
            })
            retrofit.record_retrofit(run_dir, self._summary(), ("regression",))
            state = json.loads((run_dir / "state.json").read_text())
            self.assertIn("regression", state["stages"])
            self.assertEqual(state["stages"][-1], "regression")

    def test_rerunning_a_retrofit_replaces_rather_than_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp), {
                "profile": "baseline", "stages": ["worktree", "patcher"],
                "steps": [], "commands": [], "agents": [],
            })
            retrofit.record_retrofit(run_dir, self._summary(), ("regression", "verifier"))
            retrofit.record_retrofit(run_dir, self._summary(), ("regression", "verifier"))
            state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(len(state["commands"]), 1)
            self.assertEqual(len(state["agents"]), 1)
            self.assertEqual(len(state["steps"]), 2)

    def test_a_runs_own_verifier_record_is_never_purged(self) -> None:
        # The purge keys ("verifier", "regression_") are not unique to the
        # retrofit. Applied to a run that genuinely ran those gates it would
        # delete the artifacts that run is judged on, so it is gated on a prior
        # retrofit having been recorded.
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp), {
                "profile": "full", "stages": ["worktree", "patcher", "verifier"],
                "steps": [{"name": "verifier", "status": "accepted"}],
                "commands": [{"name": "regression_1", "exit_code": 0}],
                "agents": [{"agent_name": "verifier", "parsed_output": {"verdict": "accepted"}}],
            })
            retrofit.record_retrofit(run_dir, self._summary(
                steps=[], commands=[], agents=[],
            ), ("regression",))
            state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual(len(state["agents"]), 1)
            self.assertEqual(state["steps"][0]["name"], "verifier")
            self.assertEqual(state["commands"][0]["name"], "regression_1")

    def test_results_artifact_is_written_even_when_state_is_unreadable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run1"
            run_dir.mkdir()
            (run_dir / "state.json").write_text("{ not json", encoding="utf-8")
            headline = retrofit.record_retrofit(run_dir, self._summary(), ("regression",))
            self.assertFalse(headline["state_updated"])
            self.assertTrue((run_dir / retrofit.RESULTS_SUBDIR / "results.json").is_file())

    def test_a_partial_retrofit_keeps_the_earlier_gates_result(self) -> None:
        # The bug this defends: retrying only the verifier (because the first
        # attempt errored on it) used to overwrite the whole record, so the
        # regression pass alongside it silently vanished from the headline.
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(Path(tmp), {
                "profile": "baseline", "stages": ["worktree", "patcher"],
                "steps": [], "commands": [], "agents": [],
            })
            retrofit.record_retrofit(run_dir, self._summary(
                gates={"regression": {"status": "passed"},
                       "verifier": {"status": "errored"}},
                gates_passed=["regression"], gates_errored=["verifier"],
                all_gates_passed=False,
            ), ("regression", "verifier"))

            # Second pass replays only the verifier, and it succeeds this time.
            headline = retrofit.record_retrofit(run_dir, self._summary(
                gates={"verifier": {"status": "passed"}},
                gates_passed=["verifier"], gates_errored=[],
                steps=[{"name": "verifier", "status": "accepted"}], commands=[],
                agents=[{"agent_name": "verifier", "parsed_output": {"verdict": "accepted"}}],
            ), ("verifier",))

            self.assertEqual(headline["gates_passed"], ["regression", "verifier"])
            self.assertEqual(headline["gates_errored"], [])
            self.assertTrue(headline["all_gates_passed"])
            # The regression command from the first pass survived the second.
            state = json.loads((run_dir / "state.json").read_text())
            self.assertEqual([c["name"] for c in state["commands"]], ["regression_1"])
            self.assertEqual(len(state["agents"]), 1)


class TargetSelectionTests(unittest.TestCase):
    """Which finished runs are eligible for a retrofit."""

    def _verdict(self, tmp: Path, **fields) -> Path:
        run_dir = tmp / "20260101_000000_finding-abc123456789"
        run_dir.mkdir(parents=True)
        payload = {"status": "accepted", "profile": "baseline",
                   "stages": ["worktree", "docker_build", "patcher"]}
        payload.update(fields)
        (run_dir / "verdict.json").write_text(json.dumps(payload), encoding="utf-8")
        return run_dir

    def _select(self, tmp, **over):
        from security_pipeline import cli

        project = ProjectMetadata(
            project_slug="s", cve_id="CVE-1", cwe_id="", cwe_name="", github_url="",
            github_tag="", buggy_commit_id="", fix_commit_ids="", source_path=tmp,
            dockerfile_path=tmp, build_system="maven", build_command="b", test_command="t",
        )
        alert = tmp / "a.json"
        alert.write_text("{}", encoding="utf-8")
        kwargs = dict(
            workspace_root=tmp, alerts_dir=tmp, runs_dir=tmp, project_slug=None,
            run_ids=None, profile="baseline", gates=("regression", "verifier"),
            include_rejected=False,
        )
        kwargs.update(over)
        with mock.patch("security_pipeline.metadata.all_alert_paths", return_value=[alert]), \
             mock.patch("security_pipeline.metadata.resolve_project_metadata", return_value=project), \
             mock.patch.object(cli, "make_finding_id", return_value="finding-abc123456789"):
            return cli._retrofit_targets(**kwargs)

    def test_a_gate_the_run_already_ran_is_not_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(tmp, stages=["worktree", "patcher", "verifier"])
            targets = self._select(tmp)
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].gates, ("regression",))  # verifier untouched

    def test_a_run_with_every_gate_already_present_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(tmp, stages=["worktree", "patcher", "regression", "verifier"])
            self.assertEqual(self._select(tmp), [])

    def test_a_gate_the_retrofit_errored_on_stays_eligible(self) -> None:
        # Recording an errored gate still adds its stage to the run. Without the
        # gates_errored subtraction that run could never be retried — it would
        # look permanently gated by an assessment that never happened.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(
                tmp,
                stages=["worktree", "patcher", "regression", "verifier"],
                retrofit_gates={"gates_errored": ["verifier"], "gates_passed": ["regression"]},
            )
            targets = self._select(tmp)
            self.assertEqual(len(targets), 1)
            self.assertEqual(targets[0].gates, ("verifier",))

    def test_force_re_assesses_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(tmp, stages=["worktree", "patcher", "regression", "verifier"])
            targets = self._select(tmp, force=True)
            self.assertEqual(targets[0].gates, ("regression", "verifier"))

    def test_other_profiles_are_left_alone_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(tmp, profile="hardening")
            self.assertEqual(self._select(tmp), [])
            self.assertEqual(len(self._select(tmp, profile="any")), 1)

    def test_rejected_runs_are_excluded_unless_asked_for(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            self._verdict(tmp, status="rejected")
            self.assertEqual(self._select(tmp), [])


class MergeStagesTests(unittest.TestCase):
    def test_unknown_profile_falls_back_to_append_order(self) -> None:
        self.assertEqual(
            retrofit.merge_stages(["a", "b"], ["verifier"], "not-a-profile"),
            ["a", "b", "verifier"],
        )

    def test_already_present_gates_are_not_duplicated(self) -> None:
        merged = retrofit.merge_stages(
            ["worktree", "patcher", "verifier"], ["verifier"], "baseline"
        )
        self.assertEqual(merged.count("verifier"), 1)


if __name__ == "__main__":
    unittest.main()
