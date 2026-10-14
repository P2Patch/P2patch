from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_pipeline.regression_diff import (  # noqa: E402
    classify_regression_failure,
    parse_junit_reports,
)

_SUREFIRE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="com.example.FooTest" tests="4" failures="1" errors="1" skipped="1">
  <testcase name="testPass" classname="com.example.FooTest" time="0.1"/>
  <testcase name="testFail" classname="com.example.FooTest" time="0.1">
    <failure message="boom">stack</failure>
  </testcase>
  <testcase name="testError" classname="com.example.FooTest" time="0.1">
    <error message="kaboom">stack</error>
  </testcase>
  <testcase name="testSkip" classname="com.example.FooTest" time="0.0">
    <skipped/>
  </testcase>
</testsuite>
"""


class ParseJUnitTests(unittest.TestCase):
    def test_parses_pass_fail_error_skip_from_nested_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "target" / "surefire-reports"
            reports.mkdir(parents=True)
            (reports / "TEST-com.example.FooTest.xml").write_text(_SUREFIRE_XML)

            outcomes = parse_junit_reports(root)

        self.assertEqual(outcomes["com.example.FooTest#testPass"], "pass")
        self.assertEqual(outcomes["com.example.FooTest#testFail"], "fail")
        self.assertEqual(outcomes["com.example.FooTest#testError"], "fail")
        self.assertEqual(outcomes["com.example.FooTest#testSkip"], "skip")

    def test_missing_root_and_bad_xml_are_ignored(self) -> None:
        self.assertEqual(parse_junit_reports(Path("/does/not/exist")), {})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "TEST-broken.xml").write_text("<not-valid")
            self.assertEqual(parse_junit_reports(root), {})


class ClassifyRegressionTests(unittest.TestCase):
    def test_genuine_regression_when_baseline_passing_test_now_fails(self) -> None:
        verdict, tests, _ = classify_regression_failure(
            post_reports={"a#t": "fail", "b#t": "pass"},
            baseline_reports={"a#t": "pass", "b#t": "pass"},
            baseline_ok=True,
        )
        self.assertEqual(verdict, "genuine")
        self.assertEqual(tests, ["a#t"])

    def test_injected_pov_test_is_scaffold(self) -> None:
        # The PoV test only exists after the exploiter runs, so it is absent from
        # the baseline; a correct patch makes its "vuln-present" assertion fail.
        verdict, tests, _ = classify_regression_failure(
            post_reports={"spark.resource.PathTraversalPovTest#escapes": "fail", "proj#t": "pass"},
            baseline_reports={"proj#t": "pass"},
            baseline_ok=True,
        )
        self.assertEqual(verdict, "scaffold")
        self.assertEqual(tests, [])

    def test_root_only_permission_test_is_scaffold(self) -> None:
        # Fails identically on the baseline (container runs as root) -> not the patch.
        verdict, _, _ = classify_regression_failure(
            post_reports={"zt.FilePermissionsTest#testPreserveWriteFlag": "fail"},
            baseline_reports={"zt.FilePermissionsTest#testPreserveWriteFlag": "fail"},
            baseline_ok=True,
        )
        self.assertEqual(verdict, "scaffold")

    def test_invalid_command_failing_on_baseline_too_is_scaffold(self) -> None:
        # "No tests were executed" / unresolvable dep: no reports, baseline also fails.
        verdict, _, _ = classify_regression_failure(
            post_reports={}, baseline_reports={}, baseline_ok=False
        )
        self.assertEqual(verdict, "scaffold")

    def test_broken_compilation_with_clean_baseline_is_genuine(self) -> None:
        # Patched tree produced no reports and failed while the baseline built fine.
        verdict, _, _ = classify_regression_failure(
            post_reports={}, baseline_reports={}, baseline_ok=True
        )
        self.assertEqual(verdict, "genuine")

    def test_genuine_wins_even_when_mixed_with_scaffold_failures(self) -> None:
        verdict, tests, _ = classify_regression_failure(
            post_reports={"real#t": "fail", "perm#t": "fail"},
            baseline_reports={"real#t": "pass", "perm#t": "fail"},
            baseline_ok=True,
        )
        self.assertEqual(verdict, "genuine")
        self.assertEqual(tests, ["real#t"])


if __name__ == "__main__":
    unittest.main()


# --------------------------------------------------------------------------- #
# The gate itself. The classifier above is only useful if the production
# regression predicate actually calls it, which for a while it did not.
# --------------------------------------------------------------------------- #

import json  # noqa: E402
import subprocess  # noqa: E402

from security_pipeline.models import (  # noqa: E402
    CommandResult,
    ExperimentConfig,
    PipelineState,
    ProjectMetadata,
    RunOptions,
)
from security_pipeline.stages import StageContext, regressions_pass_predicate  # noqa: E402


def _suite(name: str, cases: dict) -> str:
    body = "".join(
        f'<testcase name="{case}" classname="{name}"/>'
        if outcome == "pass"
        else f'<testcase name="{case}" classname="{name}"><failure message="x">s</failure></testcase>'
        for case, outcome in cases.items()
    )
    return f'<?xml version="1.0" encoding="UTF-8"?><testsuite name="{name}">{body}</testsuite>'


class _ScriptedDocker:
    """Writes the JUnit reports a command would produce, then returns its exit code.

    ``script`` maps a checkout role ("patched"/"baseline") to (exit_code, reports).
    """

    def __init__(self, checkout: Path, script: dict, role: str = "patched", calls=None):
        self.checkout = checkout
        self.script = script
        self.role = role
        self.calls = calls if calls is not None else []

    def for_checkout(self, checkout: Path) -> "_ScriptedDocker":
        return _ScriptedDocker(checkout, self.script, "baseline", self.calls)

    def run_project_command(self, command: str, name: str, timeout, env_overrides=None):
        self.calls.append(name)
        exit_code, reports = self.script[self.role]
        target = self.checkout / "target" / "surefire-reports"
        target.mkdir(parents=True, exist_ok=True)
        for suite, cases in reports.items():
            (target / f"TEST-{suite}.xml").write_text(_suite(suite, cases), encoding="utf-8")
        return CommandResult(
            name=name, command=[command], exit_code=exit_code, stdout="", stderr=""
        )


class RegressionGateTests(unittest.TestCase):
    """A failing command is a rejection only when a baseline-passing test broke."""

    def _ctx(self, tmp: str, script: dict, commit: bool = True) -> StageContext:
        root = Path(tmp)
        worktree = root / "worktree"
        (worktree / "src").mkdir(parents=True)
        (worktree / "src" / "Main.java").write_text("class Main {}", encoding="utf-8")
        if commit:
            for argv in (
                ["git", "init", "-q"],
                ["git", "add", "-A"],
                ["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                 "commit", "-q", "--no-gpg-sign", "-m", "baseline"],
            ):
                subprocess.run(argv, cwd=worktree, check=True, capture_output=True)

        project = ProjectMetadata(
            project_slug="owner__repo", cve_id="CVE-2099-0001", cwe_id="", cwe_name="",
            github_url="", github_tag="", buggy_commit_id="", fix_commit_ids="",
            source_path=worktree, dockerfile_path=worktree, build_system="maven",
            build_command="", test_command="mvn -B test",
        )
        ctx = StageContext(
            options=RunOptions(
                workspace_root=root, alerts_dir=root, runs_dir=root / "runs",
                command_timeout_seconds=10,
            ),
            experiment=ExperimentConfig(), agent_runner=None, alert={}, project=project,
            finding_id="finding-1", run_dir=root / "run", worktree_path=worktree,
            state=PipelineState(run_id="t", alert_path=Path("a")), persist=lambda: None,
        )
        (root / "run").mkdir(parents=True, exist_ok=True)
        ctx.docker = _ScriptedDocker(worktree, script)
        ctx.regression_commands = ["mvn -B test"]
        return ctx

    def test_failure_that_also_fails_on_the_baseline_is_not_a_regression(self) -> None:
        # A pre-existing/flaky/root-only failure: identical on both trees.
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp, {
                "patched": (1, {"com.example.FooTest": {"testA": "fail"}}),
                "baseline": (1, {"com.example.FooTest": {"testA": "fail"}}),
            })
            result = regressions_pass_predicate().check(ctx)
            self.assertTrue(result.passed)
            self.assertIn("pre-existing", result.summary)
            triage = [s for s in ctx.state.steps if s["name"] == "regression_triage"]
            self.assertEqual(triage[0]["status"], "scaffold")

    def test_injected_pov_test_failing_is_not_a_regression(self) -> None:
        # The PoV compiled into the project's test tree fails *because* the patch
        # works; it does not exist on the baseline, which runs clean.
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp, {
                "patched": (1, {
                    "com.example.FooTest": {"testA": "pass"},
                    "com.example.PovTest": {"testExploit": "fail"},
                }),
                "baseline": (0, {"com.example.FooTest": {"testA": "pass"}}),
            })
            result = regressions_pass_predicate().check(ctx)
            self.assertTrue(result.passed)
            self.assertIn("injected-PoV", result.summary)

    def test_a_test_that_passed_before_and_fails_after_is_a_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp, {
                "patched": (1, {"com.example.FooTest": {"testA": "fail"}}),
                "baseline": (0, {"com.example.FooTest": {"testA": "pass"}}),
            })
            result = regressions_pass_predicate().check(ctx)
            self.assertFalse(result.passed)
            self.assertIn("passed on the pristine baseline", result.summary)
            triage = [s for s in ctx.state.steps if s["name"] == "regression_triage"]
            self.assertEqual(triage[0]["status"], "genuine")
            self.assertEqual(triage[0]["regressed_tests"], ["com.example.FooTest#testA"])

    def test_passing_commands_never_build_a_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp, {
                "patched": (0, {"com.example.FooTest": {"testA": "pass"}}),
                "baseline": (0, {}),
            })
            result = regressions_pass_predicate().check(ctx)
            self.assertTrue(result.passed)
            self.assertEqual(ctx.docker.calls, ["regression_1"])
            self.assertIsNone(ctx.baseline_checkout_path)

    def test_without_a_baseline_export_the_failure_stands(self) -> None:
        # No git repo to export from -> no comparison -> stay conservative.
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp, {
                "patched": (1, {"com.example.FooTest": {"testA": "fail"}}),
                "baseline": (0, {}),
            }, commit=False)
            result = regressions_pass_predicate().check(ctx)
            self.assertFalse(result.passed)
            self.assertIn("no pristine baseline checkout", result.summary)
