"""The dashboard's retrofit button: eligibility, argv, and assess-only safety.

The background-job machinery itself (locking, dead-holder reclamation, status
tagging) is shared with the fixPOV replay and covered by
test_dashboard_fix_pov_replay against `run_jobs`. What is tested here is the
descriptor: which runs the button offers itself to, what command it launches, and
that a "would not pass" outcome is reported as a result rather than as a broken
job.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import retrofit_job  # noqa: E402
import run_jobs  # noqa: E402

KIND = retrofit_job.RETROFIT


class RetrofitJobTests(unittest.TestCase):
    RUN_ID = "20260731_120000_finding-123456abcdef"
    SLUG = "owner__repo_CVE-2099-0001_1.0"

    def _fixture(self, root: Path, *, stages, retrofit_gates=None) -> Path:
        run_dir = root / "runs" / self.RUN_ID
        run_dir.mkdir(parents=True)
        state = {"profile": "baseline", "status": "accepted", "stages": list(stages)}
        if retrofit_gates is not None:
            state["retrofit_gates"] = retrofit_gates
        (run_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
        return run_dir

    def _patches(self, root: Path, run_dir: Path, detail: dict):
        return (
            patch.object(retrofit_job.config, "REPO_ROOT", root),
            patch.object(retrofit_job.config, "RUNS_DIR", root / "runs"),
            patch.object(retrofit_job.config, "ALERTS_DIR", root / "alerts"),
            patch.object(retrofit_job.runs, "resolve_run_dir", return_value=run_dir),
            patch.object(retrofit_job.runs, "get_run", return_value=detail),
            patch.object(
                retrofit_job.groundtruth,
                "ground_truth_for_run",
                return_value={"project_slug": self.SLUG},
            ),
        )

    def _availability(self, root, run_dir, detail):
        from contextlib import ExitStack

        with ExitStack() as stack:
            for patcher in self._patches(root, run_dir, detail):
                stack.enter_context(patcher)
            return retrofit_job._availability(self.RUN_ID)

    def test_offered_for_an_accepted_run_without_a_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "docker_build", "patcher"])
            result = self._availability(root, run_dir, {"status": "accepted"})
            self.assertTrue(result["available"])
            self.assertEqual(result["gates"], ["verifier"])

    def test_not_offered_when_the_run_already_ran_the_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher", "verifier"])
            result = self._availability(root, run_dir, {"status": "accepted"})
            self.assertFalse(result["available"])
            self.assertIn("already ran the verifier", result["unavailable_reason"])

    def test_offered_again_when_a_previous_retrofit_errored(self) -> None:
        # Recording an errored gate adds its stage to the run. Without this the
        # button would go permanently dark after one failed attempt (an expired
        # agent session, a container error) — the exact case it is needed for.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(
                root,
                stages=["worktree", "patcher", "verifier"],
                retrofit_gates={"errored": ["verifier"]},
            )
            result = self._availability(
                root, run_dir,
                {"status": "accepted", "retrofit_gates": {"errored": ["verifier"]}},
            )
            self.assertTrue(result["available"])
            self.assertEqual(result["gates"], ["verifier"])

    def test_rejected_runs_are_not_offered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher"])
            result = self._availability(root, run_dir, {"status": "rejected"})
            self.assertFalse(result["available"])

    def test_command_targets_one_run_and_ignores_its_profile(self) -> None:
        # The user asked for this specific run; profile filtering could only
        # refuse it, so the job pins --profile any and one --run.
        argv = retrofit_job._command(self.RUN_ID, {"project_slug": self.SLUG, "gates": ["verifier"]})
        self.assertIn("retrofit", argv)
        self.assertEqual(argv[argv.index("--run") + 1], self.RUN_ID)
        self.assertEqual(argv[argv.index("--project") + 1], self.SLUG)
        self.assertEqual(argv[argv.index("--profile") + 1], "any")
        self.assertEqual(argv[argv.index("--gates") + 1], "verifier")
        self.assertNotIn("--force", argv)  # never silently overwrite a real gate

    def test_a_failing_gate_is_a_result_not_a_broken_job(self) -> None:
        # `retrofit` exits 1 when a gate fails or errors. "This patch would not
        # have cleared the verifier" is precisely what the button is for, so it
        # must reach the UI as `done`, not as a job error.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher"])
            status_path = run_dir / "gates" / retrofit_job.STATUS_NAME
            run_jobs._write_json(status_path, {"state": "running", "started_at": "s"})

            def completed(*args, **kwargs):
                run_jobs._write_json(
                    run_dir / "gates" / "results.json",
                    {"gates": {"verifier": {"status": "failed"}}},
                )
                return SimpleNamespace(returncode=1)

            run_jobs._acquire(KIND, run_dir, "job-1")
            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run", side_effect=completed
            ):
                run_jobs._run_job(KIND, self.RUN_ID, {"project_slug": self.SLUG}, run_dir, "job-1")

            record = json.loads(status_path.read_text())
            self.assertEqual(record["state"], "done")
            self.assertIsNone(record["error"])

    def test_a_command_that_writes_nothing_is_an_error(self) -> None:
        # Exit 0 without refreshing results.json means nothing was evaluated.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher"])
            status_path = run_dir / "gates" / retrofit_job.STATUS_NAME
            run_jobs._acquire(KIND, run_dir, "job-1")
            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run",
                side_effect=lambda *a, **k: SimpleNamespace(returncode=0),
            ):
                run_jobs._run_job(KIND, self.RUN_ID, {"project_slug": self.SLUG}, run_dir, "job-1")

            record = json.loads(status_path.read_text())
            self.assertEqual(record["state"], "error")

    def test_start_returns_without_deadlocking_on_the_real_executor(self) -> None:
        # `start` calls `_executor` while holding `_LOCK`. When both used the
        # same non-reentrant lock this deadlocked the request thread on the first
        # POST — the job sat at "running" forever with no worker and no log, and
        # the HTTP connection never closed. Every other test patches `_executor`
        # out, which is exactly why none of them caught it: this one must not.
        from contextlib import ExitStack
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher"])
            done = []
            with ExitStack() as stack:
                for patcher in self._patches(root, run_dir, {"status": "accepted"}):
                    stack.enter_context(patcher)
                # Let the real _executor run, but keep the worker itself inert.
                stack.enter_context(patch.object(run_jobs, "_run_job", lambda *a: done.append(a)))
                result = ThreadPoolExecutor(max_workers=1).submit(
                    retrofit_job.start, self.RUN_ID
                ).result(timeout=10)  # deadlock would time out here

            self.assertEqual(result["state"], "running")
            self.assertEqual(len(done), 1)

    def test_fixpov_and_retrofit_locks_do_not_collide(self) -> None:
        # The two jobs write into different subdirectories and hold independent
        # locks, so a replay must not block a retrofit of the same run.
        import fix_pov_replay

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, stages=["worktree", "patcher"])
            self.assertTrue(run_jobs._acquire(fix_pov_replay.FIXPOV_REPLAY, run_dir, "a"))
            self.assertTrue(run_jobs._acquire(KIND, run_dir, "b"))


if __name__ == "__main__":
    unittest.main()
