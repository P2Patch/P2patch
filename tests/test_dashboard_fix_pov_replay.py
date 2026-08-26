from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


# The dashboard backend is a directly-run module tree rather than a package.
BACKEND_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import fix_pov_replay as replay  # noqa: E402
import run_jobs  # noqa: E402

# The background-job machinery (locking, status writes, the worker) is shared
# with the retrofit job and lives in run_jobs; `replay` is now the descriptor
# that points it at fixPOVs. These tests exercise the machinery
# through that descriptor, which is how the dashboard reaches it.
KIND = replay.FIXPOV_REPLAY


class DashboardFixPovReplayTests(unittest.TestCase):
    RUN_ID = "20260731_120000_finding-123456abcdef"
    SLUG = "owner__repo_CVE-2099-0001_1.0"

    def _fixture(self, root: Path) -> Path:
        run_dir = root / "runs" / self.RUN_ID
        (run_dir / "worktree").mkdir(parents=True)
        manifest = root / "benchmark" / "fix_povs" / self.SLUG / "manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({"project_slug": self.SLUG, "povs": [{}]}))
        return run_dir

    def _patch_target(self, root: Path, run_dir: Path):
        return (
            patch.object(run_jobs.config, "REPO_ROOT", root),
            patch.object(replay.config, "RUNS_DIR", root / "runs"),
            patch.object(replay.config, "ALERTS_DIR", root / "alerts"),
            patch.object(replay.runs, "resolve_run_dir", return_value=run_dir),
            patch.object(
                replay.groundtruth,
                "ground_truth_for_run",
                return_value={"project_slug": self.SLUG},
            ),
            patch.object(
                replay.runs,
                "get_run",
                return_value={"status": "accepted", "fix_pov_eval": None},
            ),
        )

    def test_status_reports_replay_available_for_accepted_preserved_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            patches = self._patch_target(root, run_dir)
            with ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                status = replay.status(self.RUN_ID)

            self.assertTrue(status["available"])
            self.assertTrue(status["has_manifest"])
            self.assertEqual(status["state"], "absent")
            self.assertEqual(status["project_slug"], self.SLUG)

    def test_start_is_nonblocking_and_idempotent_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            patches = self._patch_target(root, run_dir)
            executor = SimpleNamespace(submit=lambda *args: None)
            with ExitStack() as stack:
                for patcher in patches:
                    stack.enter_context(patcher)
                stack.enter_context(patch.object(run_jobs, "_executor", lambda kind: executor))
                first = replay.start(self.RUN_ID)
                second = replay.start(self.RUN_ID)
                # Ownership is a lock file, not process memory, so a second
                # request rejoins the running job even from another worker.
                self.assertTrue(replay.is_replay_active(self.RUN_ID))
                self.assertEqual(first["state"], "running")
                self.assertEqual(second["state"], "running")
                run_jobs._release(KIND, run_dir, "")

    def test_second_process_cannot_replay_the_same_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            self.assertTrue(run_jobs._acquire(KIND, run_dir, "job-a"))
            self.assertFalse(run_jobs._acquire(KIND, run_dir, "job-b"))
            run_jobs._release(KIND, run_dir, "job-a")
            self.assertTrue(run_jobs._acquire(KIND, run_dir, "job-b"))
            run_jobs._release(KIND, run_dir, "job-b")

    def test_lock_held_by_a_dead_process_is_reclaimed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            # A worker that was killed mid-replay must not block the run forever.
            run_jobs._write_json(
                run_jobs._lock_path(KIND, run_dir), {"pid": 2 ** 22, "job_id": "ghost", "at": "then"}
            )
            self.assertTrue(run_jobs._acquire(KIND, run_dir, "job-new"))
            run_jobs._release(KIND, run_dir, "job-new")

    def test_late_worker_does_not_overwrite_a_newer_jobs_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            status_path = run_dir / "fix_pov" / replay.STATUS_NAME
            run_jobs._acquire(KIND, run_dir, "job-new")
            run_jobs._write_json(status_path, {"state": "running", "job_id": "job-new"})

            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run", side_effect=lambda *a, **k: SimpleNamespace(returncode=0)
            ):
                run_jobs._run_job(KIND, self.RUN_ID, {"project_slug": self.SLUG}, run_dir, "job-old")

            self.assertEqual(json.loads(status_path.read_text())["state"], "running")

    def test_deleted_run_is_not_resurrected_by_a_finishing_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            run_jobs._acquire(KIND, run_dir, "job-a")
            shutil.rmtree(run_dir)  # deleted from the dashboard mid-replay

            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run", side_effect=lambda *a, **k: SimpleNamespace(returncode=0)
            ):
                run_jobs._run_job(KIND, self.RUN_ID, {"project_slug": self.SLUG}, run_dir, "job-a")

            self.assertFalse(run_dir.exists())

    def test_worker_marks_fresh_inconclusive_result_done(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            status_path = run_dir / "fix_pov" / replay.STATUS_NAME
            run_jobs._write_json(status_path, {"state": "running", "started_at": "start"})

            def completed(*args, **kwargs):
                result_path = run_dir / "fix_pov" / "results.json"
                run_jobs._write_json(result_path, {"total": 1, "errored": 1})
                return SimpleNamespace(returncode=1)

            run_jobs._acquire(KIND, run_dir, "job-1")
            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run", side_effect=completed
            ):
                run_jobs._run_job(KIND, self.RUN_ID, {"project_slug": self.SLUG}, run_dir, "job-1")

            record = json.loads(status_path.read_text())
            self.assertEqual(record["state"], "done")
            self.assertEqual(record["returncode"], 1)
            self.assertIsNone(record["error"])


if __name__ == "__main__":
    unittest.main()
