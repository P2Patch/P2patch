from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import residual_replay as replay  # noqa: E402
import run_jobs  # noqa: E402
import app as dashboard_app  # noqa: E402

KIND = replay.RESPOV_REPLAY


class DashboardResidualReplayTests(unittest.TestCase):
    RUN_ID = "20260731_120000_finding-123456abcdef"
    SLUG = "owner__repo_CVE-2099-0001_1.0"

    def _fixture(self, root: Path, *, manifest: bool = True) -> Path:
        run_dir = root / "runs" / self.RUN_ID
        (run_dir / "worktree").mkdir(parents=True)
        if manifest:
            manifest_path = root / "benchmark" / "residual_povs" / self.SLUG / "manifest.json"
            manifest_path.parent.mkdir(parents=True)
            manifest_path.write_text(
                json.dumps({"project_slug": self.SLUG, "povs": [{}]}),
                encoding="utf-8",
            )
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
                return_value={"status": "accepted", "residual_eval": None},
            ),
        )

    def test_status_reports_replay_available_for_residual_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            with ExitStack() as stack:
                for patcher in self._patch_target(root, run_dir):
                    stack.enter_context(patcher)
                status = replay.status(self.RUN_ID)

            self.assertTrue(status["available"])
            self.assertTrue(status["has_manifest"])
            self.assertEqual(status["state"], "absent")
            self.assertEqual(status["project_slug"], self.SLUG)

    def test_status_explains_when_residual_manifest_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root, manifest=False)
            with ExitStack() as stack:
                for patcher in self._patch_target(root, run_dir):
                    stack.enter_context(patcher)
                status = replay.status(self.RUN_ID)

            self.assertFalse(status["available"])
            self.assertFalse(status["has_manifest"])
            self.assertIn("No curated residual POV manifest", status["unavailable_reason"])

    def test_command_runs_respov_replay_for_only_the_selected_run(self) -> None:
        availability = {"project_slug": self.SLUG}
        command = replay._command(self.RUN_ID, availability)

        self.assertEqual(command[1:5], ["-m", "security_pipeline", "respov", "replay"])
        self.assertIn(self.SLUG, command)
        self.assertEqual(command[command.index("--run") + 1], self.RUN_ID)

    def test_api_exposes_residual_replay_status_and_start(self) -> None:
        absent = {
            "run_id": self.RUN_ID,
            "project_slug": self.SLUG,
            "available": True,
            "state": "absent",
        }
        running = {**absent, "state": "running"}
        with patch.object(dashboard_app.residual_replay, "status", return_value=absent), patch.object(
            dashboard_app.residual_replay, "start", return_value=running
        ), patch.object(dashboard_app.live, "is_run_active", return_value=False):
            client = TestClient(dashboard_app.api)
            status_response = client.get(f"/runs/{self.RUN_ID}/residual-replay")
            start_response = client.post(f"/runs/{self.RUN_ID}/residual-replay")

        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["state"], "absent")
        self.assertEqual(start_response.status_code, 200)
        self.assertEqual(start_response.json()["state"], "running")

    def test_worker_accepts_fresh_inconclusive_residual_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = self._fixture(root)
            status_path = run_dir / "residual" / replay.STATUS_NAME
            run_jobs._write_json(
                status_path,
                {"state": "running", "job_id": "job-1", "started_at": "start"},
            )

            def completed(*args, **kwargs):
                result_path = run_dir / "residual" / "results.json"
                run_jobs._write_json(result_path, {"total": 1, "errored": 1})
                return SimpleNamespace(returncode=1)

            run_jobs._acquire(KIND, run_dir, "job-1")
            with patch.object(run_jobs.config, "REPO_ROOT", root), patch.object(
                run_jobs.subprocess, "run", side_effect=completed
            ):
                run_jobs._run_job(
                    KIND,
                    self.RUN_ID,
                    {"project_slug": self.SLUG},
                    run_dir,
                    "job-1",
                )

            record = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(record["state"], "done")
            self.assertEqual(record["returncode"], 1)
            self.assertIsNone(record["error"])


if __name__ == "__main__":
    unittest.main()
