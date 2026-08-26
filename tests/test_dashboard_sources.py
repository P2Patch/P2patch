"""Clone-status reporting for project sources.

The behaviour under test is narrow but was a real dead end in the UI: a slug
whose clone failed, and which was then populated some other way, must stop
reporting an error. Nothing else could clear it — `start_clone` short-circuits
on an already-present source, so the button was inert, and only a backend
restart dropped the in-memory record.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import sources  # noqa: E402

SLUG = "owner__repo_CVE-2099-0001_1.0"


class CloneStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._patches = [
            patch.object(sources, "SOURCES_DIR", root / "project-sources"),
            patch.object(sources, "CLONE_LOG_DIR", root / "clones"),
            patch.object(sources, "_JOBS", {}),
            patch.object(sources, "is_clonable", lambda slug: True),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(self._tmp.cleanup)
        for p in self._patches:
            self.addCleanup(p.stop)

    def _present(self) -> None:
        (sources.SOURCES_DIR / SLUG).mkdir(parents=True, exist_ok=True)

    def _job(self, state: str) -> None:
        job = sources.CloneJob(SLUG)
        job.state = state
        job.error = "fetch exited 1" if state == "error" else None
        sources._JOBS[SLUG] = job

    def test_absent_with_no_job(self) -> None:
        self.assertEqual(sources.status(SLUG)["state"], "absent")

    def test_failed_job_is_reported_while_the_source_is_still_missing(self) -> None:
        self._job("error")
        result = sources.status(SLUG)
        self.assertEqual(result["state"], "error")
        self.assertFalse(result["present"])

    def test_a_source_populated_after_a_failed_clone_reports_done(self) -> None:
        # The regression: cloned out-of-band (a terminal fetch run, a fixed
        # repo URL) after the dashboard's own attempt failed. The tree on disk is
        # the ground truth and must outrank the stale record.
        self._job("error")
        self._present()
        result = sources.status(SLUG)
        self.assertEqual(result["state"], "done")
        self.assertTrue(result["present"])
        self.assertIsNone(result["error"])

    def test_an_in_flight_job_is_never_masked_by_a_present_directory(self) -> None:
        # A running clone creates its target directory as it works. Reporting
        # "done" the moment the directory appears would call a half-finished
        # clone complete.
        for state in ("queued", "cloning"):
            with self.subTest(state=state):
                self._job(state)
                self._present()
                self.assertEqual(sources.status(SLUG)["state"], state)


if __name__ == "__main__":
    unittest.main()
