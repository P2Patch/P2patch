from __future__ import annotations

from io import BytesIO, StringIO
import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


# The dashboard backend is intentionally a small, directly-run module tree
# rather than a Python package.  Mirror uvicorn's import path for focused tests.
BACKEND_DIR = Path(__file__).resolve().parents[1] / "dashboard" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import live  # noqa: E402
import runs  # noqa: E402
import app as dashboard_app  # noqa: E402
from analysis import base as analysis_base  # noqa: E402
from analysis import exploit_eval, patch_eval  # noqa: E402


class DashboardHardeningTests(unittest.TestCase):
    @staticmethod
    def _agent_state(cost: float = 3.98) -> dict:
        raw = json.dumps(
            {
                "total_cost_usd": cost,
                "modelUsage": {
                    "deepseek/deepseek-v4-flash": {
                        "costUSD": cost,
                        "outputTokens": 10,
                    }
                },
                "usage": {"input_tokens": 20, "output_tokens": 10},
            }
        )
        return {
            "agents": [
                {
                    "agent_name": "patcher",
                    "raw_stdout": raw,
                    "exit_code": 0,
                    "parse_error": None,
                    "parsed_output": {"status": "patched"},
                }
            ]
        }

    def test_complete_provider_cost_overrides_claude_cli_estimate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            agent_dir = run_dir / "agent_io" / "patcher"
            agent_dir.mkdir(parents=True)
            (agent_dir / "provider_cost.json").write_text(
                json.dumps(
                    {
                        "provider": "openrouter",
                        "source": "openrouter_generation_api",
                        "complete": True,
                        "cost_usd": 0.13,
                    }
                ),
                encoding="utf-8",
            )

            agents = runs._agent_summaries(self._agent_state(), run_dir)
            self.assertEqual(agents[0]["meta"]["cost_usd"], 0.13)
            self.assertEqual(agents[0]["meta"]["estimated_cost_usd"], 3.98)
            self.assertEqual(
                agents[0]["meta"]["cost_source"],
                "openrouter_generation_api",
            )
            self.assertEqual(runs._totals(agents)["cost_usd"], 0.13)
            self.assertEqual(
                runs._totals(agents)["cost_source"],
                "openrouter_generation_api",
            )

    def test_incomplete_provider_cost_falls_back_to_claude_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            agent_dir = run_dir / "agent_io" / "patcher"
            agent_dir.mkdir(parents=True)
            (agent_dir / "provider_cost.json").write_text(
                json.dumps({"complete": False, "cost_usd": 0.01}),
                encoding="utf-8",
            )

            agents = runs._agent_summaries(self._agent_state(), run_dir)
            self.assertEqual(agents[0]["meta"]["cost_usd"], 3.98)
            self.assertEqual(agents[0]["meta"]["cost_source"], "claude_cli")
            self.assertIsNone(agents[0]["meta"]["estimated_cost_usd"])

    def test_export_endpoint_returns_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_id = "20260731_120000_finding-123456abcdef"
            (runs_dir / run_id).mkdir()
            (runs_dir / run_id / "state.json").write_text('{"status":"accepted"}', encoding="utf-8")

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                client = TestClient(dashboard_app.api)
                response = client.post("/runs/export", json={"run_ids": [run_id]})

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["content-type"], "application/zip")
            self.assertIn("p2patch-run-", response.headers["content-disposition"])
            with zipfile.ZipFile(BytesIO(response.content)) as archive:
                self.assertIn(f"{run_id}/state.json", archive.namelist())

    def test_run_exports_unpack_directly_into_runs_dir_without_symlinks(self) -> None:
        """An export is shareable and safe to extract under security_pipeline_runs/."""
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            first = "20260731_120000_finding-123456abcdef"
            second = "20260731_120001_finding-fedcba654321"
            (runs_dir / first / "agent_io" / "patcher").mkdir(parents=True)
            (runs_dir / first / "state.json").write_text('{"status":"accepted"}', encoding="utf-8")
            (runs_dir / first / "agent_io" / "patcher" / "output.json").write_text("patched", encoding="utf-8")
            (runs_dir / second).mkdir()
            external = runs_dir / "not-a-run-secret.txt"
            external.write_text("do not export", encoding="utf-8")
            (runs_dir / first / "external-link").symlink_to(external)

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                archive_path, filename = runs.export_runs([first, second, first])
                try:
                    self.assertEqual(filename, "p2patch-runs-selected.zip")
                    with zipfile.ZipFile(archive_path) as archive:
                        names = archive.namelist()
                        self.assertIn(f"{first}/state.json", names)
                        self.assertIn(f"{first}/agent_io/patcher/output.json", names)
                        self.assertIn(f"{second}/", names)
                        self.assertNotIn(f"{first}/external-link", names)
                        self.assertNotIn("not-a-run-secret.txt", names)
                finally:
                    runs.remove_export(archive_path)

    def test_export_never_follows_a_link_swapped_in_after_the_check(self) -> None:
        """The lstat check and the read must resolve the same object.

        ``zipfile.write()`` re-opens by path, so a file replaced by a symlink
        between the two — a live run still writing into its own directory — had
        the link followed and an arbitrary host file archived under the run's
        name. Simulated here by handing the writer a path that is already a link,
        which is what it would find after losing that race.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / "secret.txt"
            secret.write_text("host secret", encoding="utf-8")
            swapped = root / "state.json"
            swapped.symlink_to(secret)

            archive_path = root / "out.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                runs._archive_regular_file(archive, swapped, "run/state.json")
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.namelist(), [])

    def test_export_still_archives_a_real_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text('{"status":"accepted"}', encoding="utf-8")
            archive_path = Path(tmp) / "out.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                runs._archive_regular_file(archive, path, "run/state.json")
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.read("run/state.json").decode(), '{"status":"accepted"}'
                )

    def test_run_export_rejects_empty_and_unknown_selections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(runs.config, "RUNS_DIR", Path(tmp)):
            with self.assertRaisesRegex(runs.RunExportError, "select at least one"):
                runs.export_runs([])
            with self.assertRaisesRegex(runs.RunExportError, "run not found"):
                runs.export_runs(["../../outside"])

    def test_run_summary_includes_fix_pov_coverage_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_id = "20260731_120000_finding-123456abcdef"
            run_dir = runs_dir / run_id
            (run_dir / "fix_pov").mkdir(parents=True)
            (run_dir / "state.json").write_text(json.dumps({"status": "accepted", "agents": []}))
            (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))
            (run_dir / "fix_pov" / "results.json").write_text(json.dumps({"score": 0.75}))

            metadata = {
                "cve_id": "CVE-2099-0001",
                "cwe_id": "CWE-022",
                "project_slug": "owner__repo_CVE-2099-0001_1.0",
            }
            with patch.object(runs.config, "RUNS_DIR", runs_dir), patch.object(
                runs.groundtruth, "ground_truth_for_run", return_value=metadata
            ):
                summary = runs.list_runs()

            self.assertEqual(summary[0]["coverage_score"], 0.75)

    def test_run_summary_reads_legacy_ground_truth_results_dir(self) -> None:
        """Runs recorded before the fixPOV rename wrote ground_truth/results.json;
        they must keep their coverage score."""
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_id = "20260731_120000_finding-123456abcdef"
            run_dir = runs_dir / run_id
            (run_dir / "ground_truth").mkdir(parents=True)
            (run_dir / "state.json").write_text(json.dumps({"status": "accepted", "agents": []}))
            (run_dir / "verdict.json").write_text(json.dumps({"status": "accepted"}))
            (run_dir / "ground_truth" / "results.json").write_text(json.dumps({"score": 0.75}))

            metadata = {
                "cve_id": "CVE-2099-0001",
                "cwe_id": "CWE-022",
                "project_slug": "owner__repo_CVE-2099-0001_1.0",
            }
            with patch.object(runs.config, "RUNS_DIR", runs_dir), patch.object(
                runs.groundtruth, "ground_truth_for_run", return_value=metadata
            ):
                summary = runs.list_runs()

            self.assertEqual(summary[0]["coverage_score"], 0.75)

    def test_launcher_exposes_and_passes_round_limit(self) -> None:
        options = live.launch_options()
        hardening = next(p for p in options["profiles"] if p["value"] == "hardening")

        self.assertIn("harden", hardening["stages"])
        self.assertEqual(options["hardening_rounds"]["default"], 4)

        command = live._build_cmd(
            Path("alert.json"),
            {"profile": "hardening", "effort": "high", "max_rounds": 7},
        )
        self.assertEqual(command[command.index("--max-rounds") + 1], "7")

    def test_launcher_exposes_every_openrouter_model(self) -> None:
        from security_pipeline.openrouter import OPENROUTER_MODELS

        options = live.launch_options()["models"]
        for model_id in OPENROUTER_MODELS:
            with self.subTest(model=model_id):
                model = next(m for m in options if m["value"] == model_id)
                self.assertEqual(model["provider"], "openrouter")
                self.assertTrue(live.MODEL_RE.fullmatch(model_id))

                command = live._build_cmd(
                    Path("alert.json"),
                    {"profile": "full", "effort": "high", "model": model_id},
                )
                self.assertEqual(command[command.index("--model") + 1], model_id)

    def test_completed_rounds_fold_into_summary_and_passing_stage(self) -> None:
        state = {
            "profile": "hardening",
            "stages": ["harden"],
            "max_hardening_rounds": 4,
            "status": "accepted",
            "agents": [
                {"agent_name": "exploiter_harden_r1", "exit_code": 0, "parse_error": None, "parsed_output": {"status": "pov_created"}},
                {"agent_name": "patcher_harden_r1", "exit_code": 0, "parse_error": None, "parsed_output": {"status": "patched"}},
                {"agent_name": "exploiter_harden_r2", "exit_code": 0, "parse_error": None, "parsed_output": {"status": "no_pov"}},
            ],
            "commands": [
                {"name": "harden_variant_before_r1", "exit_code": 0, "timed_out": False},
                {"name": "harden_variant_after_r1", "exit_code": 1, "timed_out": False},
                {"name": "harden_original_recheck_r1", "exit_code": 1, "timed_out": False},
            ],
            "steps": [
                {"name": "harden", "status": "hardened", "round": 1},
                {"name": "harden", "status": "stable", "round": 2, "reason": "no new bypass"},
            ],
        }

        summary = runs._hardening_summary(state)
        self.assertEqual(summary["status"], "stable")
        self.assertEqual(summary["rounds_attempted"], 2)
        self.assertEqual(summary["rounds_hardened"], 1)

        stage = runs._stage_states(
            state,
            runs._agent_summaries(state),
            terminal=True,
            order=[("harden", "step", "Hardening loop")],
        )[0]
        self.assertEqual(stage["status"], "pass")

    def test_live_monitor_detects_labeled_round_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            agent_dir = run_dir / "agent_io" / "patcher_harden_r1"
            agent_dir.mkdir(parents=True)
            (agent_dir / "input.md").write_text("strengthen patch", encoding="utf-8")
            state = {
                "profile": "hardening",
                "stages": ["harden"],
                "steps": [{"name": "metadata", "status": "ok"}],
                "agents": [],
                "commands": [],
            }

            stages, running = live.live_stages(run_dir, state, terminal=False)

            self.assertEqual(running, "harden")
            harden = next(s for s in stages if s["key"] == "harden")
            self.assertIn("patcher_harden_r1", harden["detail"])

    def test_round_agent_artifacts_are_addressable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_id = "20260722_120000_finding-123456abcdef"
            agent_dir = runs_dir / run_id / "agent_io" / "exploiter_harden_r3"
            agent_dir.mkdir(parents=True)
            (agent_dir / "input.md").write_text("find bypass", encoding="utf-8")
            (agent_dir / "output.json").write_text('{"status":"no_pov"}', encoding="utf-8")

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                artifact = runs.get_agent_io(run_id, "exploiter_harden_r3")
                rejected = runs.get_agent_io(run_id, "../../state")

            self.assertEqual(artifact["output_json"]["status"], "no_pov")
            self.assertIsNone(rejected)


class DashboardRetryTests(unittest.TestCase):
    """Retry budgets reach the CLI, and retries are visible in the run payload."""

    def test_launcher_exposes_and_passes_retry_budgets(self) -> None:
        options = live.launch_options()
        self.assertEqual(options["correction_attempts"]["min"], 1)
        self.assertEqual(options["exploit_attempts"]["min"], 1)

        command = live._build_cmd(
            Path("alert.json"),
            {
                "profile": "hardening",
                "effort": "high",
                "max_rounds": 4,
                "max_correction_attempts": 5,
                "max_exploit_attempts": 2,
            },
        )
        self.assertEqual(command[command.index("--max-correction-attempts") + 1], "5")
        self.assertEqual(command[command.index("--max-exploit-attempts") + 1], "2")

    def test_out_of_range_budget_is_rejected(self) -> None:
        target = {"sources_present": True, "project_slug": "p"}
        with self.assertRaises(live.LaunchError):
            live._validate_options(target, "high", None, "full", False, 4, 0, 3)
        with self.assertRaises(live.LaunchError):
            live._validate_options(target, "high", None, "full", False, 4, 3, 99)

    def test_retry_summary_attributes_each_failure_to_its_gate(self) -> None:
        state = {
            "max_correction_attempts": 3,
            "max_exploit_attempts": 3,
            "steps": [
                {"name": "exploit_retry", "status": "retry", "attempt": 1,
                 "failing": "pov_did_not_reproduce", "detail": "exit 1"},
                {"name": "correction", "status": "retry", "stage": "pov_after", "attempt": 1,
                 "failing": "pov_no_longer_reproduces", "detail": "still reproduces"},
                {"name": "correction", "status": "converged", "stage": "pov_after", "attempt": 2},
            ],
        }

        summary = runs._retry_summary(state)

        self.assertEqual(summary["exploit_retries"][0]["agent"], "exploiter_retry_a2")
        correction = summary["patch_corrections"][0]
        self.assertEqual(correction["gate"], "pov_after")
        self.assertEqual(correction["agent"], "patcher_correction_pov_after_a2")
        self.assertEqual(summary["gates_converged"], ["pov_after"])

    def test_retry_summary_surfaces_api_error_reroll(self) -> None:
        state = {
            "max_correction_attempts": 3,
            "max_exploit_attempts": 3,
            "max_api_error_attempts": 2,
            "steps": [],
            "agents": [
                {"agent_name": "patcher", "api_error_attempts": [], "parse_error": None},
                {"agent_name": "patcher_apierr_a2", "parse_error": None, "refused": False,
                 "api_error_attempts": ["API Error: Output blocked by content filtering policy"]},
                {"agent_name": "exploiter_apierr_a2",
                 "parse_error": "claude exited with code 1", "refused": False,
                 "api_error_attempts": ["API Error: Connection closed mid-response."]},
            ],
        }

        summary = runs._retry_summary(state)

        self.assertEqual(summary["max_api_error_attempts"], 2)
        rerolls = summary["api_error_retries"]
        self.assertEqual(len(rerolls), 2)
        cf, drop = rerolls
        self.assertEqual((cf["kind"], cf["recovered"], cf["agent"]),
                         ("content_filter", True, "patcher_apierr_a2"))
        self.assertEqual((drop["kind"], drop["recovered"]), ("connection", False))

    def test_live_monitor_shows_base_agent_during_api_error_reroll(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            # First-pass patcher was blocked and wrote its output.json; the
            # api-error re-roll in patcher_apierr_a2 is the one actually working.
            done = run_dir / "agent_io" / "patcher"
            done.mkdir(parents=True)
            (done / "input.md").write_text("patch it", encoding="utf-8")
            (done / "output.json").write_text('{"parse_error": "claude exited with code 1"}',
                                              encoding="utf-8")
            retry = run_dir / "agent_io" / "patcher_apierr_a2"
            retry.mkdir(parents=True)
            (retry / "input.md").write_text("patch it, minimal edits", encoding="utf-8")
            # Exploiter + POV-before passed; the patcher is the stage in flight, and
            # its base run has been blocked, so the re-roll folder is the live agent.
            state = {
                "profile": "full",
                "stages": ["exploiter", "patcher", "converge"],
                "steps": [
                    {"name": "metadata", "status": "ok"},
                    {"name": "pov_before_patch", "status": "ok"},
                ],
                "agents": [
                    {"agent_name": "exploiter", "exit_code": 0, "parse_error": None,
                     "parsed_output": {"status": "pov_created"}},
                ],
                "commands": [],
            }

            stages, running = live.live_stages(run_dir, state, terminal=False)

            self.assertEqual(running, "patcher")
            stage = next(s for s in stages if s["key"] == "patcher")
            self.assertIn("patcher_apierr_a2", stage["detail"])

    def test_retry_agent_artifacts_are_addressable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_id = "20260722_120000_finding-123456abcdef"
            agent_dir = runs_dir / run_id / "agent_io" / "patcher_correction_pov_after_a2"
            agent_dir.mkdir(parents=True)
            (agent_dir / "input.md").write_text("fix your patch", encoding="utf-8")
            (agent_dir / "output.json").write_text('{"status":"patched"}', encoding="utf-8")

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                artifact = runs.get_agent_io(run_id, "patcher_correction_pov_after_a2")

            self.assertEqual(artifact["output_json"]["status"], "patched")

    def test_live_monitor_shows_the_retrying_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            # First-pass exploiter finished; its retry is the one actually working.
            done = run_dir / "agent_io" / "exploiter"
            done.mkdir(parents=True)
            (done / "input.md").write_text("build a pov", encoding="utf-8")
            (done / "output.json").write_text('{"status":"pov_created"}', encoding="utf-8")
            retry = run_dir / "agent_io" / "exploiter_retry_a2"
            retry.mkdir(parents=True)
            (retry / "input.md").write_text("fix your pov", encoding="utf-8")
            state = {
                "profile": "full",
                "stages": ["exploiter", "patcher"],
                "steps": [{"name": "metadata", "status": "ok"}],
                "agents": [
                    {"agent_name": "exploiter", "exit_code": 0, "parse_error": None,
                     "parsed_output": {"status": "pov_created"}},
                ],
                "commands": [],
            }

            stages, running = live.live_stages(run_dir, state, terminal=False)

            self.assertEqual(running, "pov_before_patch")
            stage = next(s for s in stages if s["key"] == "pov_before_patch")
            self.assertIn("exploiter_retry_a2", stage["detail"])

    def test_failed_gate_reads_as_running_while_the_patcher_corrects_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            correction = run_dir / "agent_io" / "patcher_correction_a2"
            correction.mkdir(parents=True)
            (correction / "input.md").write_text("fix your patch", encoding="utf-8")
            state = {
                "profile": "full",
                "stages": ["exploiter", "patcher", "converge"],
                "steps": [
                    {"name": "metadata", "status": "ok"},
                    {"name": "pov_before_patch", "status": "ok"},
                ],
                "agents": [
                    {"agent_name": "exploiter", "exit_code": 0, "parse_error": None,
                     "parsed_output": {"status": "pov_created"}},
                    {"agent_name": "patcher", "exit_code": 0, "parse_error": None,
                     "parsed_output": {"status": "patched"}},
                ],
                # The POV still reproduced — a failure the run can still recover from.
                "commands": [{"name": "pov_after_patch", "exit_code": 0, "timed_out": False}],
            }

            stages, running = live.live_stages(run_dir, state, terminal=False)

            self.assertEqual(running, "pov_after_patch")
            stage = next(s for s in stages if s["key"] == "pov_after_patch")
            self.assertEqual(stage["status"], "running")
            self.assertIn("patcher_correction_a2", stage["detail"])


class RunDirBindingTests(unittest.TestCase):
    """A live monitor must show the run its own launch created, and no other.

    The finding id is profile-independent, so every run of the same alert shares
    it. Binding by "newest dir for this finding, touched near my start time"
    therefore hands a second launch the *previous* profile's run — two monitors
    rendering one run, which is how a hardening launch came up showing a
    baseline rail.
    """

    FINDING = "finding-123456abcdef"

    def _launch(self, tmp: Path, profile: str) -> "live.Launch":
        ln = live.Launch(
            f"launch-{profile}", "alert.json", {"finding_id": self.FINDING, "profile": profile}
        )
        ln.dir = tmp / "live" / ln.id
        ln.log_path = ln.dir / "orchestrator.log"
        ln.dir.mkdir(parents=True, exist_ok=True)
        ln.started_wall = time.time()
        return ln

    def _run_dir(self, runs_dir: Path, name: str, profile: str) -> Path:
        run_dir = runs_dir / name
        run_dir.mkdir()
        (run_dir / "state.json").write_text(
            json.dumps({"profile": profile, "status": "running"}), encoding="utf-8"
        )
        return run_dir

    def test_launch_does_not_bind_a_sibling_launchs_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir()
            baseline_dir = self._run_dir(runs_dir, f"20260731_120000_{self.FINDING}", "baseline")
            baseline = self._launch(Path(tmp), "baseline")
            baseline.run_id, baseline.run_dir = baseline_dir.name, baseline_dir
            live._LAUNCHES[baseline.id] = baseline

            # The hardening launch is spawned right after; its own run dir does not
            # exist yet, while the baseline run's dir was touched moments ago.
            hardening = self._launch(Path(tmp), "hardening")
            os.utime(baseline_dir, None)
            try:
                with patch.object(runs.config, "RUNS_DIR", runs_dir):
                    self.assertIsNone(live._discover_run_dir(hardening))

                    hardening_dir = self._run_dir(
                        runs_dir, f"20260731_120100_{self.FINDING}", "hardening"
                    )
                    found = live._discover_run_dir(hardening)
            finally:
                live._LAUNCHES.pop(baseline.id, None)

            self.assertEqual(found, hardening_dir)

    def test_announced_run_dir_wins_over_the_timestamp_heuristic(self) -> None:
        """The child prints the dir it claimed, which ends the guessing."""
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir()
            self._run_dir(runs_dir, f"20260731_120000_{self.FINDING}", "baseline")
            mine = self._run_dir(runs_dir, f"20260731_120100_{self.FINDING}", "hardening")
            # Newer sibling that the heuristic would prefer, but that is not ours.
            self._run_dir(runs_dir, f"20260731_120200_{self.FINDING}", "hardening")

            ln = self._launch(Path(tmp), "hardening")
            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                found = live._discover_run_dir(ln, f"security-pipeline: run dir {mine}\n")

            self.assertEqual(found.name, mine.name)

    def test_a_wrong_binding_is_repaired_once_the_child_announces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir()
            wrong = self._run_dir(runs_dir, f"20260731_120000_{self.FINDING}", "baseline")
            mine = self._run_dir(runs_dir, f"20260731_120100_{self.FINDING}", "hardening")

            ln = self._launch(Path(tmp), "hardening")
            ln.run_id, ln.run_dir = wrong.name, wrong
            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                found = live._discover_run_dir(ln, f"security-pipeline: run dir {mine}\n")

            self.assertEqual(found.name, mine.name)
            self.assertEqual(ln.run_id, mine.name)

    def test_a_pre_announcement_mismatch_is_repaired_from_the_profile(self) -> None:
        """Records already on disk heal too: they predate the announcement."""
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir()
            wrong = self._run_dir(runs_dir, f"20260731_120000_{self.FINDING}", "baseline")
            ln = self._launch(Path(tmp), "hardening")
            ln.run_id, ln.run_dir = wrong.name, wrong
            mine = self._run_dir(runs_dir, f"20260731_120100_{self.FINDING}", "hardening")

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                found = live._discover_run_dir(ln, "")

            self.assertEqual(found.name, mine.name)

    def test_a_correct_binding_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp) / "runs"
            runs_dir.mkdir()
            mine = self._run_dir(runs_dir, f"20260731_120000_{self.FINDING}", "hardening")
            self._run_dir(runs_dir, f"20260731_120100_{self.FINDING}", "hardening")
            ln = self._launch(Path(tmp), "hardening")
            ln.run_id, ln.run_dir = mine.name, mine

            with patch.object(runs.config, "RUNS_DIR", runs_dir):
                found = live._discover_run_dir(ln, "")

            self.assertEqual(found.name, mine.name)

    def test_pipeline_announces_its_run_dir_on_stderr(self) -> None:
        """The announcement the dashboard parses is emitted by the pipeline itself."""
        from security_pipeline import pipeline as pipeline_mod

        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            run_dir = runs_dir / f"20260731_120000_{self.FINDING}"
            captured = StringIO()
            with patch.object(sys, "stderr", captured):
                pipeline_mod.announce_run_dir(run_dir)

            self.assertEqual(
                live._announced_run_dir_name(captured.getvalue()), run_dir.name
            )


class EvalAlignmentTests(unittest.TestCase):
    def _hardening_detail(self, final_replay: dict) -> dict:
        return {
            "hardening": {
                "status": "stable",
                "max_rounds": 4,
                "rounds_attempted": 2,
                "rounds": [{"round": 1}, {"round": 2}],
            },
            "commands": [
                {"name": "harden_variant_before_r1", "exit_code": 0, "timed_out": False},
                {"name": "harden_original_recheck_r1", "exit_code": 1, "timed_out": False},
                # Authoritative final-patch verification (P1), not the per-round check.
                {"name": "harden_final_replay_r1", **final_replay},
            ],
            "agents": [],
        }

    def test_blocked_variant_uses_final_replay(self) -> None:
        sig = analysis_base.hardening_signals(self._hardening_detail({"exit_code": 1, "timed_out": False}))
        self.assertEqual(sig["variants_found"], 1)
        self.assertTrue(sig["all_variants_blocked"])
        self.assertTrue(sig["original_still_blocked"])
        self.assertTrue(sig["stopped_because_no_new_bypass"])

    def test_final_replay_reproduction_is_a_proven_hole(self) -> None:
        # The final patch regressed the round-1 variant — a definite exit 0.
        sig = analysis_base.hardening_signals(self._hardening_detail({"exit_code": 0, "timed_out": False}))
        self.assertFalse(sig["all_variants_blocked"])

    def test_timeout_is_inconclusive_not_a_hole(self) -> None:
        # P2: a timeout must be tri-state null, never False ("proven hole").
        sig = analysis_base.hardening_signals(self._hardening_detail({"exit_code": 0, "timed_out": True}))
        self.assertIsNone(sig["variants"][0]["blocked_by_final_patch"])
        self.assertIsNone(sig["all_variants_blocked"])

    def test_missing_final_replay_is_inconclusive(self) -> None:
        detail = self._hardening_detail({"exit_code": 1, "timed_out": False})
        detail["commands"] = [c for c in detail["commands"] if c["name"] != "harden_final_replay_r1"]
        sig = analysis_base.hardening_signals(detail)
        self.assertIsNone(sig["all_variants_blocked"])

    def test_no_round_evidence_returns_none(self) -> None:
        # P3a: a hardening-profile run rejected before the loop carries a summary
        # with zero rounds and must not emit a "we looped" signal.
        self.assertIsNone(
            analysis_base.hardening_signals(
                {"hardening": {"status": "pending", "rounds": []}, "commands": [], "agents": []}
            )
        )

    def test_round_reports_sort_numerically(self) -> None:
        # P3b: r10 must come after r2, not lexically between r1 and r2.
        agents = [
            {"name": "exploiter_harden_r10", "parsed_output": {"status": "no_pov"}},
            {"name": "exploiter_harden_r2", "parsed_output": {"status": "pov_created"}},
            {"name": "exploiter_harden_r1", "parsed_output": {"status": "pov_created"}},
            {"name": "patcher_harden_r1", "parsed_output": {"status": "patched"}},
            {"name": "exploiter", "parsed_output": {"status": "pov_created"}},
        ]
        names = [name for name, _ in exploit_eval._round_reports(agents)]
        self.assertEqual(names, ["exploiter_harden_r1", "exploiter_harden_r2", "exploiter_harden_r10"])

    def test_non_hardening_run_gets_no_signal_or_section(self) -> None:
        self.assertIsNone(analysis_base.hardening_signals({"commands": [], "agents": []}))
        # Both judge inputs must stay byte-identical to before for non-hardening runs.
        self.assertEqual(patch_eval._hardening_section(None), [])
        self.assertEqual(exploit_eval._hardening_section(None, []), [])


if __name__ == "__main__":
    unittest.main()
