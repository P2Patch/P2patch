from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from security_pipeline import docker_runner, env
from security_pipeline.claude_agents import extract_json_object, parse_claude_stdout
from security_pipeline.cli import main, plan_alerts
from security_pipeline.docker_runner import DockerRunner, sanitize_docker_component
from security_pipeline.gates import (
    GateError,
    filter_duplicate_pov_commands,
    normalize_path_text,
    validate_exploiter_output,
    validate_patcher_output,
)
from security_pipeline.metadata import resolve_project_metadata
from security_pipeline.models import AgentResult, CommandResult, ProjectMetadata
from security_pipeline.pipeline import existing_run_dirs, make_finding_id
from security_pipeline.workspace import (
    create_worktree,
    hash_path_tree,
    restore_path_tree,
    restore_worktree_sources,
    snapshot_path_tree,
    snapshot_worktree_sources,
)


class MetadataTests(unittest.TestCase):
    def test_resolves_alert_to_project_and_dockerfile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture_workspace(root)
            alert_path = root / "finder_results_filtered" / "ALERT.json"

            metadata = resolve_project_metadata(alert_path, root)

            self.assertEqual(metadata.project_slug, "owner__repo_CVE-2099-0001_1.0.0")
            self.assertEqual(metadata.cwe_id, "CWE-022")
            self.assertEqual(metadata.build_system, "maven")
            self.assertEqual(metadata.test_command, "mvn -B test")
            self.assertTrue(str(metadata.dockerfile_path).endswith("/42/Dockerfile"))

    @staticmethod
    def _write_fixture_workspace(root: Path) -> None:
        (root / "finder_results_filtered").mkdir(parents=True)
        (root / "benchmark/dataset/project-sources/owner__repo_CVE-2099-0001_1.0.0").mkdir(parents=True)
        (root / "benchmark/dataset/project-sources/owner__repo_CVE-2099-0001_1.0.0/pom.xml").write_text("<project />")
        (root / "benchmark/dataset/Dockerfiles/owner__repo_CVE-2099-0001_1.0.0/42").mkdir(parents=True)
        (root / "benchmark/dataset/Dockerfiles/owner__repo_CVE-2099-0001_1.0.0/42/Dockerfile").write_text("FROM scratch\n")
        (root / "benchmark/dataset").mkdir(parents=True, exist_ok=True)
        (root / "benchmark/dataset/project_info.csv").write_text(
            "id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids\n"
            "1,owner__repo_CVE-2099-0001_1.0.0,CVE-2099-0001,CWE-022,Path Traversal,owner,repo,1.0.0,https://example.invalid,GHSA-test,abc,def\n"
        )
        (root / "benchmark/dataset/build_info.csv").write_text(
            "project_slug,status,jdk_version,mvn_version,gradle_version,use_gradlew\n"
            "owner__repo_CVE-2099-0001_1.0.0,success,8,3.5.0,,\n"
        )
        (root / "finder_results_filtered/ALERT.json").write_text(
            json.dumps({"cve_id": "CVE-2099-0001", "cwe_id": "cwe-022", "vulnerabilities": []})
        )


class DockerRunnerTests(unittest.TestCase):
    def test_constructs_builder_and_project_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dockerfile = root / "Dockerfile"
            dockerfile.write_text("FROM scratch\n")
            project = ProjectMetadata(
                project_slug="OWNER__Repo/CVE",
                cve_id="CVE-1",
                cwe_id="CWE-022",
                cwe_name="",
                github_url="",
                github_tag="",
                buggy_commit_id="",
                fix_commit_ids="",
                source_path=root / "source",
                dockerfile_path=dockerfile,
                build_system="maven",
                build_command="mvn package",
                test_command="mvn test",
            )
            runner = DockerRunner(project, root / "worktree", root / "run")
            anonymous_runner = DockerRunner(project, root / "worktree", root / "run", image_key="finding-abc123")

            self.assertIn("--target", runner.build_args())
            self.assertIn("builder", runner.build_args())
            self.assertTrue(runner.image_tag.startswith("p2patch-owner__repo-cve:"))
            self.assertTrue(anonymous_runner.image_tag.startswith("p2patch-finding-abc123:"))
            self.assertNotIn("cve", anonymous_runner.image_tag.lower())
            self.assertIn("/workspace/repo", runner.command_args("mvn test"))
            self.assertEqual(sanitize_docker_component("A/B C"), "a-b-c")



class ClaudeParsingTests(unittest.TestCase):
    def test_parses_wrapped_claude_json_result(self) -> None:
        raw = json.dumps({"type": "result", "result": "{\"status\":\"pov_created\"}"})
        self.assertEqual(parse_claude_stdout(raw), {"status": "pov_created"})

    def test_extracts_fenced_json(self) -> None:
        self.assertEqual(extract_json_object("```json\n{\"ok\": true}\n```"), {"ok": True})


class GateTests(unittest.TestCase):
    def test_validates_pov_under_expected_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            pov = worktree / ".security-pipeline/pov/pov.sh"
            pov.parent.mkdir(parents=True)
            pov.write_text("#!/usr/bin/env bash\n")

            validated = validate_exploiter_output(
                {"status": "pov_created", "pov_path": ".security-pipeline/pov/pov.sh", "pov_command": "./pov.sh"},
                worktree,
            )

            self.assertEqual(validated["pov_command"], "./pov.sh")

    def test_normalizes_agent_path_with_parenthetical_text(self) -> None:
        self.assertEqual(
            normalize_path_text(".security-pipeline/pov/run_pov.sh (drives helper.java)"),
            ".security-pipeline/pov/run_pov.sh",
        )

    def test_rejects_pov_outside_expected_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(GateError):
                validate_exploiter_output(
                    {"status": "pov_created", "pov_path": "src/test.java", "pov_command": "mvn test"},
                    Path(tmp),
                )

    def test_resolves_container_mount_path_against_worktree(self) -> None:
        # Agents sometimes echo /workspace/repo (the in-container mount from
        # docker_runner.py) for pov_path instead of a worktree-relative path.
        with tempfile.TemporaryDirectory() as tmp:
            worktree = Path(tmp)
            pov = worktree / ".security-pipeline/pov/pov.sh"
            pov.parent.mkdir(parents=True)
            pov.write_text("#!/usr/bin/env bash\n")

            validated = validate_exploiter_output(
                {
                    "status": "pov_created",
                    "pov_path": "/workspace/repo/.security-pipeline/pov/pov.sh",
                    "pov_command": "./pov.sh",
                },
                worktree,
            )

            self.assertEqual(validated["pov_path"], str(pov))

    def test_rejects_foreign_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(GateError):
                validate_exploiter_output(
                    {"status": "pov_created", "pov_path": "/etc/passwd", "pov_command": "mvn test"},
                    Path(tmp),
                )

    def test_rejects_invalid_regression_command_shape(self) -> None:
        with self.assertRaises(GateError):
            validate_patcher_output({"status": "patched", "regression_commands": "mvn test"})

    def test_filters_duplicate_pov_regression_command(self) -> None:
        self.assertEqual(
            filter_duplicate_pov_commands(
                ["mvn test", " bash   .security-pipeline/pov/run_pov.sh "],
                "bash .security-pipeline/pov/run_pov.sh",
            ),
            ["mvn test"],
        )

    def test_hash_changes_when_pov_is_modified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pov_dir = Path(tmp) / ".security-pipeline/pov"
            pov_dir.mkdir(parents=True)
            pov_file = pov_dir / "pov.txt"
            pov_file.write_text("before")
            before = hash_path_tree(pov_dir)
            pov_file.write_text("after")
            self.assertNotEqual(before, hash_path_tree(pov_dir))


class PovIntegrityHashTests(unittest.TestCase):
    """Running a POV must not read as tampering with it.

    A POV command routinely compiles in place — `javac Pov.java` writes
    `Pov.class` beside the source, `javac -d . pkg/Pov.java` writes it into a
    package subdirectory — and the patcher is expected to re-run the POV to
    check its own fix. Hashing that output rejected correct patches.
    """

    def _pov_dir(self, tmp: str) -> Path:
        pov_dir = Path(tmp) / ".security-pipeline/pov"
        pov_dir.mkdir(parents=True)
        (pov_dir / "Pov.java").write_text("class Pov {}")
        return pov_dir

    def test_ignores_class_files_beside_the_pov_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pov_dir = self._pov_dir(tmp)
            before = hash_path_tree(pov_dir)

            (pov_dir / "Pov.class").write_bytes(b"\xca\xfe\xba\xbe v1")
            self.assertEqual(before, hash_path_tree(pov_dir))
            # A re-run recompiles: same file, different bytes. Still not tampering.
            (pov_dir / "Pov.class").write_bytes(b"\xca\xfe\xba\xbe v2")
            self.assertEqual(before, hash_path_tree(pov_dir))

    def test_ignores_class_files_in_package_subdirectories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pov_dir = self._pov_dir(tmp)
            before = hash_path_tree(pov_dir)

            package = pov_dir / "org/apache/commons/io"
            package.mkdir(parents=True)
            (package / "Pov.class").write_bytes(b"\xca\xfe\xba\xbe")
            self.assertEqual(before, hash_path_tree(pov_dir))

    def test_still_detects_an_edit_to_pov_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pov_dir = self._pov_dir(tmp)
            before = hash_path_tree(pov_dir)

            (pov_dir / "Pov.java").write_text("class Pov { /* neutered */ }")
            self.assertNotEqual(before, hash_path_tree(pov_dir))

    def test_restore_undoes_edits_additions_and_deletions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pov_dir = self._pov_dir(tmp)
            script = pov_dir / "run_pov.sh"
            script.write_text("#!/usr/bin/env bash\nexit 0\n")
            script.chmod(0o755)
            snapshot = snapshot_path_tree(pov_dir)
            before = hash_path_tree(pov_dir)

            (pov_dir / "Pov.java").write_text("class Pov { /* neutered */ }")
            script.unlink()
            (pov_dir / "Extra.java").write_text("class Extra {}")
            (pov_dir / "Pov.class").write_bytes(b"\xca\xfe\xba\xbe")  # build output: left alone

            changed = restore_path_tree(pov_dir, snapshot)

            self.assertEqual(changed, ["Extra.java", "Pov.java", "run_pov.sh"])
            self.assertEqual(before, hash_path_tree(pov_dir))
            self.assertFalse((pov_dir / "Extra.java").exists())
            self.assertEqual(script.stat().st_mode & 0o777, 0o755)
            self.assertTrue((pov_dir / "Pov.class").exists())
            # Nothing left to undo the second time around.
            self.assertEqual(restore_path_tree(pov_dir, snapshot), [])


class DockerLogPathTests(unittest.TestCase):
    def _runner(self, run_dir: Path) -> DockerRunner:
        project = ProjectMetadata(
            project_slug="owner__repo", cve_id="CVE-2099-0001", cwe_id="", cwe_name="",
            github_url="", github_tag="", buggy_commit_id="", fix_commit_ids="",
            source_path=run_dir, dockerfile_path=run_dir / "Dockerfile",
            build_system="maven", build_command="", test_command="",
        )
        (run_dir / "Dockerfile").write_text("FROM scratch\n")
        return DockerRunner(project, run_dir, run_dir)

    def test_log_name_cannot_escape_the_docker_directory(self) -> None:
        # fixPOV log names are built from manifest POV ids (`fixpov_<id>`).
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(Path(tmp))
            for name in ("fixpov_../../escape", "fixpov_/etc/passwd", "../../../x"):
                path = runner.log_path_for(name)
                self.assertEqual(path.parent, runner.docker_log_dir, name)

    def test_ordinary_log_names_are_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._runner(Path(tmp))
            self.assertEqual(runner.log_path_for("pov_after_patch").name, "pov_after_patch.log")
            self.assertEqual(runner.log_path_for("fixpov_zip-slip.1").name, "fixpov_zip-slip.1.log")


class PovGuardSymlinkTests(unittest.TestCase):
    """A link inside the PoV tree must never be followed.

    The guard snapshots and rewrites files under `.security-pipeline/pov`. When
    those operations dereferenced links, a PoV entry pointing at product source
    made the guard read the product file into the snapshot and then write the old
    bytes back through the link — reverting the patcher's own fix, after which the
    run could never pass the PoV-after gate it was being sent back to fix.
    """

    def _tree(self, tmp: str):
        root = Path(tmp)
        pov_dir = root / ".security-pipeline/pov"
        pov_dir.mkdir(parents=True)
        (root / "src").mkdir()
        source = root / "src" / "Main.java"
        source.write_text("class Main { /* vulnerable */ }")
        return root, pov_dir, source

    def test_restore_does_not_write_through_a_link_into_product_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, pov_dir, source = self._tree(tmp)
            (pov_dir / "alias.java").symlink_to("../../src/Main.java")
            snapshot = snapshot_path_tree(pov_dir)

            source.write_text("class Main { /* patched */ }")
            changed = restore_path_tree(pov_dir, snapshot)

            self.assertEqual(changed, [])
            self.assertIn("patched", source.read_text())
            self.assertTrue((pov_dir / "alias.java").is_symlink())

    def test_link_swapped_in_over_a_pov_file_is_replaced_by_the_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, pov_dir, source = self._tree(tmp)
            pov_file = pov_dir / "Pov.java"
            pov_file.write_text("class Pov {}")
            snapshot = snapshot_path_tree(pov_dir)

            # Swap the real PoV file for a link at the same path.
            pov_file.unlink()
            pov_file.symlink_to("../../src/Main.java")
            changed = restore_path_tree(pov_dir, snapshot)

            self.assertEqual(changed, ["Pov.java"])
            self.assertFalse(pov_file.is_symlink())
            self.assertEqual(pov_file.read_text(), "class Pov {}")
            self.assertIn("vulnerable", source.read_text())

    def test_a_link_that_replaces_a_directory_is_removed_and_files_restored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, pov_dir, _ = self._tree(tmp)
            (pov_dir / "sub").mkdir()
            (pov_dir / "sub" / "Helper.java").write_text("class Helper {}")
            snapshot = snapshot_path_tree(pov_dir)

            shutil.rmtree(pov_dir / "sub")
            (pov_dir / "sub").symlink_to(root / "src")
            restore_path_tree(pov_dir, snapshot)

            self.assertFalse((pov_dir / "sub").is_symlink())
            self.assertEqual((pov_dir / "sub" / "Helper.java").read_text(), "class Helper {}")

    def test_hash_reflects_the_link_target_not_its_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, pov_dir, source = self._tree(tmp)
            (pov_dir / "alias.java").symlink_to("../../src/Main.java")
            before = hash_path_tree(pov_dir)
            source.write_text("class Main { /* patched */ }")
            # Editing the *target* is not a change to the PoV tree...
            self.assertEqual(before, hash_path_tree(pov_dir))
            # ...but repointing the link is.
            (pov_dir / "alias.java").unlink()
            (pov_dir / "alias.java").symlink_to("../../src/Other.java")
            self.assertNotEqual(before, hash_path_tree(pov_dir))


class SourceGuardTests(unittest.TestCase):
    """The exploiter owns its PoV tree and nothing else.

    In a hardening round the exploiter runs in the already-patched worktree, so an
    edit it leaves behind rides into the final diff — and the "no new bypass
    found" exit calls that patch stable without ever inspecting it.
    """

    def _repo(self, tmp: str) -> Path:
        repo = Path(tmp) / "worktree"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "Main.java").write_text("class Main { /* vulnerable */ }")
        (repo / "src" / "Other.java").write_text("class Other {}")
        (repo / ".gitignore").write_text("target/\n")
        for argv in (
            ["git", "init", "-q"],
            ["git", "add", "-A"],
            ["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid",
             "commit", "-q", "--no-gpg-sign", "-m", "baseline"],
        ):
            subprocess.run(argv, cwd=repo, check=True, capture_output=True)
        return repo

    def test_restores_edits_to_already_patched_and_pristine_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            patched = repo / "src" / "Main.java"
            patched.write_text("class Main { /* patched */ }")  # the patcher's fix

            snapshot = snapshot_worktree_sources(repo)

            # Now the exploiter meddles: weakens the fix and edits a pristine file.
            patched.write_text("class Main { /* fix removed */ }")
            (repo / "src" / "Other.java").write_text("class Other { /* debug */ }")

            changed = restore_worktree_sources(repo, snapshot)

            self.assertEqual(changed, ["src/Main.java", "src/Other.java"])
            self.assertIn("patched", patched.read_text())
            self.assertEqual((repo / "src" / "Other.java").read_text(), "class Other {}")

    def test_deletes_product_files_the_exploiter_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            snapshot = snapshot_worktree_sources(repo)
            (repo / "src" / "Injected.java").write_text("class Injected {}")

            self.assertEqual(restore_worktree_sources(repo, snapshot), ["src/Injected.java"])
            self.assertFalse((repo / "src" / "Injected.java").exists())

    def test_a_new_directory_like_a_submodule_checkout_is_removed_not_crashed(self) -> None:
        # A path git status reports as changed is not necessarily a file: a
        # project's build step (e.g. `./bootstrap`) can populate a whole git
        # submodule checkout under a path that was absent at snapshot time.
        # Path.unlink() cannot remove a non-empty directory; restore must
        # recurse instead of raising IsADirectoryError.
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            snapshot = snapshot_worktree_sources(repo)
            self.assertNotIn("gnulib", snapshot)

            submodule = repo / "gnulib"
            submodule.mkdir()
            (submodule / "lib.c").write_text("int x;")
            # Simulate git status already having reported the path (e.g. a
            # staged gitlink) before it was checked out to disk.
            snapshot["gnulib"] = None

            self.assertEqual(restore_worktree_sources(repo, snapshot), ["gnulib"])
            self.assertFalse(submodule.exists())

    def test_leaves_the_pov_tree_and_build_output_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            snapshot = snapshot_worktree_sources(repo)

            pov = repo / ".security-pipeline" / "pov"
            pov.mkdir(parents=True)
            (pov / "Pov.java").write_text("class Pov {}")  # the exploiter's own work
            (repo / "target").mkdir()
            (repo / "target" / "Main.class").write_bytes(b"\xca\xfe\xba\xbe")

            self.assertEqual(restore_worktree_sources(repo, snapshot), [])
            self.assertTrue((pov / "Pov.java").exists())
            self.assertTrue((repo / "target" / "Main.class").exists())

    def test_restores_a_product_file_the_exploiter_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            snapshot = snapshot_worktree_sources(repo)
            (repo / "src" / "Other.java").unlink()

            self.assertEqual(restore_worktree_sources(repo, snapshot), ["src/Other.java"])
            self.assertEqual((repo / "src" / "Other.java").read_text(), "class Other {}")

    def test_unignored_build_output_is_never_deleted(self) -> None:
        # A project shipping no `target/` ignore rule reports the whole directory
        # as one untracked entry; deleting it would throw away the incremental
        # build every later command depends on.
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            (repo / ".gitignore").unlink()
            subprocess.run(["git", "rm", "-q", "--cached", ".gitignore"], cwd=repo,
                           check=True, capture_output=True)
            (repo / "target" / "classes").mkdir(parents=True)
            (repo / "target" / "classes" / "Main.class").write_bytes(b"\xca\xfe\xba\xbe")
            snapshot = snapshot_worktree_sources(repo)
            (repo / "target" / "classes" / "New.class").write_bytes(b"\xca\xfe")

            restore_worktree_sources(repo, snapshot)

            self.assertTrue((repo / "target" / "classes" / "Main.class").exists())

    def test_a_tracked_symlink_is_left_for_git_rather_than_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            (repo / "link.java").symlink_to("src/Main.java")
            snapshot = snapshot_worktree_sources(repo)
            self.assertEqual(snapshot["link.java"][0], "other")
            self.assertEqual(restore_worktree_sources(repo, snapshot), [])
            self.assertTrue((repo / "link.java").is_symlink())

    def test_untouched_tree_reports_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            (repo / "src" / "Main.java").write_text("class Main { /* patched */ }")
            snapshot = snapshot_worktree_sources(repo)
            self.assertEqual(restore_worktree_sources(repo, snapshot), [])


class CliDryRunTests(unittest.TestCase):
    def test_dry_run_writes_context_without_docker_or_claude(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            MetadataTests._write_fixture_workspace(root)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "run",
                        "--alert",
                        str(root / "finder_results_filtered/ALERT.json"),
                        "--workspace-root",
                        str(root),
                        "--runs-dir",
                        str(root / "runs"),
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            run_dirs = list((root / "runs").iterdir())
            self.assertEqual(len(run_dirs), 1)
            self.assertTrue((run_dirs[0] / "context.json").exists())
            self.assertNotIn("CVE-2099-0001", run_dirs[0].name)
            context_text = (run_dirs[0] / "context.json").read_text()
            state_text = (run_dirs[0] / "state.json").read_text()
            verdict_text = (run_dirs[0] / "verdict.json").read_text()
            self.assertNotIn("CVE-2099-0001", context_text)
            self.assertNotIn("owner__repo_CVE-2099-0001_1.0.0", context_text)
            self.assertNotIn("CVE-2099-0001", state_text)
            self.assertNotIn("owner__repo_CVE-2099-0001_1.0.0", state_text)
            self.assertNotIn("CVE-2099-0001", verdict_text)
            self.assertNotIn("owner__repo_CVE-2099-0001_1.0.0", verdict_text)
            verdict = json.loads((run_dirs[0] / "verdict.json").read_text())
            self.assertEqual(verdict["status"], "dry_run")

    def test_records_the_requested_model_in_state_and_verdict(self) -> None:
        """The launched model is a run artifact, not only a per-agent report.

        The Claude CLI reports the model it served each agent with, but nothing
        reports one until an agent finishes — so a queued run, one still
        building its image, and one whose agents all crashed had no record of
        the model at all, and the dashboard rendered them as "default".
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            MetadataTests._write_fixture_workspace(root)
            with redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        "run",
                        "--alert",
                        str(root / "finder_results_filtered/ALERT.json"),
                        "--workspace-root",
                        str(root),
                        "--runs-dir",
                        str(root / "runs"),
                        "--model",
                        "glm-5.3",
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            run_dir = next(iter((root / "runs").iterdir()))
            self.assertEqual(json.loads((run_dir / "state.json").read_text())["model"], "glm-5.3")
            self.assertEqual(json.loads((run_dir / "verdict.json").read_text())["model"], "glm-5.3")

    def test_an_unspecified_model_is_recorded_as_the_pinned_default(self) -> None:
        """"Default" in the launcher still means one specific pinned model.

        The runner passes ``--model DEFAULT_AGENT_MODEL`` when a run does not
        choose one, so recording "" would keep claiming the model is unknown
        when it is not.
        """
        from security_pipeline.claude_agents import DEFAULT_AGENT_MODEL

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            MetadataTests._write_fixture_workspace(root)
            with redirect_stdout(io.StringIO()):
                main(
                    [
                        "run",
                        "--alert",
                        str(root / "finder_results_filtered/ALERT.json"),
                        "--workspace-root",
                        str(root),
                        "--runs-dir",
                        str(root / "runs"),
                        "--dry-run",
                    ]
                )
            run_dir = next(iter((root / "runs").iterdir()))
            self.assertEqual(
                json.loads((run_dir / "verdict.json").read_text())["model"], DEFAULT_AGENT_MODEL
            )


class ExistingRunDirsTests(unittest.TestCase):
    def test_matches_timestamped_and_collision_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            (runs / "20200101_000000_finding-abc123def456").mkdir()
            (runs / "20200102_000000_finding-abc123def456_2").mkdir()
            (runs / "20200101_000000_finding-999999999999").mkdir()
            (runs / "not-a-run.txt").write_text("x")

            matches = existing_run_dirs(runs, "finding-abc123def456")

            names = sorted(path.name for path in matches)
            self.assertEqual(
                names,
                ["20200101_000000_finding-abc123def456", "20200102_000000_finding-abc123def456_2"],
            )

    def test_returns_empty_when_runs_dir_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(existing_run_dirs(Path(tmp) / "missing", "finding-abc123def456"), [])


class PlanAlertsTests(unittest.TestCase):
    def _setup(self, tmp: str):
        root = Path(tmp)
        MetadataTests._write_fixture_workspace(root)
        alert_path = root / "finder_results_filtered" / "ALERT.json"
        runs = root / "runs"
        runs.mkdir()
        finding_id = make_finding_id(alert_path, resolve_project_metadata(alert_path, root))
        return root, alert_path, runs, finding_id

    @staticmethod
    def _make_prior_run(runs: Path, finding_id: str, status: str) -> Path:
        run_dir = runs / f"20200101_000000_{finding_id}"
        run_dir.mkdir()
        (run_dir / "verdict.json").write_text(json.dumps({"status": status}))
        return run_dir

    def test_runs_when_no_prior_and_not_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, alert_path, runs, _ = self._setup(tmp)
            plan = plan_alerts([alert_path], workspace_root=root, runs_dir=runs, exclude=[], rerun=False)
            self.assertEqual(plan, [(alert_path, None)])

    def test_skips_prior_real_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, alert_path, runs, finding_id = self._setup(tmp)
            self._make_prior_run(runs, finding_id, "rejected")
            plan = plan_alerts([alert_path], workspace_root=root, runs_dir=runs, exclude=[], rerun=False)
            self.assertEqual(len(plan), 1)
            self.assertTrue(plan[0][1].startswith("already ran"))

    def test_dry_run_only_does_not_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, alert_path, runs, finding_id = self._setup(tmp)
            self._make_prior_run(runs, finding_id, "dry_run")
            plan = plan_alerts([alert_path], workspace_root=root, runs_dir=runs, exclude=[], rerun=False)
            self.assertEqual(plan, [(alert_path, None)])

    def test_rerun_ignores_prior_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, alert_path, runs, finding_id = self._setup(tmp)
            self._make_prior_run(runs, finding_id, "accepted")
            plan = plan_alerts([alert_path], workspace_root=root, runs_dir=runs, exclude=[], rerun=True)
            self.assertEqual(plan, [(alert_path, None)])

    def test_excludes_by_cve_project_slug_and_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, alert_path, runs, _ = self._setup(tmp)
            for token in ("CVE-2099-0001", "owner__repo_CVE-2099-0001_1.0.0", "ALERT.json", "ALERT"):
                plan = plan_alerts([alert_path], workspace_root=root, runs_dir=runs, exclude=[token], rerun=True)
                self.assertEqual(len(plan), 1, token)
                self.assertTrue(plan[0][1].startswith("excluded"), token)


class SkipCliTests(unittest.TestCase):
    def test_bare_run_defaults_to_all_and_skips_prior_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            MetadataTests._write_fixture_workspace(root)
            alert_path = root / "finder_results_filtered" / "ALERT.json"
            runs = root / "runs"
            runs.mkdir()
            finding_id = make_finding_id(alert_path, resolve_project_metadata(alert_path, root))
            PlanAlertsTests._make_prior_run(runs, finding_id, "rejected")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    ["run", "--workspace-root", str(root), "--runs-dir", str(runs), "--dry-run"]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(stdout.getvalue().strip().splitlines()[0])
            self.assertEqual(summary["status"], "skipped")
            self.assertTrue(summary["reason"].startswith("already ran"))
            # No new run directory was created for the skipped alert.
            self.assertEqual(len(list(runs.iterdir())), 1)

    def test_except_flag_skips_matching_alert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            MetadataTests._write_fixture_workspace(root)
            alert_path = root / "finder_results_filtered" / "ALERT.json"
            runs = root / "runs"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "run",
                        "--alert",
                        str(alert_path),
                        "--except",
                        "CVE-2099-0001",
                        "--workspace-root",
                        str(root),
                        "--runs-dir",
                        str(runs),
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            summary = json.loads(stdout.getvalue().strip().splitlines()[0])
            self.assertEqual(summary["status"], "skipped")
            self.assertTrue(summary["reason"].startswith("excluded"))
            self.assertFalse(runs.exists() and any(runs.iterdir()))


class HardeningProfileTests(unittest.TestCase):
    def test_hardening_profile_resolves_with_loop_between_pov_and_regression(self) -> None:
        from security_pipeline.stages import build_stages, resolve_experiment

        experiment = resolve_experiment(profile="hardening")
        stage_names = [stage.name for stage in build_stages(experiment)]

        self.assertEqual(experiment.patcher_evidence, "full")
        self.assertIn("harden", stage_names)
        self.assertLess(stage_names.index("pov_after"), stage_names.index("harden"))
        self.assertLess(stage_names.index("harden"), stage_names.index("regression"))

    def test_default_max_rounds_is_four(self) -> None:
        from security_pipeline.models import RunOptions

        options = RunOptions(
            workspace_root=Path("."), alerts_dir=Path("."), runs_dir=Path(".")
        )
        self.assertEqual(options.max_hardening_rounds, 4)

    def test_retry_budgets_default_to_self_correction(self) -> None:
        # A failing gate goes back to the agent that owns it by default; a budget
        # of 1 would restore the old one-shot reject-on-first-failure behavior.
        from security_pipeline.models import RunOptions

        options = RunOptions(
            workspace_root=Path("."), alerts_dir=Path("."), runs_dir=Path(".")
        )
        self.assertGreater(options.max_correction_attempts, 1)
        self.assertGreater(options.max_exploit_attempts, 1)


class _FakeDocker:
    """Returns queued CommandResults in call order and records the names run."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = []

    def run_project_command(self, command, name, timeout, env_overrides=None):
        self.calls.append(name)
        result = self._results.pop(0)
        # Re-stamp the name so it matches what the loop asked for.
        return CommandResult(
            name=name, command=result.command, exit_code=result.exit_code,
            stdout=result.stdout, stderr=result.stderr, timed_out=result.timed_out,
        )


class _FakeAgentRunner:
    """Returns queued AgentResults in call order and records the run labels.

    A queued entry may be an ``(AgentResult, side_effect)`` pair; the callable is
    invoked with the worktree path before the result is returned, so a test can
    model what an agent did to the tree (compiling a POV, editing one, ...).
    """

    def __init__(self, outputs):
        self._outputs = list(outputs)
        self.calls = []

    def run(self, name, input_text, run_dir, worktree_path, run_label=None, on_retry_reset=None):
        self.calls.append(run_label or name)
        queued = self._outputs.pop(0)
        if isinstance(queued, tuple):
            queued, side_effect = queued
            side_effect(Path(worktree_path))
        return queued


def _cmd(exit_code, command=("cmd",)):
    return CommandResult(name="", command=list(command), exit_code=exit_code, stdout="", stderr="")


def _patcher_agent(regression_commands):
    return AgentResult(
        agent_name="patcher",
        parsed_output={"status": "patched", "regression_commands": list(regression_commands)},
        raw_stdout="", raw_stderr="", exit_code=0,
        input_path=Path("i"), output_path=Path("o"), stdout_path=Path("so"), stderr_path=Path("se"),
    )


def _exploiter_agent(pov_path, pov_command, status="pov_created"):
    return AgentResult(
        agent_name="exploiter",
        parsed_output={"status": status, "pov_path": str(pov_path), "pov_command": pov_command},
        raw_stdout="", raw_stderr="", exit_code=0,
        input_path=Path("i"), output_path=Path("o"), stdout_path=Path("so"), stderr_path=Path("se"),
    )


def _stage_ctx(tmp, docker, agent_runner, **option_overrides):
    """A StageContext over a throwaway worktree with a POV tree already staged."""
    from security_pipeline.models import ExperimentConfig, PipelineState, RunOptions
    from security_pipeline.stages import StageContext

    worktree = Path(tmp)
    pov_dir = worktree / ".security-pipeline" / "pov"
    pov_dir.mkdir(parents=True, exist_ok=True)
    (pov_dir / "pov.sh").write_text("#!/usr/bin/env bash\n")

    project = ProjectMetadata(
        project_slug="s", cve_id="", cwe_id="", cwe_name="", github_url="", github_tag="",
        buggy_commit_id="", fix_commit_ids="", source_path=worktree, dockerfile_path=worktree,
        build_system="maven", build_command="mvn package", test_command="mvn test",
    )
    options = RunOptions(
        workspace_root=worktree, alerts_dir=worktree, runs_dir=worktree,
        command_timeout_seconds=10, **option_overrides,
    )
    ctx = StageContext(
        options=options, experiment=ExperimentConfig(), agent_runner=agent_runner,
        alert={}, project=project, finding_id="finding-1", run_dir=worktree,
        worktree_path=worktree, state=PipelineState(run_id="t", alert_path=Path("a")),
        persist=lambda: None,
    )
    ctx.docker = docker
    ctx.base_context = {}
    return ctx


def _result_stdout(message: str, *, terminal_reason: str = "api_error",
                   stop_reason: str = "stop_sequence") -> str:
    """A terminal CLI result object like the one raw_stdout carries."""
    return json.dumps({
        "type": "result", "is_error": True, "subtype": "success",
        "terminal_reason": terminal_reason, "stop_reason": stop_reason,
        "result": message,
    })


def _agent(exit_code: int, raw_stdout: str = "", refused: bool = False,
           parse_error=None) -> AgentResult:
    return AgentResult(
        agent_name="patcher", parsed_output={} if exit_code else {"status": "patched"},
        raw_stdout=raw_stdout, raw_stderr="", exit_code=exit_code,
        input_path=Path("i"), output_path=Path("o"), stdout_path=Path("so"), stderr_path=Path("se"),
        parse_error=parse_error or ("claude exited with code 1" if exit_code else None),
        refused=refused, refusal_reason=("refused" if refused else None),
    )


class TransientApiErrorDetectionTests(unittest.TestCase):
    def test_flags_content_filter_and_connection_drop(self) -> None:
        from security_pipeline.claude_agents import detect_transient_api_error, is_content_filter_error

        cf = detect_transient_api_error(_result_stdout("API Error: Output blocked by content filtering policy"))
        self.assertIsNotNone(cf)
        self.assertTrue(is_content_filter_error(cf))

        drop = detect_transient_api_error(_result_stdout("API Error: Connection closed mid-response."))
        self.assertIsNotNone(drop)
        self.assertFalse(is_content_filter_error(drop))

    def test_ignores_refusal_clean_result_and_plain_crash(self) -> None:
        from security_pipeline.claude_agents import detect_transient_api_error

        # A cyber-safety refusal is a policy verdict, never retried here.
        self.assertIsNone(detect_transient_api_error(
            _result_stdout("Cyber Verification Program", terminal_reason="", stop_reason="refusal")))
        # api_error but not a known-transient message -> not retried.
        self.assertIsNone(detect_transient_api_error(_result_stdout("API Error: invalid request")))
        # No terminal api_error at all.
        self.assertIsNone(detect_transient_api_error(json.dumps({"type": "result", "result": "ok"})))
        # Unparseable output.
        self.assertIsNone(detect_transient_api_error("not json"))


class ApiErrorRetryTests(unittest.TestCase):
    """A transient API failure re-rolls the same model instead of killing the run."""

    def _runner(self, attempts, **opts):
        from security_pipeline.claude_agents import ClaudeAgentRunner
        from security_pipeline.models import RunOptions

        options = RunOptions(
            workspace_root=Path("."), alerts_dir=Path("."), runs_dir=Path("."), **opts,
        )
        runner = ClaudeAgentRunner(options, package_root=Path("."))
        queued = list(attempts)
        seen = []

        def fake_invoke(agent_name, task, run_dir, worktree_path, io_name):
            seen.append((io_name, task))
            return queued.pop(0)

        runner._invoke = fake_invoke  # type: ignore[assignment]
        return runner, seen

    def test_content_filter_then_success_reruls_with_minimal_edits_note(self) -> None:
        from security_pipeline.claude_agents import RETRY_MINIMAL_EDITS_NOTE

        blocked = _agent(1, _result_stdout("API Error: Output blocked by content filtering policy"))
        runner, seen = self._runner([blocked, _agent(0)], max_api_error_attempts=2)
        resets = []
        result = runner.run("patcher", "TASK", Path("r"), Path("w"),
                            on_retry_reset=lambda: resets.append(True))

        self.assertTrue(result.ok)
        self.assertEqual([s[0] for s in seen], ["patcher", "patcher_apierr_a2"])
        self.assertEqual(seen[0][1], "TASK")                       # first attempt untouched
        self.assertTrue(seen[1][1].endswith(RETRY_MINIMAL_EDITS_NOTE))  # retry steered
        self.assertEqual(len(resets), 1)                           # partial edits wiped once
        # The retry history rides on the returned result -> state.json -> dashboard.
        self.assertEqual(len(result.api_error_attempts), 1)
        self.assertIn("content filter", result.api_error_attempts[0].lower())

    def test_happy_path_records_no_retry_history(self) -> None:
        runner, seen = self._runner([_agent(0)], max_api_error_attempts=2)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertTrue(result.ok)
        self.assertEqual(len(seen), 1)
        self.assertEqual(result.api_error_attempts, ())            # empty on the common path

    def test_connection_drop_retries_without_note(self) -> None:
        dropped = _agent(1, _result_stdout("API Error: Connection closed mid-response."))
        runner, seen = self._runner([dropped, _agent(0)], max_api_error_attempts=2)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertTrue(result.ok)
        self.assertEqual(seen[1][1], "TASK")   # connection drop: identical re-roll, no note

    def test_refusal_is_not_retried(self) -> None:
        refusal = _agent(1, _result_stdout("Cyber Verification Program",
                                           terminal_reason="", stop_reason="refusal"), refused=True)
        runner, seen = self._runner([refusal, _agent(0)], max_api_error_attempts=3)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertTrue(result.refused)
        self.assertEqual(len(seen), 1)         # policy refusal: no re-roll

    def test_plain_crash_is_not_retried(self) -> None:
        crash = _agent(1, "segfault, no json")
        runner, seen = self._runner([crash, _agent(0)], max_api_error_attempts=3)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertFalse(result.ok)
        self.assertEqual(len(seen), 1)

    def test_budget_exhausted_returns_last_failure(self) -> None:
        blocked = _agent(1, _result_stdout("API Error: Output blocked by content filtering policy"))
        runner, seen = self._runner([blocked, blocked], max_api_error_attempts=2)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertFalse(result.ok)
        self.assertEqual([s[0] for s in seen], ["patcher", "patcher_apierr_a2"])

    def test_budget_of_one_disables_retry(self) -> None:
        blocked = _agent(1, _result_stdout("API Error: Output blocked by content filtering policy"))
        runner, seen = self._runner([blocked], max_api_error_attempts=1)
        result = runner.run("patcher", "TASK", Path("r"), Path("w"))
        self.assertFalse(result.ok)
        self.assertEqual(len(seen), 1)         # 1 == old one-shot behaviour

    def test_patcher_reset_degrades_to_none_without_a_git_worktree(self) -> None:
        # StageContext hands run() this reset; when the tree has no git index the
        # snapshot is impossible and the retry must still proceed (reset -> None).
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _stage_ctx(tmp, docker=None, agent_runner=None)
            self.assertIsNone(ctx.patcher_retry_reset())


class ExploiterRetryTests(unittest.TestCase):
    """A POV that does not reproduce goes back to the exploiter, not to a verdict."""

    def test_retries_exploiter_until_the_pov_reproduces(self) -> None:
        from security_pipeline.stages import ExploiterStage

        with tempfile.TemporaryDirectory() as tmp:
            pov = Path(tmp) / ".security-pipeline" / "pov" / "pov.sh"
            docker = _FakeDocker([
                _cmd(1),  # attempt 1: POV does not reproduce -> back to the exploiter
                _cmd(0),  # attempt 2: POV reproduces
            ])
            agents = _FakeAgentRunner([
                _exploiter_agent(pov, "./pov.sh"),
                _exploiter_agent(pov, "./pov2.sh"),
            ])
            ctx = _stage_ctx(tmp, docker, agents, max_exploit_attempts=2)

            with mock.patch("security_pipeline.stages.write_diffs"):
                ExploiterStage().run(ctx)

            self.assertEqual(agents.calls, ["exploiter", "exploiter_retry_a2"])
            # Each attempt keeps its own docker log instead of overwriting.
            self.assertEqual(docker.calls, ["pov_before_patch", "pov_before_patch_a2"])
            self.assertEqual(ctx.pov_command, "./pov2.sh")
            self.assertEqual(ctx.protected_pov_commands, ["./pov2.sh"])
            statuses = [(s["name"], s["status"]) for s in ctx.state.steps]
            self.assertIn(("exploit_retry", "retry"), statuses)
            self.assertIn(("pov_before_patch", "ok"), statuses)

    def test_one_shot_budget_rejects_without_retrying(self) -> None:
        from security_pipeline.stages import ExploiterStage, StageError

        with tempfile.TemporaryDirectory() as tmp:
            pov = Path(tmp) / ".security-pipeline" / "pov" / "pov.sh"
            docker = _FakeDocker([_cmd(1)])
            agents = _FakeAgentRunner([_exploiter_agent(pov, "./pov.sh")])
            ctx = _stage_ctx(tmp, docker, agents, max_exploit_attempts=1)

            with mock.patch("security_pipeline.stages.write_diffs"):
                with self.assertRaises(StageError) as caught:
                    ExploiterStage().run(ctx)

            self.assertEqual(caught.exception.category, "agent_failure")
            self.assertEqual(agents.calls, ["exploiter"])

    def test_invalid_exploiter_output_is_fed_back(self) -> None:
        from security_pipeline.stages import ExploiterStage

        with tempfile.TemporaryDirectory() as tmp:
            pov = Path(tmp) / ".security-pipeline" / "pov" / "pov.sh"
            docker = _FakeDocker([_cmd(0)])
            agents = _FakeAgentRunner([
                _exploiter_agent(pov, "./pov.sh", status="no_pov"),  # fails the gate
                _exploiter_agent(pov, "./pov.sh"),
            ])
            ctx = _stage_ctx(tmp, docker, agents, max_exploit_attempts=2)

            with mock.patch("security_pipeline.stages.write_diffs"):
                ExploiterStage().run(ctx)

            self.assertEqual(agents.calls, ["exploiter", "exploiter_retry_a2"])
            # A rejected output never reaches the container.
            self.assertEqual(docker.calls, ["pov_before_patch_a2"])
            retry = next(s for s in ctx.state.steps if s["name"] == "exploit_retry")
            self.assertEqual(retry["failing"], "pov_output_invalid")


class PovIntegrityGuardTests(unittest.TestCase):
    """The guard must measure one patcher run — and repair, not reject.

    Both regressions covered here rejected real runs: a patcher that only re-ran
    the POV to self-verify (its compiler output landed in the POV tree), and a
    patcher blamed one stage later for POV files the *exploiter* had legitimately
    added during a hardening round that exited without re-baselining.
    """

    def _patcher_ctx(self, tmp, docker, agents, **overrides):
        ctx = _stage_ctx(tmp, docker, agents, **overrides)
        ctx.pov_command = "./pov.sh"
        ctx.protected_pov_commands = ["./pov.sh"]
        return ctx

    @staticmethod
    def _pov_step(ctx):
        return next((s for s in ctx.state.steps if s["name"] == "pov_guard"), None)

    def test_patcher_recompiling_the_pov_is_not_tampering(self) -> None:
        from security_pipeline.stages import PatcherStage

        def ran_the_pov(worktree: Path) -> None:
            # `javac .security-pipeline/pov/Pov.java` — no -d, output beside the source.
            (worktree / ".security-pipeline/pov/Pov.class").write_bytes(b"\xca\xfe\xba\xbe")

        with tempfile.TemporaryDirectory() as tmp:
            agents = _FakeAgentRunner([(_patcher_agent(["mvn test"]), ran_the_pov)])
            ctx = self._patcher_ctx(tmp, _FakeDocker([]), agents)

            with mock.patch("security_pipeline.stages.write_diffs"), mock.patch(
                "security_pipeline.stages.collect_patch_only_diff", return_value="diff"
            ):
                PatcherStage().run(ctx)

            self.assertIsNone(self._pov_step(ctx))
            self.assertEqual(ctx.regression_commands, ["mvn test"])

    def test_patcher_editing_the_pov_is_reverted_not_rejected(self) -> None:
        from security_pipeline.stages import PatcherStage

        def neutered_the_pov(worktree: Path) -> None:
            (worktree / ".security-pipeline/pov/pov.sh").write_text("exit 1\n")

        with tempfile.TemporaryDirectory() as tmp:
            agents = _FakeAgentRunner([(_patcher_agent(["mvn test"]), neutered_the_pov)])
            ctx = self._patcher_ctx(tmp, _FakeDocker([]), agents)
            pov = ctx.pov_root() / "pov.sh"
            original = pov.read_text()

            with mock.patch("security_pipeline.stages.write_diffs"), mock.patch(
                "security_pipeline.stages.collect_patch_only_diff", return_value="diff"
            ):
                PatcherStage().run(ctx)  # the run survives...

            self.assertEqual(pov.read_text(), original)  # ...against the real POV
            step = self._pov_step(ctx)
            self.assertIsNotNone(step)
            self.assertEqual(step["status"], "restored")
            self.assertEqual(step["agent"], "patcher")
            self.assertEqual(step["paths"], ["pov.sh"])

    def test_pov_added_by_the_exploiter_is_not_blamed_on_the_next_patcher(self) -> None:
        # The hardening loop only re-baselined on the confirmed-bypass path, so a
        # round that exited via "stable" left the exploiter's new variant files
        # looking like tampering at the next gate that re-patches.
        from security_pipeline.stages import RegressionStage

        with tempfile.TemporaryDirectory() as tmp:
            docker = _FakeDocker([
                _cmd(1),                       # attempt 1: POV blocked
                _cmd(1, ["mvn", "test"]),      # attempt 1: regression fails -> re-patch
                _cmd(0, ["mvn", "package"]),   # attempt 1: mandatory build check passes
                _cmd(1),                       # attempt 2: POV still blocked
                _cmd(0, ["mvn", "test"]),      # attempt 2: regression passes
                _cmd(0, ["mvn", "package"]),   # attempt 2: mandatory build check passes
            ])
            agents = _FakeAgentRunner([_patcher_agent(["mvn test"])])
            ctx = self._patcher_ctx(tmp, docker, agents, max_correction_attempts=2)
            ctx.patcher_output = {"status": "patched"}
            ctx.regression_commands = ["mvn test"]
            ctx.baseline_pov()

            # A hardening round's exploiter authors a bypass variant, then the round
            # exits "stable" (the variant did not bypass / none was found).
            variant = ctx.pov_root() / "BypassPov.java"
            variant.write_text("class BypassPov {}")

            with mock.patch("security_pipeline.stages.write_diffs"):
                RegressionStage().run(ctx)

            self.assertEqual(agents.calls, ["patcher_correction_regression_a2"])
            self.assertIsNone(self._pov_step(ctx))
            self.assertTrue(variant.exists())  # the exploiter's work is not clobbered


class PovAfterCorrectionTests(unittest.TestCase):
    """The standalone POV-after gate (hardening profile) re-patches, not rejects."""

    def test_pov_still_reproducing_goes_back_to_the_patcher(self) -> None:
        from security_pipeline.stages import PovAfterStage

        with tempfile.TemporaryDirectory() as tmp:
            docker = _FakeDocker([
                _cmd(0),  # POV still reproduces -> re-patch
                _cmd(1),  # blocked after the correction
            ])
            agents = _FakeAgentRunner([_patcher_agent(["mvn test"])])
            ctx = _stage_ctx(tmp, docker, agents, max_correction_attempts=2)
            ctx.pov_command = "./pov.sh"
            ctx.protected_pov_commands = ["./pov.sh"]
            ctx.pov_hash_before = hash_path_tree(ctx.pov_root())
            ctx.patcher_output = {"status": "patched"}

            with mock.patch("security_pipeline.stages.write_diffs"):
                PovAfterStage().run(ctx)

            self.assertEqual(agents.calls, ["patcher_correction_pov_after_a2"])
            self.assertEqual(docker.calls, ["pov_after_patch", "pov_after_patch"])
            self.assertEqual(ctx.pov_after.exit_code, 1)
            retry = next(
                s for s in ctx.state.steps if s["name"] == "correction" and s["status"] == "retry"
            )
            self.assertEqual(retry["stage"], "pov_after")
            # The regression gate has not run yet — that is a later stage.
            self.assertNotIn("patch_and_regression", [s["name"] for s in ctx.state.steps])


class CorrectionLoopTests(unittest.TestCase):
    """The self-correction fix-point over the POV-after + regression predicates."""

    def _ctx(self, tmp, docker, agent_runner, *, attempts, regression_commands):
        ctx = _stage_ctx(tmp, docker, agent_runner, max_correction_attempts=attempts)
        ctx.pov_command = "./pov.sh"
        ctx.protected_pov_commands = ["./pov.sh"]
        ctx.pov_hash_before = hash_path_tree(ctx.pov_root())
        ctx.patcher_output = {"status": "patched"}
        ctx.regression_commands = list(regression_commands)
        return ctx

    def test_one_shot_rejects_without_re_patching(self) -> None:
        # Budget 1 == the old gates: a still-reproducing POV rejects immediately.
        from security_pipeline.stages import PatchCorrectionLoop, StageError, pov_blocked_predicate, regressions_pass_predicate

        with tempfile.TemporaryDirectory() as tmp:
            docker = _FakeDocker([_cmd(0)])  # POV still reproduces
            agents = _FakeAgentRunner([])
            ctx = self._ctx(tmp, docker, agents, attempts=1, regression_commands=["mvn test"])

            with mock.patch("security_pipeline.stages.write_diffs"):
                with self.assertRaises(StageError) as caught:
                    PatchCorrectionLoop().converge(
                        ctx, [pov_blocked_predicate(), regressions_pass_predicate()]
                    )

            self.assertEqual(caught.exception.category, "agent_failure")
            self.assertEqual(agents.calls, [])  # the patcher was never re-invoked
            self.assertEqual(docker.calls, ["pov_after_patch"])  # regression not reached

    def test_retries_patcher_until_pov_is_blocked(self) -> None:
        from security_pipeline.stages import PatchCorrectionLoop, pov_blocked_predicate, regressions_pass_predicate

        with tempfile.TemporaryDirectory() as tmp:
            docker = _FakeDocker([
                _cmd(0),                       # attempt 1: POV still reproduces -> re-patch
                _cmd(1),                       # attempt 2: POV blocked
                _cmd(0, ["mvn", "test"]),      # attempt 2: regression passes
                _cmd(0, ["mvn", "package"]),   # attempt 2: mandatory build check passes
            ])
            agents = _FakeAgentRunner([_patcher_agent(["mvn test"])])
            ctx = self._ctx(tmp, docker, agents, attempts=2, regression_commands=["mvn test"])

            with mock.patch("security_pipeline.stages.write_diffs"):
                PatchCorrectionLoop().converge(
                    ctx, [pov_blocked_predicate(), regressions_pass_predicate()]
                )

            self.assertEqual(agents.calls, ["patcher_correction_a2"])
            self.assertEqual(ctx.pov_after.exit_code, 1)
            statuses = [(s["name"], s["status"]) for s in ctx.state.steps]
            self.assertIn(("correction", "retry"), statuses)
            self.assertIn(("correction", "converged"), statuses)

    def test_correcting_patcher_cannot_shrink_the_regression_set(self) -> None:
        from security_pipeline.stages import PatchCorrectionLoop, pov_blocked_predicate, regressions_pass_predicate

        with tempfile.TemporaryDirectory() as tmp:
            docker = _FakeDocker([
                _cmd(1),                       # attempt 1: POV blocked
                _cmd(0, ["testA"]),            # attempt 1: testA passes
                _cmd(1, ["testB"]),            # attempt 1: testB fails -> re-patch
                _cmd(0, ["mvn", "package"]),   # attempt 1: mandatory build check passes
                _cmd(1),                       # attempt 2: POV blocked
                _cmd(0, ["testA"]),            # attempt 2: testA passes
                _cmd(0, ["testB"]),            # attempt 2: testB passes
                _cmd(0, ["mvn", "package"]),   # attempt 2: mandatory build check passes
            ])
            # The re-patch tries to drop testB (the failing test) from its set.
            agents = _FakeAgentRunner([_patcher_agent(["testA"])])
            ctx = self._ctx(tmp, docker, agents, attempts=2, regression_commands=["testA", "testB"])

            with mock.patch("security_pipeline.stages.write_diffs"):
                PatchCorrectionLoop().converge(
                    ctx, [pov_blocked_predicate(), regressions_pass_predicate()]
                )

            # testB survived the shrink attempt and was still enforced.
            self.assertIn("testB", ctx.regression_commands)


class EnsureBuildCheckedTests(unittest.TestCase):
    """`_ensure_build_checked` guarantees a full-project build is always part of
    the regression gate, without forcing an expensive `clean` rebuild onto every
    correction attempt or duplicating a command the patcher already proposed.
    """

    @staticmethod
    def _ctx_with_build_command(build_command: str):
        import types

        project = ProjectMetadata(
            project_slug="s", cve_id="", cwe_id="", cwe_name="", github_url="", github_tag="",
            buggy_commit_id="", fix_commit_ids="", source_path=Path("."), dockerfile_path=Path("."),
            build_system="unknown", build_command=build_command, test_command="",
        )
        return types.SimpleNamespace(project=project)

    def test_appends_the_project_build_command_when_missing(self) -> None:
        from security_pipeline.stages import _ensure_build_checked

        ctx = self._ctx_with_build_command("make CFLAGS=-fsanitize=address")
        result = _ensure_build_checked(["make -C bfd elf64-x86-64.lo"], ctx)

        self.assertEqual(
            result, ["make -C bfd elf64-x86-64.lo", "make CFLAGS=-fsanitize=address"]
        )

    def test_skips_a_build_command_containing_clean(self) -> None:
        # `gradle ... clean build` is a real per-project default (see metadata.py).
        # Forcing that onto every correction attempt would throw away incremental
        # build state and cost minutes per check -- exactly what agent_guard.py
        # already blocks agents from doing themselves.
        from security_pipeline.stages import _ensure_build_checked

        ctx = self._ctx_with_build_command("./gradlew --no-daemon clean build -x test")
        result = _ensure_build_checked(["mvn test"], ctx)

        self.assertEqual(result, ["mvn test"])

    def test_skips_when_build_command_is_empty(self) -> None:
        from security_pipeline.stages import _ensure_build_checked

        ctx = self._ctx_with_build_command("")
        result = _ensure_build_checked(["mvn test"], ctx)

        self.assertEqual(result, ["mvn test"])

    def test_does_not_duplicate_a_command_the_patcher_already_proposed(self) -> None:
        from security_pipeline.stages import _ensure_build_checked

        ctx = self._ctx_with_build_command("mvn   package")  # extra whitespace
        result = _ensure_build_checked(["mvn test", "mvn package"], ctx)

        self.assertEqual(result, ["mvn test", "mvn package"])


class ParallelRunTests(unittest.TestCase):
    def test_concurrent_runs_never_share_a_run_directory(self) -> None:
        # `run --jobs N` calls run_alert from several threads. Two alerts landing
        # on the same run id in the same second must still get distinct dirs, or
        # they would overwrite each other's artifacts.
        from concurrent.futures import ThreadPoolExecutor

        from security_pipeline.pipeline import claim_run_dir

        with tempfile.TemporaryDirectory() as tmp:
            runs_dir = Path(tmp)
            with ThreadPoolExecutor(max_workers=8) as pool:
                claimed = list(pool.map(lambda _: claim_run_dir(runs_dir, "20990101_000000_finding-a"), range(24)))

            self.assertEqual(len(set(claimed)), 24)
            self.assertTrue(all(path.is_dir() for path in claimed))


class WorkspaceTests(unittest.TestCase):
    def test_create_worktree_makes_isolated_git_repo_without_source_path_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "owner__repo_CVE-2099-0001_1.0.0"
            source.mkdir()
            (source / "README.md").write_text("hello\n")
            self._git(source, "init", "-q")
            self._git(source, "add", "-A")
            self._git(
                source,
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-q",
                "--no-gpg-sign",
                "-m",
                "baseline",
            )

            worktree = create_worktree(source, root / "runs/finding-abc123")

            self.assertTrue((worktree / ".git").is_dir())
            self.assertFalse((worktree / ".git").is_file())
            git_files = "\n".join(
                path.read_text(errors="ignore")
                for path in (worktree / ".git").rglob("*")
                if path.is_file()
            )
            self.assertNotIn("CVE-2099-0001", git_files)
            (worktree / "README.md").write_text("changed\n")
            diff = self._git(worktree, "diff").stdout
            self.assertIn("-hello", diff)

    @staticmethod
    def _git(cwd: Path, *args: str):
        import subprocess

        result = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return result


class AgentIsolationTests(unittest.TestCase):
    """What an agent is allowed to reach, and how the argv is assembled."""

    def _runner(self, **overrides):
        from security_pipeline.claude_agents import ClaudeAgentRunner
        from security_pipeline.models import RunOptions

        options = RunOptions(
            workspace_root=Path("."), alerts_dir=Path("."), runs_dir=Path("."), **overrides
        )
        return ClaudeAgentRunner(options, Path("security_pipeline"))

    def _command(self, **overrides):
        return self._runner(**overrides).build_command(
            "patcher", Path("/tmp/run"), Path("/tmp/settings.json")
        )

    def test_web_tools_are_denied(self) -> None:
        # The pipeline redacts the CVE from every agent so the experiment measures
        # repair from an alert, not recall of a public advisory. An exploiter once
        # web-searched its way to the CVE *and its official fix commit*, which also
        # contaminates that run's fixPOV score.
        from security_pipeline.claude_agents import DISALLOWED_TOOLS

        for tool in ("WebSearch", "WebFetch"):
            self.assertIn(tool, DISALLOWED_TOOLS)

    def test_background_and_scheduling_tools_are_denied(self) -> None:
        from security_pipeline.claude_agents import DISALLOWED_TOOLS

        for tool in ("Task", "ScheduleWakeup", "Monitor", "TaskOutput", "ToolSearch"):
            self.assertIn(tool, DISALLOWED_TOOLS)

    def test_disallowed_tools_is_not_the_last_flag(self) -> None:
        # --disallowed-tools is variadic: every argv entry after it is eaten as
        # another tool name until the next flag. Last-position would silently
        # swallow whatever argv element follows it.
        command = self._command()
        flag = command.index("--disallowed-tools")
        self.assertTrue(command[flag + 2].startswith("--"), command[flag : flag + 3])

    def test_command_does_not_carry_the_prompt(self) -> None:
        # The task prompt is piped over stdin (_run_blocking/_run_streaming), not
        # appended to argv: a single argv string is capped at MAX_ARG_STRLEN (128
        # KiB) on Linux, well below what an unclipped alert can reach — a run
        # crashed with "OSError: [Errno 7] Argument list too long" on a 174 KB
        # prompt before this was fixed.
        command = self._command()
        self.assertNotIn("THE PROMPT", command)

    def test_does_not_inherit_operator_or_project_settings(self) -> None:
        # `--settings` only ADDS a source. With --setting-sources omitted the CLI
        # loads user + project + local, so the agent picked up both the operator's
        # ~/.claude settings and the analyzed project's own .claude/settings.json
        # (agents run with the worktree as cwd). An explicitly empty list is what
        # loads none of them.
        command = self._command()
        self.assertEqual(command[command.index("--setting-sources") + 1], "")
        self.assertIn("--strict-mcp-config", command)
        self.assertIn("--settings", command)

    def test_pipeline_settings_are_still_passed_explicitly(self) -> None:
        command = self._command()
        self.assertEqual(command[command.index("--settings") + 1], "/tmp/settings.json")

    def test_model_is_always_pinned(self) -> None:
        from security_pipeline.claude_agents import DEFAULT_AGENT_MODEL

        command = self._command()
        self.assertEqual(command[command.index("--model") + 1], DEFAULT_AGENT_MODEL)
        override = self._command(model="claude-haiku-4-5")
        self.assertEqual(override[override.index("--model") + 1], "claude-haiku-4-5")

    def test_openrouter_retains_stream_for_billed_cost_reconciliation(self) -> None:
        command = self._command(model="deepseek/deepseek-v4-flash")
        self.assertEqual(command[command.index("--output-format") + 1], "stream-json")
        self.assertIn("--include-partial-messages", command)

    def test_settings_wire_up_the_bash_guard_hook(self) -> None:
        from security_pipeline.claude_agents import agent_settings

        hooks = agent_settings(Path("security_pipeline"))["hooks"]["PreToolUse"]
        self.assertEqual(hooks[0]["matcher"], "Bash")
        self.assertIn("agent_guard.py", hooks[0]["hooks"][0]["command"])


class ZaiRoutingTests(unittest.TestCase):
    """Selecting a GLM model routes the run through Z.ai's Anthropic-compatible
    endpoint. Agents run with `--setting-sources ""`, so ~/.claude/settings.json
    is never read — the config has to ride in the pipeline-owned settings file
    and the subprocess env, and the credential must stay out of run artifacts."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.settings = self.tmp / "settings-zai.json"
        self._write(
            {
                "env": {
                    "ANTHROPIC_AUTH_TOKEN": "real-key-123",
                    "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
                    "API_TIMEOUT_MS": "3000000",
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-4.5-air",
                    "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-4.7",
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-4.7",
                }
            }
        )
        patcher = mock.patch.dict(
            "os.environ", {"P2PATCH_ZAI_SETTINGS": str(self.settings)}, clear=False
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, payload) -> None:
        self.settings.write_text(json.dumps(payload), encoding="utf-8")

    def test_recognizes_only_the_glm_models(self) -> None:
        from security_pipeline.zai import is_zai_model

        self.assertTrue(is_zai_model("glm-5.1"))
        self.assertTrue(is_zai_model("GLM-5.2"))
        self.assertFalse(is_zai_model("sonnet"))
        self.assertFalse(is_zai_model(""))
        self.assertFalse(is_zai_model(None))

    def test_alias_slots_retarget_the_selected_model(self) -> None:
        from security_pipeline.zai import zai_env

        env = zai_env("glm-5.2")
        self.assertEqual(env["ANTHROPIC_DEFAULT_OPUS_MODEL"], "glm-5.2")
        self.assertEqual(env["ANTHROPIC_DEFAULT_SONNET_MODEL"], "glm-5.2")
        # Including the background-turn slot, so a GLM run is single-model
        # rather than silently splitting onto the file's stock "air" model.
        self.assertEqual(env["ANTHROPIC_DEFAULT_HAIKU_MODEL"], "glm-5.2")
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "https://api.z.ai/api/anthropic")
        self.assertEqual(
            zai_env("glm-5.1"),
            {
                "ANTHROPIC_AUTH_TOKEN": "real-key-123",
                "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic",
                "API_TIMEOUT_MS": "3000000",
                "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-5.1",
                "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-5.1",
                "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-5.1",
            },
        )

    def test_placeholder_key_is_rejected_before_the_run_starts(self) -> None:
        from security_pipeline.zai import ZaiConfigError, zai_env

        self._write({"env": {"ANTHROPIC_AUTH_TOKEN": "your_zai_api_key",
                             "ANTHROPIC_BASE_URL": "https://api.z.ai/api/anthropic"}})
        with self.assertRaises(ZaiConfigError):
            zai_env("glm-5.2")

    def test_missing_base_url_is_rejected(self) -> None:
        from security_pipeline.zai import ZaiConfigError, zai_env

        self._write({"env": {"ANTHROPIC_AUTH_TOKEN": "real-key-123"}})
        with self.assertRaises(ZaiConfigError):
            zai_env("glm-5.2")

    def test_missing_settings_file_is_rejected(self) -> None:
        from security_pipeline.zai import ZaiConfigError, zai_env

        self.settings.unlink()
        with self.assertRaises(ZaiConfigError):
            zai_env("glm-5.2")

    def test_credentials_never_reach_the_persisted_settings_file(self) -> None:
        from security_pipeline.claude_agents import agent_settings
        from security_pipeline.zai import zai_settings_env

        env = zai_settings_env("glm-5.2")
        # Omitted, not redacted: the CLI applies this file's env over the
        # process env, so a placeholder here would clobber the real token.
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
        self.assertIn("ANTHROPIC_BASE_URL", env)

        settings = agent_settings(Path("security_pipeline"), "glm-5.2")
        self.assertNotIn("real-key-123", json.dumps(settings))
        self.assertEqual(settings["env"]["ANTHROPIC_DEFAULT_OPUS_MODEL"], "glm-5.2")
        # The Bash guard still applies to a GLM run.
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["matcher"], "Bash")

    def test_claude_models_get_no_env_block(self) -> None:
        from security_pipeline.claude_agents import agent_settings

        self.assertNotIn("env", agent_settings(Path("security_pipeline"), "sonnet"))
        self.assertNotIn("env", agent_settings(Path("security_pipeline")))

    def test_process_env_carries_the_token_and_drops_host_anthropic_vars(self) -> None:
        from security_pipeline.zai import zai_process_env

        env = zai_process_env(
            "glm-5.2",
            base={"PATH": "/usr/bin", "ANTHROPIC_API_KEY": "host-key", "API_TIMEOUT_MS": "10"},
        )
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "real-key-123")
        self.assertEqual(env["PATH"], "/usr/bin")
        # A host configured for normal Claude use must not half-authenticate the run.
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual(env["API_TIMEOUT_MS"], "3000000")

    def test_runner_passes_glm_env_to_the_subprocess(self) -> None:
        from security_pipeline.claude_agents import ClaudeAgentRunner

        runner = ClaudeAgentRunner.__new__(ClaudeAgentRunner)
        runner.options = SimpleNamespace(model="glm-5.2")
        env = runner._agent_env()
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "https://api.z.ai/api/anthropic")

        runner.options = SimpleNamespace(model="sonnet")
        # None == inherit, the historical behaviour for a Claude model.
        self.assertIsNone(runner._agent_env())


class OpenRouterRoutingTests(unittest.TestCase):
    """DeepSeek V4 Flash uses OpenRouter only for the selected run, while the
    API key stays out of the persisted per-agent settings artifact."""

    MODEL = "deepseek/deepseek-v4-flash"

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.settings = self.tmp / "settings-openrouter.json"
        self._write({"env": {"OPENROUTER_API_KEY": "sk-or-real-key"}})
        patcher = mock.patch.dict(
            "os.environ",
            {"P2PATCH_OPENROUTER_SETTINGS": str(self.settings)},
            clear=False,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _write(self, payload) -> None:
        self.settings.write_text(json.dumps(payload), encoding="utf-8")

    def test_recognizes_only_the_configured_openrouter_model(self) -> None:
        from security_pipeline.openrouter import is_openrouter_model

        self.assertTrue(is_openrouter_model(self.MODEL))
        self.assertTrue(is_openrouter_model(self.MODEL.upper()))
        self.assertTrue(is_openrouter_model("openai/gpt-5.6-luna"))
        self.assertFalse(is_openrouter_model("deepseek/deepseek-v4-pro"))
        # A real OpenRouter slug that is not on the allowlist stays unrouted:
        # selecting a sibling variant must not silently repoint a run.
        self.assertFalse(is_openrouter_model("openai/gpt-5.6-luna-pro"))
        self.assertFalse(is_openrouter_model("sonnet"))
        self.assertFalse(is_openrouter_model(None))

    def test_the_two_glm_routes_do_not_claim_each_others_slug(self) -> None:
        """GLM 5.2/5.3 are selectable on two routes; each owns exactly one slug.

        `z-ai/glm-5.x` goes through OpenRouter (billed cost reconcilable),
        `glm-5.x` goes direct to Z.ai; a run must never be silently re-routed
        because the two names describe the same model.
        """
        from security_pipeline.openrouter import is_openrouter_model
        from security_pipeline.zai import is_zai_model

        for direct, routed in (("glm-5.2", "z-ai/glm-5.2"), ("glm-5.3", "z-ai/glm-5.3")):
            self.assertTrue(is_openrouter_model(routed))
            self.assertFalse(is_zai_model(routed))
            self.assertTrue(is_zai_model(direct))
            self.assertFalse(is_openrouter_model(direct))

    def test_glm52_floor_is_pinned_to_the_streamlake_fp8_preset(self) -> None:
        """The legacy cheapest launcher id resolves to one provider endpoint."""
        from security_pipeline.openrouter import (
            GLM52_STREAMLAKE_REQUEST_MODEL,
            is_openrouter_model,
            openrouter_env,
        )

        self.assertTrue(is_openrouter_model("z-ai/glm-5.2:floor"))
        self.assertTrue(is_openrouter_model("z-ai/glm-5.3:floor"))
        self.assertEqual(
            openrouter_env("z-ai/glm-5.2:floor")["ANTHROPIC_DEFAULT_OPUS_MODEL"],
            GLM52_STREAMLAKE_REQUEST_MODEL,
        )
        # Other :floor models keep OpenRouter's ordinary price-sorted routing.
        self.assertEqual(
            openrouter_env("z-ai/glm-5.3:floor")["ANTHROPIC_DEFAULT_OPUS_MODEL"],
            "z-ai/glm-5.3:floor",
        )
        self.assertFalse(is_openrouter_model("z-ai/glm-5.2:nitro"))
        self.assertFalse(is_openrouter_model("z-ai/glm-5.2:free"))

    def test_builds_official_anthropic_skin_and_pins_every_model_slot(self) -> None:
        from security_pipeline.openrouter import openrouter_env

        env = openrouter_env(self.MODEL)
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "https://openrouter.ai/api")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "sk-or-real-key")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "")
        self.assertNotIn("OPENROUTER_API_KEY", env)
        for slot in (
            "ANTHROPIC_DEFAULT_FABLE_MODEL",
            "ANTHROPIC_DEFAULT_OPUS_MODEL",
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "ANTHROPIC_DEFAULT_HAIKU_MODEL",
            "CLAUDE_CODE_SUBAGENT_MODEL",
        ):
            self.assertEqual(env[slot], self.MODEL)

    def test_every_configured_model_routes_and_pins_its_own_slots(self) -> None:
        from security_pipeline.openrouter import (
            ALIAS_SLOTS_FOR_SELECTED_MODEL,
            OPENROUTER_MODELS,
            openrouter_env,
            openrouter_request_model,
        )

        for model in OPENROUTER_MODELS:
            with self.subTest(model=model):
                env = openrouter_env(model)
                self.assertEqual(
                    env["ANTHROPIC_BASE_URL"], "https://openrouter.ai/api"
                )
                self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "sk-or-real-key")
                for slot in ALIAS_SLOTS_FOR_SELECTED_MODEL:
                    self.assertEqual(env[slot], openrouter_request_model(model))

    def test_config_summary_exposes_the_request_facing_preset(self) -> None:
        from security_pipeline.openrouter import (
            GLM52_STREAMLAKE_ENDPOINT,
            GLM52_STREAMLAKE_REQUEST_MODEL,
            describe_openrouter_config,
        )

        summary = describe_openrouter_config("z-ai/glm-5.2:floor")
        self.assertEqual(summary["model"], "z-ai/glm-5.2:floor")
        self.assertEqual(summary["request_model"], GLM52_STREAMLAKE_REQUEST_MODEL)
        self.assertEqual(summary["provider_endpoint"], GLM52_STREAMLAKE_ENDPOINT)
        self.assertEqual(GLM52_STREAMLAKE_ENDPOINT, "streamlake/fp8")

    def test_plain_environment_key_is_also_supported(self) -> None:
        from security_pipeline.openrouter import openrouter_env

        with mock.patch.dict(
            "os.environ",
            {"OPENROUTER_API_KEY": "sk-or-from-env"},
            clear=True,
        ):
            env = openrouter_env(self.MODEL)
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "sk-or-from-env")

    def test_missing_or_placeholder_key_is_rejected_before_launch(self) -> None:
        from security_pipeline.openrouter import OpenRouterConfigError, openrouter_env

        self._write({"env": {"OPENROUTER_API_KEY": "sk-or-your-key"}})
        with self.assertRaises(OpenRouterConfigError):
            openrouter_env(self.MODEL)

        self.settings.unlink()
        with self.assertRaises(OpenRouterConfigError):
            openrouter_env(self.MODEL)

    def test_credentials_never_reach_persisted_agent_settings(self) -> None:
        from security_pipeline.claude_agents import agent_settings
        from security_pipeline.openrouter import openrouter_settings_env

        env = openrouter_settings_env(self.MODEL)
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual(env["ANTHROPIC_BASE_URL"], "https://openrouter.ai/api")

        settings = agent_settings(Path("security_pipeline"), self.MODEL)
        self.assertNotIn("sk-or-real-key", json.dumps(settings))
        self.assertEqual(
            settings["env"]["ANTHROPIC_DEFAULT_SONNET_MODEL"], self.MODEL
        )
        self.assertEqual(settings["hooks"]["PreToolUse"][0]["matcher"], "Bash")

    def test_process_env_is_isolated_and_runner_uses_it(self) -> None:
        from security_pipeline.claude_agents import ClaudeAgentRunner
        from security_pipeline.openrouter import openrouter_process_env

        env = openrouter_process_env(
            self.MODEL,
            base={
                "PATH": "/usr/bin",
                "ANTHROPIC_API_KEY": "host-anthropic-key",
                "OPENROUTER_API_KEY": "host-openrouter-key",
            },
        )
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "sk-or-real-key")
        self.assertEqual(env["ANTHROPIC_API_KEY"], "")
        self.assertNotIn("OPENROUTER_API_KEY", env)

        runner = ClaudeAgentRunner.__new__(ClaudeAgentRunner)
        runner.options = SimpleNamespace(model=self.MODEL)
        self.assertEqual(
            runner._agent_env()["ANTHROPIC_BASE_URL"], "https://openrouter.ai/api"
        )

    def test_extracts_only_structured_unique_generation_ids(self) -> None:
        from security_pipeline.openrouter import openrouter_generation_ids

        stream = self.tmp / "stream.jsonl"
        events = [
            {"type": "assistant", "message": {"id": "gen-12345678", "content": []}},
            {"type": "user", "request_id": "gen-12345678"},
            {"type": "assistant", "event": {"message": {"id": "gen-abcdefgh"}}},
            {
                "type": "assistant",
                "message": {
                    "id": "not-a-generation",
                    "content": [{"type": "text", "text": "ignore gen-proseonly99"}],
                },
            },
        ]
        stream.write_text("\n".join(json.dumps(event) for event in events), encoding="utf-8")

        self.assertEqual(
            openrouter_generation_ids(stream),
            ("gen-12345678", "gen-abcdefgh"),
        )

    def test_reconciles_exact_generation_cost_and_reuses_complete_cache(self) -> None:
        from security_pipeline.openrouter import reconcile_openrouter_cost

        stream = self.tmp / "stream.jsonl"
        stream.write_text(
            "\n".join(
                json.dumps({"request_id": generation_id})
                for generation_id in ("gen-12345678", "gen-abcdefgh")
            ),
            encoding="utf-8",
        )
        output = self.tmp / "provider_cost.json"
        calls = []

        def billed(generation_id: str) -> float:
            calls.append(generation_id)
            return {"gen-12345678": 0.00125, "gen-abcdefgh": 0.00275}[generation_id]

        result = reconcile_openrouter_cost(
            stream,
            output,
            self.MODEL,
            fetch_cost=billed,
        )
        self.assertTrue(result["complete"])
        self.assertEqual(result["generation_count"], 2)
        self.assertEqual(result["resolved_count"], 2)
        self.assertAlmostEqual(result["cost_usd"], 0.004)
        self.assertEqual(set(calls), {"gen-12345678", "gen-abcdefgh"})
        self.assertNotIn("sk-or-real-key", output.read_text(encoding="utf-8"))

        cached = reconcile_openrouter_cost(
            stream,
            output,
            self.MODEL,
            fetch_cost=lambda _generation_id: self.fail("complete cache was ignored"),
        )
        self.assertEqual(cached, result)

    def test_generation_lookup_retries_eventually_consistent_404(self) -> None:
        import urllib.error

        from security_pipeline.openrouter import openrouter_generation_cost

        missing = urllib.error.HTTPError(
            "https://openrouter.ai/api/v1/generation",
            404,
            "not indexed yet",
            None,
            None,
        )
        response = mock.MagicMock()
        response.__enter__.return_value = io.StringIO(
            json.dumps({"data": {"total_cost": 0.0123}})
        )
        with (
            mock.patch(
                "security_pipeline.openrouter.urllib.request.urlopen",
                side_effect=[missing, response],
            ),
            mock.patch("security_pipeline.openrouter.time.sleep") as sleep,
        ):
            cost = openrouter_generation_cost(
                "gen-12345678", "sk-or-real-key", attempts=2
            )

        self.assertEqual(cost, 0.0123)
        sleep.assert_called_once_with(0.5)

    def test_partial_reconciliation_is_explicit_and_not_complete(self) -> None:
        from security_pipeline.openrouter import reconcile_openrouter_cost

        stream = self.tmp / "stream.jsonl"
        stream.write_text(
            "\n".join(
                json.dumps({"request_id": generation_id})
                for generation_id in ("gen-12345678", "gen-abcdefgh")
            ),
            encoding="utf-8",
        )

        def partial(generation_id: str) -> float:
            if generation_id == "gen-abcdefgh":
                raise RuntimeError("temporarily unavailable")
            return 0.00125

        result = reconcile_openrouter_cost(
            stream,
            self.tmp / "provider_cost.json",
            self.MODEL,
            fetch_cost=partial,
        )
        self.assertFalse(result["complete"])
        self.assertEqual(result["generation_count"], 2)
        self.assertEqual(result["resolved_count"], 1)
        self.assertEqual(result["cost_usd"], 0.00125)
        self.assertEqual(len(result["errors"]), 1)


class AgentGuardTests(unittest.TestCase):
    """The PreToolUse hook. Prompt text alone did not hold: across the first 30
    runs agents ran `clean` 44 times and burned 18.5 min polling backgrounded
    builds, both explicitly forbidden."""

    def _check(self, command, **extra):
        from security_pipeline.agent_guard import check

        return check("Bash", {"command": command, **extra})

    def test_blocks_clean_builds(self) -> None:
        for command in (
            "mvn -B clean package",
            "cd repo && ./mvnw clean install -DskipTests",
            "gradle clean build",
            "./gradlew clean test",
        ):
            self.assertIn("clean", self._check(command), command)

    def test_blocks_polling_and_background_work(self) -> None:
        self.assertIn("tail -f", self._check("tail -f /tmp/build.log"))
        self.assertIn("sleep", self._check("sleep 300 && echo done"))
        self.assertIn("Polling", self._check("while true; do echo .; sleep 5; done"))
        self.assertIn("Background", self._check("mvn -B test", run_in_background=True))

    def test_allows_ordinary_work(self) -> None:
        for command in (
            "mvn -B test -Dtest=FooTest#bar",
            "mvn -B -pl core -am package -DskipTests",
            "javac -d .security-pipeline/pov/classes Pov.java",
            "grep -rn cleanPath src/main/java",       # 'clean' inside another word
            "mvn -B test -Dtest=CleanupTest",         # ditto, as a test name
            "rm -rf target/classes && mvn -B compile",  # targeted, not `clean`
            "sleep 3 && curl localhost:8080",         # short wait for a server
        ):
            self.assertEqual(self._check(command), "", command)

    def test_ignores_non_bash_tools(self) -> None:
        from security_pipeline.agent_guard import check

        self.assertEqual(check("Read", {"file_path": "/x/mvn clean"}), "")

    def test_blocks_network_egress_to_the_advisory_and_fix(self) -> None:
        # The exact routes seen contaminating real runs: GitHub API/raw, the fix
        # commit .patch, source tarballs, advisory DBs, web search, git fetch,
        # python urllib, and package installs.
        for command in (
            'curl -s "https://api.github.com/search/commits?q=repo:vert-x3/vertx-web"',
            "curl -sI https://github.com",
            "curl -L https://raw.githubusercontent.com/nahsra/antisamy/master/x.java",
            "git ls-remote https://github.com/apache/sling-org-apache-sling-xss.git",
            "git fetch origin && git log",
            "wget https://ftp.gnu.org/gnu/coreutils/coreutils-8.32.tar.xz",
            "python3 -c \"import urllib.request; urllib.request.urlopen('https://x/y.patch')\"",
            "curl -s https://services.nvd.nist.gov/rest/json/cve",
            "nc example.com 4444",
            "telnet scanme.nmap.org 80",
            "ssh git@github.com",
            "pip install requests",
            "npm install",
        ):
            self.assertIn("egress", self._check(command).lower(), command)

    def test_allows_loopback_and_offline_work(self) -> None:
        # A path-traversal/SSRF POV drives a locally-run server, and builds must
        # not be mistaken for egress.
        for command in (
            "curl -s http://localhost:8080/../../etc/passwd",
            "curl 127.0.0.1:8000/vuln",
            "nc localhost 9000 < payload",
            "nc -l 8080",                       # listener, not egress
            "git status --porcelain",           # local git, not a fetch
            "git describe --tags",
            "mvn -B -DskipTests package",
            "grep -rn 'https://example.com' src",  # a URL in a grep pattern, no fetch
        ):
            self.assertEqual(self._check(command), "", command)


def argv_net(runner, command: str) -> int:
    argv = runner.command_args(command)
    return argv.index("--network") + 1


class AgentNetworkPolicyTests(unittest.TestCase):
    """Agent-facing containers are network-isolated by default so agents cannot
    `curl` the advisory / official fix; P2PATCH_AGENT_NETWORK opts back in."""

    def _runner(self, root: Path) -> DockerRunner:
        project = ProjectMetadata(
            project_slug="owner__repo", cve_id="CVE-2099-0001", cwe_id="", cwe_name="",
            github_url="", github_tag="", buggy_commit_id="", fix_commit_ids="",
            source_path=root, dockerfile_path=root / "Dockerfile",
            build_system="maven", build_command="", test_command="",
        )
        (root / "Dockerfile").write_text("FROM scratch\n")
        (root / "wt").mkdir(exist_ok=True)
        return DockerRunner(project, root / "wt", root)

    def test_default_isolates_agent_containers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("P2PATCH_AGENT_NETWORK", None)
            runner = self._runner(Path(tmp))
            argv = runner.command_args("mvn test")
            self.assertIn("--network", argv)
            self.assertEqual(argv[argv.index("--network") + 1], "none")
            # The flag lands right after `docker run --rm`, before the mount.
            self.assertEqual(argv[:5], ["docker", "run", "--rm", "--network", "none"])

    def test_env_can_opt_back_into_a_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"P2PATCH_AGENT_NETWORK": "bridge"}):
                argv = self._runner(Path(tmp)).command_args("mvn test")
                self.assertEqual(argv[argv.index("--network") + 1], "bridge")
            with mock.patch.dict(os.environ, {"P2PATCH_AGENT_NETWORK": "allowlist-net"}):
                argv = self._runner(Path(tmp)).command_args("mvn test")
                self.assertEqual(argv[argv.index("--network") + 1], "allowlist-net")

    def test_wrapper_script_carries_the_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("P2PATCH_AGENT_NETWORK", None)
            wrapper = self._runner(Path(tmp)).write_wrapper()
            self.assertIn("--network none", wrapper.read_text())

    def test_evaluation_containers_keep_the_network(self) -> None:
        """The cutoff is about agents, and the POV evaluators run none.

        `--network none` on the fixPOV/residual container broke their
        staging builds (`mvn dependency:build-classpath` and `mvn install` pull
        plugins the project's `package` never used, so they are not in the
        image's ~/.m2; the coreutils harness clones gnulib). A staging failure
        records every POV `errored` with a null score, so four hardening runs
        lost their evaluation to an isolation that protected nothing -- the
        agents had already exited and the stage holds the official fix anyway.
        """
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("P2PATCH_AGENT_NETWORK", None)
            os.environ.pop("P2PATCH_EVAL_NETWORK", None)
            agent = self._runner(Path(tmp))
            self.assertEqual(agent.command_args("x")[argv_net(agent, "x")], "none")

            evaluator = agent.for_evaluation()
            argv = evaluator.command_args("bash run.sh pov1")
            self.assertEqual(argv[argv.index("--network") + 1], "bridge")
            # Same image and run dir -- only the network differs.
            self.assertEqual(evaluator.image_tag, agent.image_tag)

    def test_evaluation_network_is_itself_overridable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"P2PATCH_EVAL_NETWORK": "eval-net"}):
                argv = self._runner(Path(tmp)).for_evaluation().command_args("x")
                self.assertEqual(argv[argv.index("--network") + 1], "eval-net")
            # An agent opt-in does not silently retarget the evaluators.
            with mock.patch.dict(os.environ, {"P2PATCH_AGENT_NETWORK": "allowlist-net"}):
                os.environ.pop("P2PATCH_EVAL_NETWORK", None)
                argv = self._runner(Path(tmp)).for_evaluation().command_args("x")
                self.assertEqual(argv[argv.index("--network") + 1], "bridge")

    def test_for_checkout_keeps_the_isolation_of_its_parent(self) -> None:
        """The regression gate replays an *agent-authored* command, so its
        baseline container stays on whatever the parent runner is."""
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("P2PATCH_AGENT_NETWORK", None)
            base = Path(tmp) / "baseline_checkout"
            base.mkdir()
            argv = self._runner(Path(tmp)).for_checkout(base).command_args("mvn test")
            self.assertEqual(argv[argv.index("--network") + 1], "none")


class PromptBudgetTests(unittest.TestCase):
    """Task inputs are re-sent every turn (~35 per agent), so fat payloads are
    paid for repeatedly. Worst observed: 117 KB, of which 70 KB was one diff."""

    def test_clips_long_command_logs_head_and_tail(self) -> None:
        from security_pipeline.stages import PROMPT_LOG_TAIL_CHARS, command_evidence

        noisy = CommandResult(
            name="regression_1", command=["mvn", "test"], exit_code=1,
            stdout="START" + ("x" * 200_000) + "BUILD FAILURE", stderr="",
        )
        clipped = command_evidence(noisy)["stdout"]

        self.assertLess(len(clipped), 20_000)
        self.assertTrue(clipped.startswith("START"))
        self.assertTrue(clipped.endswith("BUILD FAILURE"))  # the part that matters
        self.assertIn("elided by the orchestrator", clipped)
        self.assertGreaterEqual(len(clipped), PROMPT_LOG_TAIL_CHARS)

    def test_short_logs_are_passed_through_untouched(self) -> None:
        from security_pipeline.stages import command_evidence

        result = CommandResult(
            name="pov", command=["./pov.sh"], exit_code=0, stdout="reproduced\n", stderr="",
        )
        self.assertEqual(command_evidence(result)["stdout"], "reproduced\n")

    def test_clips_a_huge_patch_diff(self) -> None:
        from security_pipeline.stages import PROMPT_DIFF_CHARS, clip_diff

        diff = "diff --git a/A b/A\n" + ("+line\n" * 40_000)
        clipped = clip_diff(diff)
        self.assertLess(len(clipped), PROMPT_DIFF_CHARS + 500)
        self.assertTrue(clipped.startswith("diff --git"))

    def test_the_alert_itself_is_never_clipped(self) -> None:
        # The alert defines what a complete fix must cover; trimming it would
        # change the task, not just the token bill.
        from security_pipeline.stages import build_base_context

        alert = {"name": "A", "cve_id": "CVE-2099-1", "traces": ["t" * 100_000]}
        context = build_base_context(
            alert, _project_stub(), "finding-1", Path("/run"), Path("/wt"), None
        )
        self.assertEqual(context["alert"]["traces"], ["t" * 100_000])
        self.assertNotIn("cve_id", context["alert"])  # still redacted


class CrlfDiffTests(unittest.TestCase):
    """A CRLF project's diff must keep its CRs or `git apply` rejects it.

    `subprocess.run(text=True)` decodes in universal-newline mode, silently
    rewriting every CRLF in git's output to LF. zip4j ships CRLF sources, so its
    recorded `patch_only.diff` had LF context lines that no longer matched the
    file — measured on the real run, 131 CRs dropped from one file's diff — and
    reconstruction-based fixPOV replay fell back for every zip4j run.
    """

    @staticmethod
    def _crlf_repo(repo: Path) -> None:
        repo.mkdir(parents=True, exist_ok=True)
        WorkspaceTests._git(repo, "init", "-q")
        # Pin the eol policy: a developer machine with core.autocrlf=input would
        # normalize the CRLF away at `git add` and the test would pass vacuously.
        # The servers these runs happen on have it unset, which is why zip4j's
        # blobs really do carry CRLF.
        WorkspaceTests._git(repo, "config", "core.autocrlf", "false")
        (repo / "App.java").write_bytes(
            b"package app;\r\n\r\nclass App {\r\n\tvoid run() {}\r\n}\r\n"
        )
        WorkspaceTests._git(repo, "add", "-A")
        WorkspaceTests._git(
            repo, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
            "commit", "-q", "--no-gpg-sign", "-m", "base",
        )

    def test_diff_of_a_crlf_file_keeps_its_carriage_returns(self) -> None:
        from security_pipeline.workspace import collect_patch_only_diff

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self._crlf_repo(repo)
            (repo / "App.java").write_bytes(
                b"package app;\r\n\r\nimport java.io.IOException;\r\n"
                b"\r\nclass App {\r\n\tvoid run() {}\r\n}\r\n"
            )
            self.assertIn("\r", collect_patch_only_diff(repo))

    def test_crlf_diff_round_trips_through_write_text_and_git_apply(self) -> None:
        from security_pipeline.logging_io import write_text
        from security_pipeline.workspace import collect_patch_only_diff

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            self._crlf_repo(repo)
            (repo / "App.java").write_bytes(
                b"package app;\r\n\r\nimport java.io.IOException;\r\n"
                b"\r\nclass App {\r\n\tvoid run() {}\r\n}\r\n"
            )
            patch_file = write_text(Path(tmp) / "patch.diff", collect_patch_only_diff(repo))

            # A pristine checkout of the same base, as replay reconstructs it.
            target = Path(tmp) / "target"
            self._crlf_repo(target)
            applied = subprocess.run(
                ["git", "apply", str(patch_file)], cwd=target,
                capture_output=True, text=True, errors="replace",
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(
                (target / "App.java").read_bytes(), (repo / "App.java").read_bytes()
            )


class UntrackedBinaryDiffTests(unittest.TestCase):
    """An untracked binary file must not make the whole diff unappliable.

    A patcher that re-runs the POV to check its own fix leaves a `.class` beside
    the source. `git diff --no-index` recorded it as a contentless "Binary files
    ... differ" stanza, and `git apply` then rejected the *entire* patch with
    "cannot apply binary patch ... without full index line" — which is what
    reconstruction-based fixPOV replay depends on.
    """

    def test_untracked_binary_file_round_trips_through_git_apply(self) -> None:
        from security_pipeline.workspace import collect_patch_only_diff

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            WorkspaceTests._git(repo, "init", "-q")
            (repo / "App.java").write_text("class App {}\n")
            WorkspaceTests._git(repo, "add", "-A")
            WorkspaceTests._git(
                repo, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                "commit", "-q", "--no-gpg-sign", "-m", "base",
            )
            # What a patcher's self-verification leaves behind: a tracked edit
            # plus untracked compiled output with bytes git treats as binary.
            (repo / "App.java").write_text("class App { /* fixed */ }\n")
            (repo / "Pov.class").write_bytes(bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0xFF]))

            diff = collect_patch_only_diff(repo)
            self.assertIn("Pov.class", diff)
            self.assertIn("GIT binary patch", diff)

            patch_file = Path(tmp) / "patch.diff"
            patch_file.write_text(diff)
            target = Path(tmp) / "target"
            target.mkdir()
            WorkspaceTests._git(target, "init", "-q")
            (target / "App.java").write_text("class App {}\n")
            WorkspaceTests._git(target, "add", "-A")
            WorkspaceTests._git(
                target, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                "commit", "-q", "--no-gpg-sign", "-m", "base",
            )
            applied = subprocess.run(
                ["git", "apply", str(patch_file)], cwd=target,
                capture_output=True, text=True, errors="replace",
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertIn("fixed", (target / "App.java").read_text())
            self.assertEqual(
                (target / "Pov.class").read_bytes(),
                bytes([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0xFF]),
            )


class NonUtf8WorktreeTests(unittest.TestCase):
    """A project file that is not UTF-8 must not kill the run.

    antisamy ships Latin-1 i18n bundles (`AntiSamy_de_DE.properties` contains
    0xFC = 'ü'). The patcher edited one, `git diff` then emitted those raw bytes,
    and `subprocess.run(text=True)` decoded them as UTF-8 and raised — stranding
    a run that had already produced a POV and a patch.
    """

    def test_git_diff_survives_latin1_files(self) -> None:
        from security_pipeline.workspace import collect_git_diff, collect_patch_only_diff

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            WorkspaceTests._git(repo, "init", "-q")
            bundle = repo / "AntiSamy_de_DE.properties"
            bundle.write_bytes(b"error.css=Das Stylesheet \xfcbersteigt die Grenze\n")
            WorkspaceTests._git(repo, "add", "-A")
            WorkspaceTests._git(
                repo, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                "commit", "-q", "--no-gpg-sign", "-m", "base",
            )
            bundle.write_bytes(b"error.css=Das Stylesheet \xfcberschreitet die Grenze\n")

            # Neither call may raise UnicodeDecodeError.
            self.assertIn("AntiSamy_de_DE.properties", collect_git_diff(repo))
            self.assertIn("AntiSamy_de_DE.properties", collect_patch_only_diff(repo))

    def test_write_diffs_survives_latin1_files(self) -> None:
        from security_pipeline.stages import write_diffs

        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "worktree"
            repo.mkdir()
            WorkspaceTests._git(repo, "init", "-q")
            (repo / "msgs.properties").write_bytes(b"k=\xfc\xe9\x8f\n")
            WorkspaceTests._git(repo, "add", "-A")
            WorkspaceTests._git(
                repo, "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                "commit", "-q", "--no-gpg-sign", "-m", "base",
            )
            (repo / "msgs.properties").write_bytes(b"k=\xfc\xe9\x8f changed\n")

            run_dir = Path(tmp) / "run"
            write_diffs(run_dir, repo)
            self.assertTrue((run_dir / "git" / "full.diff").exists())


class StageCrashTests(unittest.TestCase):
    """A crash must still produce a verdict, not a run stuck at `created`."""

    def test_unexpected_exception_becomes_a_rejected_verdict(self) -> None:
        from security_pipeline.models import PipelineState
        from security_pipeline.pipeline import SecurityPipeline

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            state = PipelineState(run_id="t", alert_path=Path("a"))
            state.run_dir = run_dir

            pipeline = SecurityPipeline.__new__(SecurityPipeline)
            result = pipeline._fail(state, "docker_build stage crashed: RuntimeError: boom")

            self.assertEqual(result.status, "rejected")
            verdict = json.loads((run_dir / "verdict.json").read_text())
            self.assertEqual(verdict["status"], "rejected")
            self.assertIn("crashed", verdict["reason"])

    def test_stage_loop_catches_more_than_stage_error(self) -> None:
        # Guard the contract itself: the loop must not narrow back to StageError.
        import inspect

        from security_pipeline.pipeline import SecurityPipeline

        source = inspect.getsource(SecurityPipeline.run_alert)
        self.assertIn("except StageError", source)
        self.assertIn("except Exception", source)


class ProviderCostFinalizationTests(unittest.TestCase):
    def test_openrouter_run_rechecks_incomplete_agent_costs_at_completion(self) -> None:
        from security_pipeline.pipeline import SecurityPipeline

        pipeline = SecurityPipeline.__new__(SecurityPipeline)
        pipeline.options = SimpleNamespace(
            model="deepseek/deepseek-v4-flash", dry_run=False
        )
        run_dir = Path("/tmp/run")
        with mock.patch(
            "security_pipeline.pipeline.reconcile_openrouter_run_costs"
        ) as reconcile:
            pipeline._reconcile_provider_costs(run_dir)

        reconcile.assert_called_once_with(run_dir, "deepseek/deepseek-v4-flash")

    def test_claude_run_does_not_use_openrouter_cost_finalization(self) -> None:
        from security_pipeline.pipeline import SecurityPipeline

        pipeline = SecurityPipeline.__new__(SecurityPipeline)
        pipeline.options = SimpleNamespace(model="sonnet", dry_run=False)
        with mock.patch(
            "security_pipeline.pipeline.reconcile_openrouter_run_costs"
        ) as reconcile:
            pipeline._reconcile_provider_costs(Path("/tmp/run"))

        reconcile.assert_not_called()


def _project_stub() -> ProjectMetadata:
    return ProjectMetadata(
        project_slug="s", cve_id="", cwe_id="", cwe_name="", github_url="", github_tag="",
        buggy_commit_id="", fix_commit_ids="", source_path=Path("."), dockerfile_path=Path("."),
        build_system="maven", build_command="mvn package", test_command="mvn test",
    )



class CompiledPovBinaryGuardTests(unittest.TestCase):
    """A compiled PoV harness is build output; a crafted ELF *input* is not.

    `.exe` was already exempt from the integrity guard, but that is the Windows
    convention — the Linux one is no extension at all, so `gcc -o pov pov.c`
    produced a file the guard treated as hand-authored PoV source and reverted
    after every patcher run. The patcher recompiles the harness against its fix,
    the guard puts back the build linked against unpatched code, and the gate
    then re-runs that stale binary forever. Two real runs (libjpeg-turbo
    CWE-476, binutils dwarf2 CWE-369) were rejected this way with a correct fix.
    """

    ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8

    def _guard(self, tmp, write):
        """Snapshot the PoV tree, let ``write`` mutate it, restore; return changed."""
        from security_pipeline.workspace import restore_path_tree, snapshot_path_tree

        pov = Path(tmp) / "pov"
        pov.mkdir(parents=True, exist_ok=True)
        write(pov)
        snapshot = snapshot_path_tree(pov)
        return pov, snapshot, restore_path_tree

    def test_a_recompiled_pov_binary_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            def build(pov):
                binary = pov / "pov"          # no suffix: the Linux convention
                binary.write_bytes(self.ELF + b"old")
                binary.chmod(0o755)

            pov, snapshot, restore = self._guard(tmp, build)
            # The patcher rebuilds the harness against its fix, as it should.
            (pov / "pov").write_bytes(self.ELF + b"rebuilt")

            self.assertEqual(restore(pov, snapshot), [])
            self.assertEqual((pov / "pov").read_bytes(), self.ELF + b"rebuilt")

    def test_a_crafted_elf_exploit_input_is_still_protected(self) -> None:
        # The load-bearing half of the check: binutils PoVs feed malformed object
        # files, which are also \x7fELF. Editing one into something benign would
        # walk the gate, so a non-executable binary stays guarded.
        with tempfile.TemporaryDirectory() as tmp:
            def stage(pov):
                (pov / "crafted.elf").write_bytes(self.ELF + b"malformed")
                (pov / "crafted.elf").chmod(0o644)

            pov, snapshot, restore = self._guard(tmp, stage)
            (pov / "crafted.elf").write_bytes(self.ELF + b"benign")

            self.assertEqual(restore(pov, snapshot), ["crafted.elf"])
            self.assertEqual((pov / "crafted.elf").read_bytes(), self.ELF + b"malformed")

    def test_an_extensionless_pov_script_is_still_protected(self) -> None:
        # Detection is by magic bytes, not by "has no extension", so an
        # executable shell harness named `run_pov` is not mistaken for output.
        with tempfile.TemporaryDirectory() as tmp:
            def stage(pov):
                script = pov / "run_pov"
                script.write_text("#!/bin/sh\nexec ./target\n")
                script.chmod(0o755)

            pov, snapshot, restore = self._guard(tmp, stage)
            (pov / "run_pov").write_text("#!/bin/sh\nexit 1\n")

            self.assertEqual(restore(pov, snapshot), ["run_pov"])
            self.assertIn("exec ./target", (pov / "run_pov").read_text())


class PovHarnessErrorTests(unittest.TestCase):
    """A PoV that could not execute is not evidence the patch works."""

    def test_an_unexecutable_harness_does_not_pass_the_gate(self) -> None:
        # "Any non-zero means blocked" pointed the wrong way here: a deleted or
        # unbuilt harness exits 127 and used to *accept* the run, with the
        # vulnerability never re-tested.
        from security_pipeline.stages import pov_blocked_predicate

        for exit_code in (126, 127):
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as tmp:
                ctx = _stage_ctx(tmp, _FakeDocker([_cmd(exit_code)]), _FakeAgentRunner([]))
                ctx.pov_command = "./pov.sh"

                result = pov_blocked_predicate().check(ctx)

                self.assertFalse(result.passed)
                self.assertIn("harness failed to execute", result.summary)
                step = next(s for s in ctx.state.steps if s["name"] == "pov_harness_error")
                self.assertEqual(step["exit_code"], exit_code)

    def test_an_ordinary_failure_still_counts_as_blocked(self) -> None:
        from security_pipeline.stages import pov_blocked_predicate

        with tempfile.TemporaryDirectory() as tmp:
            ctx = _stage_ctx(tmp, _FakeDocker([_cmd(1)]), _FakeAgentRunner([]))
            ctx.pov_command = "./pov.sh"

            result = pov_blocked_predicate().check(ctx)

            self.assertTrue(result.passed)
            self.assertEqual([s for s in ctx.state.steps if s["name"] == "pov_harness_error"], [])


class GuardOwnershipReclaimTests(unittest.TestCase):
    """A container runs as root; the guard that cleans up after it does not."""

    def test_a_restore_that_eperms_reclaims_ownership_and_retries(self) -> None:
        # `reclaim_ownership` only ran in the pipeline's closing `finally`, so a
        # hardening round's guard deleting a path the container had just created
        # crashed the whole run with PermissionError.
        from security_pipeline.stages import StageContext

        class _ReclaimingDocker(_FakeDocker):
            def __init__(self):
                super().__init__([])
                self.reclaimed = 0

            def reclaim_ownership(self):
                self.reclaimed += 1

        with tempfile.TemporaryDirectory() as tmp:
            docker = _ReclaimingDocker()
            ctx = _stage_ctx(tmp, docker, _FakeAgentRunner([]))
            attempts = {"n": 0}

            def restore():
                attempts["n"] += 1
                if attempts["n"] == 1:
                    raise PermissionError(13, "Permission denied")
                return ["pov/work_bypass/asan_output.txt"]

            changed = StageContext._restore_guarded(ctx, restore, "patcher_harden_r1")

            self.assertEqual(changed, ["pov/work_bypass/asan_output.txt"])
            self.assertEqual(docker.reclaimed, 1)
            self.assertEqual(attempts["n"], 2)
            step = next(s for s in ctx.state.steps if s["name"] == "ownership_reclaim")
            self.assertEqual(step["agent"], "patcher_harden_r1")


class PovSanitizerEnvTests(unittest.TestCase):
    """Leak reports must not masquerade as the vulnerability under test."""

    def _runner(self, tmp):
        from security_pipeline.docker_runner import DockerRunner

        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text("FROM scratch\n")
        project = ProjectMetadata(
            project_slug="s", cve_id="", cwe_id="", cwe_name="", github_url="", github_tag="",
            buggy_commit_id="", fix_commit_ids="", source_path=Path(tmp), dockerfile_path=dockerfile,
            build_system="maven", build_command="mvn package", test_command="mvn test",
        )
        return DockerRunner(project, Path(tmp), Path(tmp))

    def test_leak_detection_is_disabled_for_pov_runs(self) -> None:
        from security_pipeline.docker_runner import POV_SANITIZER_ENV

        with tempfile.TemporaryDirectory() as tmp:
            argv = self._runner(tmp).command_args("./pov.sh", POV_SANITIZER_ENV)

            self.assertIn("-e", argv)
            self.assertIn("ASAN_OPTIONS=detect_leaks=0", argv)
            # The env pairs must precede the image name, or docker reads them as
            # arguments to the command instead of as flags.
            self.assertLess(argv.index("ASAN_OPTIONS=detect_leaks=0"), argv.index("bash"))

    def test_an_ordinary_command_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertNotIn("-e", self._runner(tmp).command_args("mvn package"))

class LegacyEnvNameTests(unittest.TestCase):
    """The AutoSec -> P2Patch rename must not silently unconfigure a host.

    Operators export these in shell profiles and systemd units this repo cannot
    reach, so the pre-rename spelling stays readable. A run host that had opted
    its builds back onto the network would otherwise go isolated again and
    start failing builds for no visible reason."""

    def test_new_name_is_read(self):
        with mock.patch.dict(os.environ, {"P2PATCH_AGENT_NETWORK": "bridge"}, clear=True):
            self.assertEqual(env.get_env("P2PATCH_AGENT_NETWORK"), "bridge")

    def test_falls_back_to_the_pre_rename_name(self):
        with mock.patch.dict(os.environ, {"AUTOSEC_AGENT_NETWORK": "allowlist-net"}, clear=True):
            self.assertEqual(env.get_env("P2PATCH_AGENT_NETWORK"), "allowlist-net")
            self.assertEqual(docker_runner.agent_network_policy(), "allowlist-net")

    def test_new_name_wins_over_the_legacy_one(self):
        with mock.patch.dict(
            os.environ,
            {"P2PATCH_AGENT_NETWORK": "bridge", "AUTOSEC_AGENT_NETWORK": "allowlist-net"},
            clear=True,
        ):
            self.assertEqual(env.get_env("P2PATCH_AGENT_NETWORK"), "bridge")

    def test_an_explicit_empty_new_value_is_not_overridden_by_the_legacy_one(self):
        # "" means isolated -- a real choice, not "unset".
        with mock.patch.dict(
            os.environ,
            {"P2PATCH_AGENT_NETWORK": "", "AUTOSEC_AGENT_NETWORK": "bridge"},
            clear=True,
        ):
            self.assertEqual(env.get_env("P2PATCH_AGENT_NETWORK"), "")
            self.assertEqual(docker_runner.agent_network_policy(), "none")

    def test_unset_everywhere_is_none(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(env.get_env("P2PATCH_AGENT_NETWORK"))


class BuildOutputGuardTests(unittest.TestCase):
    """An autotools tree ships no .gitignore, so git cannot classify its build.

    The product-source guard's only signal was "untracked and not ignored means
    the agent authored it". On libtiff that description fits all 185 files the
    build produces, so the guard deleted 184 of them after the exploiter's turn
    -- including the `tools/tiffcrop` the exploiter had just used to prove the
    CVE reproduces with a real ASan crash. Every retry then re-ran a binary that
    no longer existed and the run was rejected for "not reproducing".
    """

    def _repo(self, tmp):
        from security_pipeline.workspace import run_local_command

        repo = Path(tmp)
        run_local_command("init", ["git", "init", "-q"], cwd=repo)
        run_local_command("cfg1", ["git", "config", "user.email", "t@t"], cwd=repo)
        run_local_command("cfg2", ["git", "config", "user.name", "t"], cwd=repo)
        (repo / "tools").mkdir()
        (repo / "tools" / "tiffcrop.c").write_text("int main(void){return 0;}\n")
        run_local_command("add", ["git", "add", "-A"], cwd=repo)
        run_local_command("commit", ["git", "commit", "-qm", "base"], cwd=repo)
        return repo

    def test_build_output_survives_the_guard(self) -> None:
        from security_pipeline.workspace import (
            restore_worktree_sources,
            snapshot_worktree_sources,
        )

        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            outputs = ["Makefile", "config.status", "tools/tiffcrop"]
            snapshot = snapshot_worktree_sources(repo, build_outputs=outputs)

            # The exploiter builds the project to prove the CVE reproduces.
            (repo / "Makefile").write_text("all:\n")
            (repo / "config.status").write_text("#!/bin/sh\n")
            (repo / "tools" / "tiffcrop").write_bytes(b"\x7fELF binary")

            changed = restore_worktree_sources(repo, snapshot, build_outputs=outputs)

            self.assertEqual(changed, [])
            self.assertTrue((repo / "tools" / "tiffcrop").exists())
            self.assertTrue((repo / "config.status").exists())

    def test_product_source_the_exploiter_added_is_still_removed(self) -> None:
        # The guard still has to do its actual job: anything outside the build's
        # own output is the exploiter editing the code it is meant to attack.
        from security_pipeline.workspace import (
            restore_worktree_sources,
            snapshot_worktree_sources,
        )

        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo(tmp)
            outputs = ["Makefile"]
            snapshot = snapshot_worktree_sources(repo, build_outputs=outputs)

            (repo / "Makefile").write_text("all:\n")            # build output
            (repo / "tools" / "sneaky.c").write_text("/* mine */\n")  # not
            (repo / "tools" / "tiffcrop.c").write_text("int main(void){return 1;}\n")

            changed = restore_worktree_sources(repo, snapshot, build_outputs=outputs)

            self.assertEqual(changed, ["tools/sneaky.c", "tools/tiffcrop.c"])
            self.assertFalse((repo / "tools" / "sneaky.c").exists())
            self.assertIn("return 0", (repo / "tools" / "tiffcrop.c").read_text())
            self.assertTrue((repo / "Makefile").exists())

    def test_a_probe_failure_falls_back_to_the_old_behaviour(self) -> None:
        from security_pipeline.stages import StageContext

        class _NoProbeDocker(_FakeDocker):
            def image_build_outputs(self):
                raise RuntimeError("image not built")

        with tempfile.TemporaryDirectory() as tmp:
            ctx = _stage_ctx(tmp, _NoProbeDocker([]), _FakeAgentRunner([]))
            self.assertEqual(StageContext.build_outputs(ctx), [])

class StreamRecoveryTests(unittest.TestCase):
    """A finished turn that ends in prose is not a failed run.

    An agent 35+ turns deep emits its structured output while self-verifying and
    then closes with a summary instead of repeating it. The parser only reads
    the final turn, so one patcher's clean 70-turn run — with the patch already
    written to disk — was rejected for "no JSON object found".
    """

    def _stream(self, tmp, *texts):
        path = Path(tmp) / "stream.jsonl"
        with open(path, "w", encoding="utf-8") as handle:
            for text in texts:
                handle.write(json.dumps({
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": text}]},
                }) + "\n")
            handle.write(json.dumps({"type": "result", "result": "all done"}) + "\n")
        return path

    def test_structured_output_from_an_earlier_turn_is_recovered(self) -> None:
        from security_pipeline.claude_agents import recover_output_from_stream

        with tempfile.TemporaryDirectory() as tmp:
            path = self._stream(
                tmp,
                'Here it is:\n<StructuredOutput>\n{"status": "patched", "n": 1}\n</StructuredOutput>',
                "I have already provided the structured output above.",
            )
            self.assertEqual(
                recover_output_from_stream(path), {"status": "patched", "n": 1}
            )

    def test_the_latest_object_wins(self) -> None:
        from security_pipeline.claude_agents import recover_output_from_stream

        with tempfile.TemporaryDirectory() as tmp:
            path = self._stream(
                tmp,
                '<StructuredOutput>{"status": "draft"}</StructuredOutput>',
                '<StructuredOutput>{"status": "patched"}</StructuredOutput>',
                "Done.",
            )
            self.assertEqual(recover_output_from_stream(path), {"status": "patched"})

    def test_prose_only_recovers_nothing(self) -> None:
        from security_pipeline.claude_agents import recover_output_from_stream

        with tempfile.TemporaryDirectory() as tmp:
            path = self._stream(tmp, "I thought about it.", "I gave up.")
            self.assertIsNone(recover_output_from_stream(path))

    def test_a_missing_stream_recovers_nothing(self) -> None:
        from security_pipeline.claude_agents import recover_output_from_stream

        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(recover_output_from_stream(Path(tmp) / "absent.jsonl"))

    def test_a_raw_newline_inside_a_string_still_parses(self) -> None:
        # Agents routinely put a literal newline in a summary field. Strict JSON
        # forbids it, and rejecting the object discards a completed turn over
        # whitespace — this is what actually defeated the recovery above.
        from security_pipeline.claude_agents import extract_json_object

        self.assertEqual(
            extract_json_object('{"summary": "line one\nline two"}'),
            {"summary": "line one\nline two"},
        )

if __name__ == "__main__":
    unittest.main()
