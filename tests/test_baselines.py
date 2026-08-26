"""Tests for the San2Patch baseline view and the patch-scoring driver.

Two things worth pinning down, both places where a wrong answer would be *invisible*
rather than loud:

- **The dashboard button and the batch driver must score the same bytes.** Both go
  through ``baselines/patch_source.py``; if they ever diverged they would disagree
  about a case with nothing in either output saying why.
- **A non-attempt must never be counted as a repair failure.** A San2Patch case
  shredded by an API usage limit still writes a ``res.txt`` reading
  ``vuln_test_failed``; folding those into the denominator understated the tool by 20
  points once already.
- **Sharing a case id does not mean sharing a commit.** VulnLoc and our VulnLoc+
  dataset pin two zziplib CVEs at different revisions, so a patch scored on the wrong
  one either will not apply or will not compile. The base has to come from the
  benchmark, and a base we cannot resolve must report as unresolved rather than as
  agreement.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "dashboard" / "backend"
for p in (str(REPO_ROOT), str(BACKEND_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from baselines import patch_source  # noqa: E402
import san2patch  # noqa: E402
import san2patch_fixpov  # noqa: E402


class PatchSourceTests(unittest.TestCase):
    def test_only_san2patch_is_registered(self):
        """LoopRepair is deliberately not a baseline here: this driver WRITES into a
        baseline's own result directories, and that experiment is owned elsewhere."""
        self.assertEqual(patch_source.BASELINE_NAMES, ("san2patch",))

    def test_san2patch_patch_is_already_a_git_diff(self):
        case = patch_source.find_case("san2patch", REPO_ROOT, "CVE-2017-7601")
        self.assertIsNotNone(case)
        text, err = patch_source.patch_text("san2patch", case)
        self.assertIsNone(err)
        self.assertTrue(text.startswith("diff --git "), text[:40])

    def test_a_case_with_no_patch_reports_why_rather_than_raising(self):
        """A failed case has no patch. That is expected, not an error -- but it must be
        distinguishable from 'we have not scored this yet'."""
        case = patch_source.find_case("san2patch", REPO_ROOT, "CVE-2018-8964")
        text, err = patch_source.patch_text("san2patch", case)
        self.assertIsNone(text)
        self.assertIn("no patch", err)

    def test_project_slugs_reads_the_crlf_csv(self):
        slugs = patch_source.project_slugs(REPO_ROOT)
        self.assertEqual(slugs["CVE-2017-7601"], "vadz__libtiff_CVE-2017-7601_3144e57770c1")
        # Non-CVE VulnLoc ids resolve through the same column.
        self.assertIn("gnubug-25023", slugs)
        self.assertFalse(any("\r" in s for s in slugs.values()))

    def test_project_rows_carries_the_base_commit(self):
        rows = patch_source.project_rows(REPO_ROOT)
        self.assertEqual(
            rows["CVE-2017-5974"]["buggy_commit_id"],
            "3a4ffcdd78708c2c7bb9aa89b0a6df0aab6c9d3e",
        )


class BasePlanTests(unittest.TestCase):
    """Which commit a third-party patch is a diff against.

    These four cases are the whole reason ``base_plan`` exists, and each of them
    used to be silently assumed to be the fifth (``same``)."""

    def _plan(self, case_id, dataset_revision, source_path=None):
        case = patch_source.find_case("san2patch", REPO_ROOT, case_id)
        self.assertIsNotNone(case, case_id)
        return patch_source.base_plan(
            "san2patch", REPO_ROOT, case, dataset_revision, source_path=source_path
        )

    def test_abbreviated_sha_matching_ours_is_same(self):
        plan = self._plan("CVE-2017-7601", "3144e57770c1e4d26520d8abee750f8ac8b75490")
        self.assertEqual(plan["state"], "same")
        self.assertIsNone(plan["base_revision"])

    def test_benchmark_pinning_a_later_commit_is_a_mismatch(self):
        """zziplib CVE-2017-5974: VulnLoc pins upstream's first (incomplete) fix,
        `03de3be`; we pin `3a4ffcdd`, before any fix. Their patch is a diff against
        code that only exists after that commit."""
        plan = self._plan("CVE-2017-5974", "3a4ffcdd78708c2c7bb9aa89b0a6df0aab6c9d3e")
        self.assertEqual(plan["state"], "differs")
        self.assertEqual(plan["base_revision"], "03de3be")

    def test_a_tag_that_peels_to_our_commit_is_not_a_mismatch(self):
        """The project clones are --depth 1 and carry no tags, so this can only be
        settled from the checked-in ls-remote result. Getting it wrong would send
        three currently-correct cases down the alternate-base path for nothing."""
        plan = self._plan("CVE-2018-8806", "b72cc2fda0e8b3792b7b3f7361fc3f917f269433")
        self.assertEqual(plan["state"], "same")
        self.assertEqual(plan["resolved"], "b72cc2fda0e8b3792b7b3f7361fc3f917f269433")

    def test_an_unresolvable_ref_reports_unresolved_rather_than_agreement(self):
        case = patch_source.find_case("san2patch", REPO_ROOT, "CVE-2018-8806")
        original = dict(patch_source.KNOWN_TAG_COMMITS)
        patch_source.KNOWN_TAG_COMMITS.clear()
        try:
            plan = patch_source.base_plan(
                "san2patch", REPO_ROOT, case, "b72cc2fda0e8b3792b7b3f7361fc3f917f269433",
                source_path=Path("/nonexistent"),
            )
        finally:
            patch_source.KNOWN_TAG_COMMITS.update(original)
        self.assertEqual(plan["state"], "unresolved")
        # Crucially it does NOT set a base revision: an unresolved ref falls back to
        # today's behaviour rather than guessing a tree to score on.
        self.assertIsNone(plan["base_revision"])

    def test_a_benchmark_without_a_commit_reports_unknown(self):
        """potrace ships a source.zip, not a git checkout."""
        plan = self._plan("CVE-2013-7437", "189777a2bd5015c4debbef6e54f34ab5a8c99586")
        self.assertEqual(plan["state"], "unknown")
        self.assertIsNone(plan["base_revision"])


class San2PatchViewTests(unittest.TestCase):
    def test_rate_excludes_rows_that_never_reached_the_model(self):
        rows = san2patch.list_results()
        stats = san2patch.stats()
        invalid = [r for r in rows if not r["valid"]]
        self.assertTrue(invalid, "fixture should contain at least one non-attempt")
        # Denominator is valid rows only, so an incident cannot read as a failure.
        self.assertEqual(stats["patched"] + stats["failed"], len(rows) - len(invalid))
        self.assertEqual(stats["total"], len(rows))

    def test_case_dir_rejects_traversal(self):
        for bad in ("../../etc", "..", "a/b", ""):
            self.assertIsNone(san2patch._case_dir(bad), bad)

    def test_pov_headline_is_none_until_something_has_been_scored(self):
        """Absent must not render as zero -- 'not looked at' and 'blocked nothing'
        are opposite conclusions about a patch."""
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(san2patch._pov_headline(Path(td), "fix_pov"))
        self.assertIsNone(san2patch._pov_headline(None, "fix_pov"))

    def test_pov_headline_reads_a_results_json(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "fix_pov"
            d.mkdir()
            (d / "results.json").write_text(json.dumps(
                {"score": 0.5, "total": 4, "blocked": 2, "all_blocked": False}))
            self.assertEqual(
                san2patch._pov_headline(Path(td), "fix_pov"),
                {"score": 0.5, "total": 4, "all_blocked": False, "all_hardened": None},
            )


class San2PatchReplayJobTests(unittest.TestCase):
    """The per-case replay button must reach the same CLI, manifests and images the
    batch driver does — otherwise the dashboard and the report can disagree."""

    def test_argv_targets_the_same_cli_and_manifest(self):
        avail = san2patch_fixpov._availability("fixpov", "CVE-2017-7601")
        self.assertTrue(avail["available"], avail)
        argv = san2patch_fixpov._command("fixpov")("CVE-2017-7601", avail)
        self.assertIn("fixpov", argv)
        self.assertIn("replay-patch", argv)
        self.assertEqual(argv[argv.index("--project") + 1],
                         "vadz__libtiff_CVE-2017-7601_3144e57770c1")
        # Label is tool-prefixed: both baselines have a libtiff CVE-2017-7601 patch,
        # and an unprefixed label would have them share one scratch checkout.
        self.assertEqual(argv[argv.index("--label") + 1], "san2patch-CVE-2017-7601")
        patch = Path(argv[argv.index("--patch-file") + 1])
        self.assertTrue(patch.is_file())
        self.assertTrue(patch.read_text().startswith("diff --git "))

    def test_the_button_uses_the_same_base_the_batch_driver_would(self):
        """The button and score_patches.py must score the same bytes on the same tree.
        Without the base, clicking replay on zziplib CVE-2017-5974 would fail to apply
        while the batch run scored it — a silent disagreement with nothing in either
        output explaining it."""
        avail = san2patch_fixpov._availability("fixpov", "CVE-2017-5974")
        self.assertEqual(avail["base"]["state"], "differs")
        argv = san2patch_fixpov._command("fixpov")("CVE-2017-5974", avail)
        self.assertEqual(argv[argv.index("--base-revision") + 1], "03de3be")

    def test_a_matching_base_adds_no_flag(self):
        """The overwhelming majority of cases agree, and for those the argv must be
        exactly what it has always been."""
        avail = san2patch_fixpov._availability("fixpov", "CVE-2017-7601")
        self.assertEqual(avail["base"]["state"], "same")
        argv = san2patch_fixpov._command("fixpov")("CVE-2017-7601", avail)
        self.assertNotIn("--base-revision", argv)

    def test_unavailable_reasons_are_specific(self):
        # A failed case has no patch: not an error, but not scoreable either.
        a = san2patch_fixpov._availability("fixpov", "CVE-2018-8964")
        self.assertFalse(a["available"])
        self.assertIn("no patch", a["unavailable_reason"])
        # A case with no project_info row cannot even be mapped to a manifest.
        b = san2patch_fixpov._availability("fixpov", "gnubug-25003")
        self.assertFalse(b["available"])
        self.assertIn("project_info", b["unavailable_reason"])

    def test_unknown_case_raises_rather_than_reporting_unavailable(self):
        with self.assertRaises(san2patch_fixpov.ReplayError):
            san2patch_fixpov._availability("fixpov", "CVE-0000-0000")


class San2PatchTraceTests(unittest.TestCase):
    def test_trace_is_readable_and_traversal_is_refused(self):
        r = san2patch.get_result("CVE-2017-7601")
        self.assertTrue(r["traces"], "fixture should have at least one trace")
        self.assertIsNotNone(san2patch.get_trace("CVE-2017-7601", r["traces"][0]))
        for bad in ("stage_0_0/../../../../etc/passwd", "../aggregate.json",
                    "stage_0_0/nope.json", "res.txt", ""):
            self.assertIsNone(san2patch.get_trace("CVE-2017-7601", bad), bad)


if __name__ == "__main__":
    unittest.main()
