"""Baseline-diff for the regression gate.

A failing regression command is only a *genuine* regression if a test that
PASSED on the pristine pre-patch baseline now FAILS on the patched tree. Every
other reason a regression command exits non-zero is a scaffold artifact, not a
patch defect:

  * the exploiter's PoV, compiled into the project's ``target/test-classes`` under
    a project package, is re-run by ``mvn test`` and its "vuln-present" assertion
    fails once the patch correctly fixes the vuln (it is a *new* test, absent from
    the baseline);
  * a test that fails only because the container runs as root (permission bits,
    read-only-file semantics) — it fails on the baseline too;
  * a pre-existing/flaky failure unrelated to the patch — it fails on the baseline
    too;
  * an invalid regression command the agent picked (wrong ``-Dtest`` filter,
    unresolvable dependency, "No tests were executed") — it fails on the baseline
    too.

This module parses JUnit XML reports (Maven surefire/failsafe and Gradle both
emit ``TEST-*.xml`` in the same schema) and, given the post-patch reports plus a
baseline replay of the same command, decides genuine vs scaffold. It is pure and
build-system-agnostic so it can be unit-tested without Docker.

A project whose regression/test command never produces JUnit XML at all (a C/C++
project's ``make check``/crash-reproduction command, most commonly) is not a
special case: ``parse_junit_reports`` returns ``{}`` for both sides, so
``classify_regression_failure`` falls straight to its no-reports branch below —
genuine iff the baseline replay exited 0 and the patched one didn't (the patch
broke the build/behavior), scaffold iff the same command already failed on the
baseline (pre-existing/root-only/invalid command). That is exactly the
exit-code-only diff such a project needs, with no separate code path required.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

PASS = "pass"
FAIL = "fail"
SKIP = "skip"


def parse_junit_reports(root: Path, newer_than: Optional[float] = None) -> Dict[str, str]:
    """Map ``"<classname>#<test>" -> pass|fail|skip`` from all JUnit XML under root.

    A test that appears failing in any report shard is recorded as failing.
    Unreadable/malformed report files are skipped rather than raising.

    ``newer_than`` (a POSIX timestamp) keeps only reports written since then,
    which is what makes this usable on a worktree that accumulates build output:
    surefire leaves the previous command's XML in place, and without the filter a
    later command would inherit an earlier one's results.
    """
    outcomes: Dict[str, str] = {}
    if not root.exists():
        return outcomes
    for xml_path in root.rglob("TEST-*.xml"):
        try:
            if newer_than is not None and xml_path.stat().st_mtime < newer_than:
                continue
            tree = ET.parse(xml_path)
        except (ET.ParseError, OSError):
            continue
        node = tree.getroot()
        suites = [node] if node.tag == "testsuite" else list(node.iter("testsuite"))
        for suite in suites:
            for case in suite.iter("testcase"):
                classname = case.get("classname") or case.get("class") or suite.get("name") or ""
                name = case.get("name") or ""
                test_id = f"{classname}#{name}"
                if case.find("failure") is not None or case.find("error") is not None:
                    outcome = FAIL
                elif case.find("skipped") is not None:
                    outcome = SKIP
                else:
                    outcome = PASS
                # A failure in any shard wins; otherwise first outcome recorded.
                if outcomes.get(test_id) == FAIL:
                    continue
                if outcome == FAIL or test_id not in outcomes:
                    outcomes[test_id] = outcome
    return outcomes


def _failing(outcomes: Dict[str, str]) -> Set[str]:
    return {t for t, o in outcomes.items() if o == FAIL}


def _passing(outcomes: Dict[str, str]) -> Set[str]:
    return {t for t, o in outcomes.items() if o == PASS}


def classify_regression_failure(
    post_reports: Dict[str, str],
    baseline_reports: Dict[str, str],
    baseline_ok: bool,
) -> Tuple[str, List[str], str]:
    """Decide whether a failed regression command is a genuine regression.

    Returns ``(verdict, regressed_tests, explanation)`` where ``verdict`` is
    ``"genuine"`` or ``"scaffold"``. Called only for a command that already
    failed on the patched tree; ``baseline_reports``/``baseline_ok`` come from
    replaying the *same* command against the pristine pre-patch baseline.
    """
    regressed = sorted(_failing(post_reports) & _passing(baseline_reports))
    if regressed:
        return (
            "genuine",
            regressed,
            f"{len(regressed)} test(s) passed on the pristine baseline but fail after the patch",
        )
    if not baseline_ok:
        return (
            "scaffold",
            [],
            "the same command also fails on the pristine pre-patch baseline "
            "(pre-existing failure, root-only/env test, or an invalid command)",
        )
    if not post_reports:
        # Baseline ran the command cleanly, but the patched tree produced no test
        # reports at all and still failed -> the patch most likely broke the build.
        return (
            "genuine",
            [],
            "the command produced no test reports while the baseline built cleanly "
            "(the patch likely broke compilation)",
        )
    return (
        "scaffold",
        [],
        "only injected-PoV/new or already-failing tests failed; "
        "no baseline-passing test regressed",
    )
