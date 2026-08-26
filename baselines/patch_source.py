"""Where each baseline tool's patch lives, and how to make it ``git apply``-able.

One module, because the two consumers must agree byte-for-byte on what "the patch
San2Patch produced for CVE-2017-7601" is: the dashboard's per-case replay button
(``dashboard/backend/san2patch_fixpov.py``) and the batch driver
(``baselines/score_patches.py``). Two implementations would drift, and the failure
would be silent — the button and the batch run would score *different* patches and
disagree, with nothing in either output saying why.

Structured as a registry rather than one hard-coded baseline because a second
San2Patch arm (a DeepSeek run) is planned and will differ only in its results
directory. **LoopRepair is deliberately absent**: that baseline is owned and analysed
separately, and this driver writes into a baseline's own result directories — pointing
it at someone else's experiment is exactly the accident worth making impossible.

Stdlib only: the driver is meant to run anywhere the pipeline runs, and
``security_pipeline/`` is dependency-free by design.

``san2patch``
    Emits a real ``git diff`` (``diff --git`` header, index line, ``---``/``+++``)
    per successful case, at
    ``<batch>/gen_diff/<case>/<batch>_<case>_success.diff``. Nothing to fix up.
    A *failed* case has no ``*success.diff`` at all, which is correct — there is no
    patch to score.

BASE REVISIONS. A patch is a diff against a *specific commit*, and the benchmarks
do not all pin the same commit for the same CVE. Our dataset (VulnLoc+, via
``project_info.csv``) and San2Patch's VulnLoc share every case id, which made it
easy to assume they shared the tree too — they mostly do, but not always, and the
exceptions are not random drift. Upstream sometimes fixed a CVE twice; VulnLoc
then pins the bug at the *first, incomplete* fix while we pin it before any fix
(zziplib CVE-2017-5974 at ``03de3be``, CVE-2017-5975 at ``33d6e9c``). Scoring such
a patch on our tree produced a wrong answer twice over — ``git apply`` rejected
one outright, and the other applied by context and then failed to compile
(``use of undeclared label 'error'``, a label the later commit introduced).

So the base is read from the benchmark rather than assumed, and reported per case.
"""
from __future__ import annotations

import csv
import io
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Both baselines' case ids are the values in project_info.csv's `cve_id` column
# (`CVE-2017-7601`, but also `gnubug-25023` and `bugzilla-2611` — the non-CVE ids
# VulnLoc carries). One mapping function serves both.
PROJECT_INFO = Path("benchmark/dataset/project_info.csv")

SAN2PATCH_RESULTS = Path("baselines/results/san2patch/vulnloc-haiku45")
SAN2PATCH_BENCHMARK = Path("baselines/vendor/san2patch-benchmark")
PATCHAGENT_RESULTS = Path("baselines/results/patchagent/skyset-haiku45")

# Benchmark refs that are tag names, with the commit each peels to. The project
# clones are `--depth 1`, so they carry no tags and cannot resolve these offline;
# without this map all four would report as "unresolved" and silently fall back
# to our base — which happens to be right, but for no stated reason. Each value
# was obtained with `git ls-remote <url> 'refs/tags/<tag>^{}'` and equals our
# `buggy_commit_id`, i.e. these are NOT mismatches. Keyed by (case_id, ref)
# because a tag name like `v3.2.0` is not unique across projects.
KNOWN_TAG_COMMITS = {
    ("CVE-2016-5844", "v3.2.0"): "167e97be1d35c1e0947d768adbf94712244aad6b",
    ("CVE-2016-9557", "version-1.900.17"): "e613bbb1612d3a82abc9b8d170c4d9a5d2ec0135",
    ("CVE-2018-8806", "ming-0_4_8"): "b72cc2fda0e8b3792b7b3f7361fc3f917f269433",
    ("CVE-2018-8964", "ming-0_4_8"): "b72cc2fda0e8b3792b7b3f7361fc3f917f269433",
}


@dataclass(frozen=True)
class Case:
    """One case of one baseline, with everything needed to score it."""

    case_id: str          # key into project_info.csv -> project_slug
    key: str              # the baseline's own identifier (dir name, --label)
    artifact_dir: Path    # <family>/results.json is written under here
    claimed_repaired: bool
    patch_path: Optional[Path]


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def project_rows(repo_root: Path) -> Dict[str, Dict[str, str]]:
    """``cve_id`` -> the project_info.csv row, as plain strings.

    Read as bytes and decoded here rather than via ``read_text``: the file is CRLF
    and ``Path.read_text`` would translate the line endings, which matters for any
    caller that later rewrites it (see CLAUDE.md).
    """
    raw = (repo_root / PROJECT_INFO).read_bytes().decode("utf-8", errors="replace")
    out: Dict[str, Dict[str, str]] = {}
    for row in csv.DictReader(io.StringIO(raw)):
        cve = (row.get("cve_id") or "").strip()
        slug = (row.get("project_slug") or "").strip()
        if cve and slug:
            out[cve] = {key: (value or "").strip() for key, value in row.items() if key}
    return out


def project_slugs(repo_root: Path) -> Dict[str, str]:
    """``cve_id`` -> ``project_slug`` from project_info.csv."""
    return {cve: row["project_slug"] for cve, row in project_rows(repo_root).items()}


# --------------------------------------------------------------------------- san2patch


def _san2patch_cases(repo_root: Path) -> List[Case]:
    root = repo_root / SAN2PATCH_RESULTS
    agg = _read_json(root / "aggregate.json")
    if not agg:
        return []
    cases: List[Case] = []
    for row in agg.get("cases", []):
        cid, batch = row["case_id"], row["batch"]
        # aggregate.json already resolved which of two attempts is the counted one
        # (earliest complete attempt wins — see aggregate.py); scoring the batch it
        # names keeps the POV score attached to the attempt the headline reports.
        gen = root / batch / "gen_diff" / cid
        patch = next(iter(sorted(gen.glob("*success.diff"))), None)
        cases.append(
            Case(
                case_id=cid,
                key=cid,
                artifact_dir=gen,
                claimed_repaired=row.get("status") == "success",
                patch_path=patch,
            )
        )
    return cases


def _san2patch_base(repo_root: Path, case: Case) -> Optional[str]:
    """The commit san2patch-benchmark checks out for this case, verbatim.

    Read from the case's own ``setup.sh`` (``bug_commit_id=...``) rather than from
    ``vulnloc-meta-data.json``, which does not carry it. Returns None when the
    benchmark has not been cloned or has no setup script for the case — the
    caller then keeps today's behaviour and says the base is unknown, rather than
    guessing.
    """
    bench = repo_root / SAN2PATCH_BENCHMARK
    if not bench.is_dir():
        return None
    setup = None
    meta = bench / "vulnloc-meta-data.json"
    if meta.is_file():
        entries = _read_json(meta)
        for entry in entries if isinstance(entries, list) else []:
            if entry.get("bug_id") == case.case_id:
                setup = bench / entry.get("subject", "") / case.case_id / "setup.sh"
                break
    if setup is None or not setup.is_file():
        setup = next(iter(sorted(bench.glob(f"*/{case.case_id}/setup.sh"))), None)
    if setup is None or not setup.is_file():
        return None
    match = re.search(
        r"^\s*bug_commit_id=([^\s#]+)", setup.read_text(encoding="utf-8", errors="replace"),
        re.MULTILINE,
    )
    return match.group(1).strip() if match else None


def _san2patch_patch(case: Case) -> Tuple[Optional[str], Optional[str]]:
    if case.patch_path is None:
        return None, "San2Patch produced no patch for this case (no *success.diff)"
    text = case.patch_path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return None, "success.diff is empty"
    return text, None


def _patchagent_cases(repo_root: Path) -> List[Case]:
    """One Case per CVE row in the arm's aggregate.

    Note the mapping is not 1:1 with runs: a single PatchAgent run can cover two CVEs
    that share a buggy commit (libtiff c421b99 is CVE-2016-3186 and CVE-2016-5314), and
    the POV sets score those separately. Keying on ``case_id`` therefore yields two
    Cases pointing at the same patch, which is what we want -- each gets its own POV
    verdict -- while ``patchagent_case`` in the row records the shared origin.
    """
    root = repo_root / PATCHAGENT_RESULTS
    agg = _read_json(root / "aggregate.json")
    if not agg:
        return []
    cases: List[Case] = []
    for row in agg.get("cases", []):
        cid, batch = row.get("case_id"), row.get("batch")
        if not cid or not batch:
            continue          # `inapplicable` rows carry no batch and cannot be scored
        gen = root / batch / "gen_patch" / cid
        patch = gen / "patch.diff"
        cases.append(
            Case(
                case_id=cid,
                key=cid,
                artifact_dir=gen,
                claimed_repaired=row.get("status") == "patched",
                patch_path=patch if patch.is_file() else None,
            )
        )
    return cases


def _patchagent_base(repo_root: Path, case: Case) -> Optional[str]:
    """The commit skyset pins for this case, as recorded when the run was normalized.

    PatchAgent runs are built from ``skyset/<project>/<tag>/immutable`` checked out at
    the tag's commit, so the base is known exactly rather than inferred, and is carried
    in the aggregate row. Returns None if absent, so the caller says "unknown" instead
    of guessing.
    """
    agg = _read_json(repo_root / PATCHAGENT_RESULTS / "aggregate.json") or {}
    for row in agg.get("cases", []):
        if row.get("case_id") == case.case_id:
            rev = (row.get("base_revision") or "").strip()
            return rev or None
    return None


def _patchagent_patch(case: Case) -> Tuple[Optional[str], Optional[str]]:
    if case.patch_path is None:
        return None, "PatchAgent produced no patch for this case (no patch.diff)"
    text = case.patch_path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return None, "patch.diff is empty"
    return text, None


# ------------------------------------------------------------------------------ registry

_BASELINES = {
    "san2patch": (_san2patch_cases, _san2patch_patch, _san2patch_base),
    "patchagent": (_patchagent_cases, _patchagent_patch, _patchagent_base),
}

BASELINE_NAMES = tuple(_BASELINES)


def iter_cases(baseline: str, repo_root: Path) -> List[Case]:
    return _BASELINES[baseline][0](repo_root)


def find_case(baseline: str, repo_root: Path, key: str) -> Optional[Case]:
    """The one case whose ``key`` matches, or None. Used by the dashboard's per-CVE
    button, which is handed a key rather than iterating."""
    for case in iter_cases(baseline, repo_root):
        if case.key == key:
            return case
    return None


def patch_text(baseline: str, case: Case) -> Tuple[Optional[str], Optional[str]]:
    """``(git apply``-able diff text, None)`` or ``(None, why not)``."""
    return _BASELINES[baseline][1](case)


def benchmark_base(baseline: str, repo_root: Path, case: Case) -> Optional[str]:
    """The commit this baseline's benchmark pins for ``case``, or None if unknown."""
    return _BASELINES[baseline][2](repo_root, case)


def _looks_like_sha(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{7,40}", value or ""))


def _same_revision(left: Optional[str], right: Optional[str]) -> bool:
    """Prefix-wise equality — benchmarks abbreviate, project_info.csv does not."""
    left, right = (left or "").strip(), (right or "").strip()
    if not left or not right:
        return False
    return left.startswith(right) or right.startswith(left)


def base_plan(
    baseline: str, repo_root: Path, case: Case, dataset_revision: str,
    source_path: Optional[Path] = None,
) -> Dict[str, Optional[str]]:
    """Decide which commit this case's patch should be scored on, and say why.

    ``state`` is one of:

    ``same``        the benchmark pins our commit. Nothing changes.
    ``differs``     the benchmark pins a different commit, and we resolved it to
                    something usable. ``base_revision`` is set; the replay will
                    reconstruct there and re-prove every POV on the unpatched
                    tree first.
    ``unresolved``  the benchmark pins a ref we cannot resolve offline (a tag, and
                    the project clones are ``--depth 1`` so they carry none).
                    Scored on our base, as before, but recorded rather than
                    silently assumed equal — add it to ``KNOWN_TAG_COMMITS`` once
                    ``git ls-remote`` has settled it.
    ``unknown``     the benchmark is not cloned, or has no setup script for this
                    case. Scored on our base.

    Never guesses. Every path other than ``differs`` leaves the existing
    behaviour exactly as it was, which is what keeps this change from disturbing
    results anyone else already depends on.
    """
    benchmark = benchmark_base(baseline, repo_root, case)
    plan: Dict[str, Optional[str]] = {
        "benchmark_ref": benchmark,
        "dataset_revision": dataset_revision or None,
        "resolved": None,
        "base_revision": None,
        "state": "unknown",
    }
    if not benchmark:
        return plan
    if _same_revision(benchmark, dataset_revision):
        plan["state"], plan["resolved"] = "same", dataset_revision
        return plan

    known = KNOWN_TAG_COMMITS.get((case.case_id, benchmark))
    resolved = known or _rev_parse(source_path, benchmark)
    if resolved:
        plan["resolved"] = resolved
        if _same_revision(resolved, dataset_revision):
            plan["state"] = "same"
        else:
            plan["state"], plan["base_revision"] = "differs", resolved
        return plan

    if _looks_like_sha(benchmark):
        plan["state"], plan["base_revision"] = "differs", benchmark
        return plan
    plan["state"] = "unresolved"
    return plan


def _rev_parse(source_path: Optional[Path], ref: str) -> Optional[str]:
    """Resolve ``ref`` in the project's own clone, or None. Never raises."""
    if source_path is None or not (source_path / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(source_path), "rev-parse", f"{ref}^{{commit}}"],
            capture_output=True, text=True, errors="replace", timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.stdout.strip()
    return value if out.returncode == 0 and _looks_like_sha(value) else None
