"""Read-only view over the San2Patch baseline-tool benchmark results.

The sibling of ``loop_repair.py``, and deliberately the same row shape so the two
baselines can share one table and one filter (``baselines_index.py`` merges them).
Produced out-of-band by ``baselines/san2patch/server/`` on the run host and copied
into ``baselines/results/san2patch/<arm>/``; this module only reads it.

Layout differs from LoopRepair's in one way that matters here: San2Patch's index is
``aggregate.json`` rather than a CSV, and a case's artifacts live under the *batch*
that ran it (``<batch>/gen_diff/<case>/``) rather than a flat per-CVE directory. A
case attempted twice therefore has two artifact directories, and ``aggregate.json``
has already decided which one counts — the earliest complete attempt, so a re-run
cannot turn the benchmark into best-of-10. This module follows that decision rather
than re-deriving it, so the dashboard, ``RESULTS.md`` and the POV scores all describe
the same attempt.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import baseline_coverage
import config
import runs

# One arm for now; the directory name is the arm (benchmark + model), and adding a
# DeepSeek run means dropping a sibling directory in, not editing this module.
ARM = "vulnloc-haiku45"
ROOT = config.REPO_ROOT / "baselines" / "results" / "san2patch" / ARM

# Case ids are CVE-style or bug-tracker-style ("bugzilla-2633", "gnubug-25023").
# No "/" means no escaping ROOT — same path-traversal convention as loop_repair.py.
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")

LOG_NAME = "run.log"


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _aggregate() -> dict:
    return _read_json(ROOT / "aggregate.json") or {"summary": {}, "cases": []}


def _projects() -> Dict[str, str]:
    return _read_json(ROOT / "projects.json") or {}


def _case_dir(key: str) -> Optional[Path]:
    """The artifact directory of the *counted* attempt for this case."""
    if not KEY_RE.match(key):
        return None
    for c in _aggregate()["cases"]:
        if c["case_id"] == key:
            d = (ROOT / c["batch"] / "gen_diff" / key).resolve()
            return d if d.is_dir() and str(d).startswith(str(ROOT.resolve())) else None
    return None


def _pov_headline(case_dir: Optional[Path], subdir: str) -> Optional[Dict[str, Any]]:
    if case_dir is None:
        return None
    summary = _read_json(runs.eval_results_path(case_dir, subdir))
    if not summary:
        return None
    return {
        "score": summary.get("score"),
        "total": summary.get("total"),
        "all_blocked": summary.get("all_blocked"),
        "all_hardened": summary.get("all_hardened"),
    }


def list_results() -> List[Dict[str, Any]]:
    """One row per case, in the same shape ``loop_repair.list_results()`` returns."""
    projects = _projects()
    out: List[Dict[str, Any]] = []
    for c in _aggregate()["cases"]:
        cid = c["case_id"]
        d = _case_dir(cid)
        # `validity` is San2Patch-specific and load-bearing: a case that never
        # reached the model (API limit, harness fault) still wrote a res.txt saying
        # it failed. Surfacing it keeps the dashboard from showing an incident as a
        # repair failure -- the same distinction aggregate.py draws.
        valid = c.get("validity") == "valid"
        out.append(
            {
                "tool": "san2patch",
                "key": cid,
                "project": projects.get(cid, ""),
                "cve": cid,
                "status": c.get("status") or "unknown",
                "valid": valid,
                "patch_found": c.get("status") == "success",
                "elapsed_seconds": c.get("duration_s"),
                "tries": c.get("tries"),
                "prompt_tokens": c.get("input_tokens"),
                "completion_tokens": c.get("output_tokens"),
                "total_tokens": (c.get("input_tokens") or 0) + (c.get("output_tokens") or 0),
                "cost_usd": c.get("cost_usd"),
                "mean_load": c.get("mean_load"),
                # Timing measured while the host was loaded is not comparable; the
                # page says so rather than quietly showing the number.
                "contended": c.get("contended"),
                "batch": c.get("batch"),
                # Set when this case ran to completion twice. aggregate.py counts the
                # EARLIEST attempt (5 tries is the protocol; best-of-10 is not), so the
                # page has to show that a second, possibly different, outcome exists.
                "superseded_by": c.get("superseded_by"),
                "message": c.get("note") or ("" if valid else "no attempt reached the model"),
                "fix_pov": _pov_headline(d, "fix_pov"),
                "residual": _pov_headline(d, "residual"),
            }
        )
    out.sort(key=lambda r: (r["project"], r["cve"]))
    return out


def stats() -> Dict[str, Any]:
    rows = list_results()
    # Rate is over VALID rows only. Dividing by every recorded row would let an
    # API-limit casualty count as a repair failure, which is the exact error
    # aggregate.py exists to prevent.
    valid = [r for r in rows if r["valid"]]
    patched = sum(1 for r in valid if r["patch_found"])
    return {
        "total": len(rows),
        "patched": patched,
        "failed": len(valid) - patched,
        "success_rate": (patched / len(valid)) if valid else 0.0,
        "total_cost_usd": sum(r["cost_usd"] or 0.0 for r in rows),
        "total_tokens": sum(r["total_tokens"] or 0 for r in rows),
    }


_NO_PATCH_SKIP = "tool reported no patch"


def pov_summary(family: str = "fixpov") -> Optional[Dict[str, Any]]:
    """Headline of our re-scoring for one oracle family, from the roll-up
    score_patches.py writes. None until a scoring run has happened -- deliberately
    not zeros, since "not scored" and "blocked nothing" are opposite conclusions
    about a patch.

    Scored under intention-to-treat (see ``baseline_coverage``): the mean is over
    every shared subject carrying a certified suite of this family, so a case
    San2Patch produced no patch for counts as zero rather than vanishing from the
    denominator. The score sum is re-derived from the per-case rows rather than
    taken from the roll-up's ``mean_score``, which is already rounded to 4 places.
    """
    if family not in ("fixpov", "respov"):
        return None
    if family == "fixpov":
        # ``pov_scores_gtpov.json`` is the pre-rename name score_patches.py wrote;
        # already-recorded roll-ups keep it.
        d = _read_json(ROOT / "pov_scores_fixpov.json") or _read_json(ROOT / "pov_scores_gtpov.json")
    else:
        d = _read_json(ROOT / "pov_scores_respov.json")
    if not d:
        return None

    rows = d.get("rows") or []
    scores = [
        r["summary"]["score"]
        for r in rows
        if isinstance(r.get("summary"), dict) and r["summary"].get("score") is not None
    ]
    # A case with a ``superseded_by`` marker is NOT dropped here. ``aggregate.json``
    # has already chosen which attempt counts -- the earliest complete one, so a
    # re-run cannot turn the benchmark into best-of-10 -- and for these two cases
    # that attempt produced no patch. Scoring the later, luckier attempt instead
    # would be exactly the best-of-N the aggregate exists to prevent, and would
    # disagree with the row this page renders and with RESULTS.md.
    no_patch = [
        r for r in rows if (r.get("skip_reason") or "").startswith(_NO_PATCH_SKIP)
    ]
    zero_credited = baseline_coverage.zero_credited_from_cases(
        family,
        no_patch,
        slug_of=lambda r: r.get("project_slug"),
    )
    return baseline_coverage.summarize(
        scores,
        zero_credited,
        extra={
            "errored": d.get("errored"),
            "claimed_repaired": d.get("claimed_repaired"),
        },
    )


def get_result(key: str) -> Optional[Dict[str, Any]]:
    row = next((r for r in list_results() if r["key"] == key), None)
    if row is None:
        return None
    d = _case_dir(key)
    if d is None:
        return {**row, "has_patch": False, "traces": [], "logs_available": [],
                "fix_pov_eval": None, "residual_eval": None}
    patch = next(iter(sorted(d.glob("*success.diff"))), None)
    return {
        **row,
        "has_patch": patch is not None,
        # Every attempt's full LangGraph state -- the material for qualitative
        # analysis of *why* a patch looks the way it does.
        "traces": [f"{p.parent.name}/{p.name}" for p in sorted(d.glob("stage_*/*graph_output.json"))],
        "res_txt": _read_text(d / "res.txt"),
        "fix_pov_eval": runs._fix_pov_eval(d),
        "residual_eval": runs._residual_eval(d),
        "logs_available": [LOG_NAME] if (ROOT / "by-case" / f"{key}.log").is_file() else [],
    }


def get_diff(key: str) -> Optional[str]:
    d = _case_dir(key)
    if d is None:
        return None
    patch = next(iter(sorted(d.glob("*success.diff"))), None)
    return _read_text(patch) if patch else None


def get_log(key: str) -> Optional[str]:
    """The case's own runtime log, sliced out of its batch's interleaved run.log by
    ``index.py`` (the per-batch log holds five cases at once)."""
    if not KEY_RE.match(key):
        return None
    return _read_text(ROOT / "by-case" / f"{key}.log")


# stage_<N>_<M>/<name>_graph_output.json — the LangGraph state for one attempt.
# Two segments, both constrained, and the resolved parent must be the case dir's
# own stage folder: the same containment check _case_dir applies, one level down.
TRACE_RE = re.compile(r"^stage_[0-9]+_[0-9]+/[A-Za-z0-9_.-]+\.json$")


def get_trace(key: str, name: str) -> Optional[str]:
    """One attempt's full Tree-of-Thought state: every stage's reasoning, the
    candidate patches considered, and which was selected."""
    d = _case_dir(key)
    if d is None or not TRACE_RE.match(name):
        return None
    target = (d / name).resolve()
    if target.parent.parent != d.resolve() or not target.is_file():
        return None
    return _read_text(target)
