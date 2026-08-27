"""Read-only view over the PatchAgent baseline-tool benchmark results.

The sibling of ``san2patch.py``, deliberately the same row shape and the same seven
entry points, so the two baselines read the same way in the UI. Produced out of band
in PatchAgent's own artifact container and normalized into
``baselines/results/patchagent/<arm>/`` by ``baselines/patchagent/normalize_run.py``;
this module only reads it.

Three things differ from San2Patch's layout, and all three are properties of the data
rather than choices made here:

* **The arm holds two batches, and that is the point.** 14 cases ran at
  ``--max-iteration 3``; one (coreutils ``ca99c52`` = our ``gnubug-25023``) ran at 15
  because it fails at 3. Those are two experiments, so they are two batches, and each
  row carries its own ``max_iteration`` plus ``effort_comparable``. Nothing in this
  module produces a single "15 cases at one setting" number, because the data does not
  support one.
* **One PatchAgent run is not always one of our cases.** ``list_results()`` returns one
  row per ``case_id`` (our CVE — the join key, and the only key the POV scores exist at),
  so the single ``libtiff c421b99`` run appears twice: as CVE-2016-3186 (0/2 POVs
  blocked) and as CVE-2016-5314 (2/2). ``shared_run_with`` says so on both rows, and
  ``stats()`` de-duplicates every cost and effort total on ``patchagent_case`` so that
  one run's spend is counted once.
* **Cost is measured, not estimated.** ``cost_usd`` is derived from token counts obtained
  by re-counting every recorded call through Anthropic's ``count_tokens`` endpoint, tool
  schemas included. Raw traces are committed so the counts can be re-derived.
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
# second model means dropping a sibling directory in, not editing this module.
ARM = "skyset-haiku45"
ROOT = config.REPO_ROOT / "baselines" / "results" / "patchagent" / ARM

# Case ids are CVE-style or bug-tracker-style ("gnubug-25023", "bugzilla-2611").
# No "/" means no escaping ROOT — same path-traversal convention as san2patch.py.
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")

DRIVER_LOG = "driver.log"
FUNCTIONAL_LOG = "functional.log"


def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _aggregate() -> dict:
    return _read_json(ROOT / "aggregate.json") or {"summary": {}, "cases": []}


def _projects() -> Dict[str, str]:
    return _read_json(ROOT / "projects.json") or {}


def _case_row(key: str) -> Optional[dict]:
    if not KEY_RE.match(key):
        return None
    return next((c for c in _aggregate()["cases"] if c["case_id"] == key), None)


def _case_dir(key: str) -> Optional[Path]:
    """The artifact directory of this case, under the batch that ran it."""
    row = _case_row(key)
    if row is None:
        return None
    d = (ROOT / row["batch"] / "gen_patch" / key).resolve()
    return d if d.is_dir() and str(d).startswith(str(ROOT.resolve())) else None


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
    """One row per case_id, in the same shape ``san2patch.list_results()`` returns
    plus the PatchAgent-specific effort/cost fields the page has to show."""
    projects = _projects()
    out: List[Dict[str, Any]] = []
    for c in _aggregate()["cases"]:
        cid = c["case_id"]
        d = _case_dir(cid)
        # `validity` is load-bearing for the same reason it is in san2patch.py: the
        # one case whose functional gate is broken on this machine never reached the
        # model, and showing it as a repair failure would be a lie about the tool.
        valid = c.get("validity") == "valid"
        out.append(
            {
                "tool": "patchagent",
                "key": cid,
                "project": projects.get(cid, c.get("project", "")),
                "cve": cid,
                "status": c.get("status") or "unknown",
                "valid": valid,
                "patch_found": c.get("status") == "patched",
                "elapsed_seconds": c.get("duration_s"),
                # PatchAgent's own retry unit is a validate() call; `tries` keeps the
                # column name the San2Patch table already uses.
                "tries": c.get("validate_calls"),
                "agents_used": c.get("agents_used"),
                "rejected_attempts": c.get("rejected_attempts"),
                "prompt_tokens": c.get("input_tokens"),
                "completion_tokens": c.get("output_tokens"),
                "total_tokens": (c.get("input_tokens") or 0) + (c.get("output_tokens") or 0),
                "cost_usd": c.get("cost_usd"),
                "cost_basis": c.get("cost_basis"),
                "llm_calls": c.get("llm_calls"),
                # The non-uniform attempt budget. 14 cases ran at 3, one at 15; a row
                # with effort_comparable=false is not comparable with the rest on effort
                # and every consumer must be able to see that without a footnote.
                "max_iteration": c.get("max_iteration"),
                "effort_comparable": c.get("effort_comparable"),
                "batch": c.get("batch"),
                # Non-empty when ONE PatchAgent run's single patch covers more than one
                # of our CVEs (libtiff c421b99 -> CVE-2016-3186 + CVE-2016-5314). Cost
                # and effort on those rows belong to the run, not to the CVE.
                "shared_run_with": c.get("shared_run_with") or [],
                "functional_baseline": c.get("functional_baseline"),
                "message": c.get("note") or "",
                "fix_pov": _pov_headline(d, "fix_pov"),
                "residual": _pov_headline(d, "residual"),
            }
        )
    out.sort(key=lambda r: (r["project"], r["cve"]))
    return out


def stats() -> Dict[str, Any]:
    rows = list_results()
    summary = _aggregate()["summary"]
    # Rate is over VALID rows only, and cost/effort totals de-duplicate on the
    # PatchAgent run: `patched` counts our CVEs (16) while `runs` counts PatchAgent
    # invocations (15), and conflating them would either inflate the spend or
    # under-report the coverage.
    valid = [r for r in rows if r["valid"]]
    patched = sum(1 for r in valid if r["patch_found"])
    by_native: Dict[str, Dict[str, Any]] = {}
    for c in _aggregate()["cases"]:
        if c.get("validity") == "valid":
            by_native.setdefault(c["patchagent_case"], c)
    return {
        "total": len(rows),
        "patched": patched,
        "failed": len(valid) - patched,
        "not_runnable": len(rows) - len(valid),
        "not_runnable_ids": summary.get("not_runnable_ids", []),
        "success_rate": (patched / len(valid)) if valid else 0.0,
        "patchagent_runs": len(by_native),
        # De-duplicated on the native run: one patch covering two CVEs is billed once.
        "total_cost_usd": round(sum(c.get("cost_usd") or 0.0 for c in by_native.values()), 4),
        "cost_basis": "measured_tokens",
        "cost_note": summary.get("cost_note", ""),
        "total_tokens": sum((c.get("input_tokens") or 0) + (c.get("output_tokens") or 0)
                            for c in by_native.values()),
        "llm_calls": summary.get("llm_calls_total"),
        # The iteration split, as data rather than prose, so the page cannot show a
        # single rate without also being able to show that the budget was not uniform.
        "max_iteration_3": summary.get("max_iteration_3"),
        "max_iteration_other": summary.get("max_iteration_other") or {},
        "cases_sharing_a_run": summary.get("cases_sharing_a_run") or [],
        "model": summary.get("model"),
        "baseline_commit": summary.get("baseline_commit"),
    }


def pov_summary(family: str = "fixpov") -> Optional[Dict[str, Any]]:
    """Headline of our fixPOV (or residual) re-scoring. None until a scoring run
    has happened -- deliberately not zeros, since "not scored" and "blocked nothing"
    are opposite conclusions about a patch."""
    if family not in ("fixpov", "respov"):
        return None
    d = _read_json(ROOT / f"pov_scores_{family}.json")
    if not d and family == "fixpov":
        # Roll-ups recorded before the fixPOV rename were written under the old name.
        d = _read_json(ROOT / "pov_scores_gtpov.json")
    if not d:
        return None
    rows = d.get("rows") or []
    scores = [
        r["summary"]["score"]
        for r in rows
        if isinstance(r.get("summary"), dict) and r["summary"].get("score") is not None
    ]
    # Intention-to-treat, like the other two baselines -- but a no-op here, and that
    # is the point: PatchAgent shipped a patch for every shared subject it attempted,
    # so nothing is credited zero and ``n`` stays the scored count. The one subject
    # it never attempted (``gnubug-19784``, whose own functional gate hardcodes an
    # expected failure count our environment does not reproduce) is a non-attempt,
    # not a repair failure, and stays out of the denominator.
    never_attempted = set(stats().get("not_runnable_ids") or [])
    no_patch = [
        r for r in rows if (r.get("skip_reason") or "").startswith("tool reported no patch")
    ]
    zero_credited = baseline_coverage.zero_credited_from_cases(
        family,
        no_patch,
        slug_of=lambda r: r.get("project_slug"),
        is_non_attempt=lambda r: r.get("case_id") in never_attempted,
    )
    return baseline_coverage.summarize(
        scores,
        zero_credited,
        extra={
            "errored": d.get("errored"),
            "claimed_repaired": d.get("claimed_repaired"),
            # Per-POV totals as well as per-case: the headline for this arm is stated
            # in POVs (29/37 fixPOVs blocked), and a case-level count alone loses that.
            "povs_total": d.get("povs_total"),
            "povs_blocked": d.get("povs_blocked"),
            "scoring_note": d.get("scoring_note", ""),
        },
    )


def get_result(key: str) -> Optional[Dict[str, Any]]:
    row = next((r for r in list_results() if r["key"] == key), None)
    if row is None:
        return None
    d = _case_dir(key)
    if d is None:
        return {**row, "has_patch": False, "traces": [], "logs_available": [],
                "attempts": [], "fix_pov_eval": None, "residual_eval": None}
    logs = []
    if (ROOT / "by-case" / f"{key}.log").is_file():
        logs.append(DRIVER_LOG)
    if (d / "functional.log").is_file():
        logs.append(FUNCTIONAL_LOG)
    return {
        **row,
        "has_patch": (d / "patch.diff").is_file(),
        # One file per agent attempt (PatchAgent's `DefaultPolicy` ladder). The
        # 15-iteration case has seven, totalling 1.1 MB, so these load on demand.
        "traces": sorted(p.name for p in (d / "agents").glob("agent_*.json")),
        # Every candidate submitted to validate(), with the FULL validator verdict --
        # a rejection carries the post-patch symbolized sanitizer report.
        "attempts": _read_json(d / "attempts.json") or [],
        "fix_pov_eval": runs._fix_pov_eval(d),
        "residual_eval": runs._residual_eval(d),
        "logs_available": logs,
    }


def get_diff(key: str) -> Optional[str]:
    d = _case_dir(key)
    if d is None:
        return None
    patch = d / "patch.diff"
    return _read_text(patch) if patch.is_file() else None


def get_log(key: str, name: str) -> Optional[str]:
    """Two logs exist, and only for some cases: the complete driver log (kept only for
    the 15-iteration case, which is the one whose ladder is worth reading) and the
    pre-LLM functional baseline for this case."""
    if not KEY_RE.match(key):
        return None
    if name == DRIVER_LOG:
        return _read_text(ROOT / "by-case" / f"{key}.log")
    if name == FUNCTIONAL_LOG:
        d = _case_dir(key)
        return _read_text(d / "functional.log") if d else None
    return None


# agents/agent_<NN>.json — one agent attempt's full nvwa context. One segment, fully
# constrained, and the resolved parent must be the case dir's own agents/ folder: the
# same containment check _case_dir applies, one level down.
TRACE_RE = re.compile(r"^agent_[0-9]+\.json$")


def get_trace(key: str, name: str) -> Optional[str]:
    """One agent attempt's full context: every tool call it made (`viewcode`,
    `locate`, `validate`), the arguments, and what came back."""
    d = _case_dir(key)
    if d is None or not TRACE_RE.match(name):
        return None
    target = (d / "agents" / name).resolve()
    if target.parent != (d / "agents").resolve() or not target.is_file():
        return None
    return _read_text(target)
