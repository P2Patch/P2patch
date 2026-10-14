#!/usr/bin/env python3
"""Render the cross-tool comparison table from the POV scores on disk.

    python3 baselines/pov_report.py               # markdown to stdout
    python3 baselines/pov_report.py --out baselines/POV_SCORES.md

Reads each baseline's ``pov_scores_<family>.json`` (written by ``score_patches.py``)
and answers the one question the tool's own numbers cannot: **of the patches each
tool declared correct, how many actually close the vulnerability** — measured against
the certified fixPOVs, which include variants the tool's single PoC does not.

The headline this produces is the gap between two columns:

    claimed repaired          what the tool reports (its own oracle)
    fully blocked by fixPOV    what survives ours

A patch can be in the first and not the second only one way: it rejected the exact
input that demonstrated the bug and nothing else. That difference is the finding.

Two reporting rules are baked in, because both are easy to get wrong:

*Cases with no POV manifest are excluded from the rate, not counted as failures.*
Our coverage gap is not the tool's defect. They are listed separately so the
denominator is always visible.

*A case that errored is excluded too, and reported.* A replay that could not build or
whose patch would not apply produced no evidence either way; folding it in as 0 would
credit our infrastructure problems to the tool's account.

*Which commit each score was taken on is stated, not assumed.* A benchmark can pin a
different commit than our dataset for the same CVE, and then the score is only meaningful
because the POVs were re-proven to reproduce on the unpatched tree there. That column is
the audit trail for it, and it also flags the reverse — a score computed against a POV
set that has since gained or lost members.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent

# San2Patch only. Other baselines in this repo are scored and analysed by their own
# owners; this report deliberately does not read or restate their results.
SOURCES = {
    "san2patch": ("San2Patch", Path("baselines/results/san2patch/vulnloc-haiku45")),
}


def _load(tool: str, family: str) -> Optional[dict]:
    p = REPO_ROOT / SOURCES[tool][1] / f"pov_scores_{family}.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _rows(tool: str) -> Dict[str, Dict[str, Any]]:
    """case_id -> {gt: row|None, res: row|None} merged across families."""
    out: Dict[str, Dict[str, Any]] = {}
    for family, key in (("fixpov", "gt"), ("respov", "res")):
        data = _load(tool, family)
        if not data:
            continue
        for r in data["rows"]:
            out.setdefault(r["case_id"], {})[key] = r
    return out


def _score(row: Optional[dict]) -> Optional[float]:
    s = (row or {}).get("summary") or {}
    return s.get("score")


def _fmt(row: Optional[dict], family: str) -> str:
    if not row:
        return "·"
    s = row.get("summary")
    if not s:
        # Distinguish "not applicable" from "not measured": a skip has a stated
        # reason, an errored replay has none and is a hole in the data.
        return f"– _{row['skip_reason']}_" if row.get("skip_reason") else "**errored**"
    if s.get("score") is None:
        return "n/a"
    flag = s.get("all_blocked") if family == "fixpov" else s.get("all_hardened")
    blocked = s.get("blocked", s.get("hardened_beyond_fix"))
    mark = "" if flag else " ⚠"
    return f"{s['score']:.2f} ({blocked}/{s['total']}){mark}"


def _base_note(row: Optional[dict]) -> List[str]:
    """Fragments saying which tree a number was taken on, and whether it is current.

    Returned as a list rather than a joined string because the gt and res families
    are reported side by side and usually say the *same* thing about the base —
    joining first and de-duplicating after cannot tell "both mention the base" from
    "they disagree", and printed the base twice in every mismatched row.
    """
    if not row:
        return []
    notes: List[str] = []
    base = row.get("base") or {}
    summary = row.get("summary") or {}
    state = base.get("state")
    if state == "differs":
        ref = base.get("benchmark_ref") or ""
        ours = (base.get("dataset_revision") or "")[:8]
        notes.append(f"scored at benchmark base `{ref}` (ours `{ours}`)")
        reval = summary.get("oracle_revalidation") or {}
        invalid = reval.get("invalid_pov_ids") or []
        if reval:
            notes.append(
                f"{len(reval.get('valid_pov_ids') or [])} POV(s) re-proven there"
                + (f", {len(invalid)} inconclusive" if invalid else "")
            )
    elif state == "unresolved":
        notes.append(f"benchmark base `{base.get('benchmark_ref')}` unresolved; scored at ours")
    if row.get("oracle_drift"):
        notes.append(f"**stale**: {row['oracle_drift']}")
    if row.get("stale_results"):
        notes.append("**orphaned results.json** — manifest retired")
    return notes


def render() -> str:
    md: List[str] = [
        "# Do the baselines' patches actually fix the vulnerability?",
        "",
        "Generated by `baselines/pov_report.py` from the per-case `fix_pov/results.json`",
        "written by `baselines/score_patches.py`. Every patch below was scored against the",
        "**same certified POV manifests** a pipeline run is scored against, on the same Docker",
        "images, by reconstructing the vulnerable tree and applying the tool's own patch.",
        "",
        "The base is our `buggy_commit_id` unless the **base / freshness** column says",
        "otherwise. A benchmark that pins a different commit for the same CVE is scored on",
        "*its* commit, and there every POV is first re-run on the unpatched tree — one that",
        "no longer reproduces is inconclusive, never counted as blocked.",
        "",
        "`gt` = fixPOVs (does the patch match the official upstream fix — higher is",
        "better). `res` = residual POVs (did it beat upstream — 0 is a perfectly good result).",
        "⚠ marks a patch that blocked some but not all POVs.",
        "",
    ]

    headline: List[str] = [
        "| tool | claimed repaired | scored | **fully blocked** | partial | mean gt score |",
        "|---|---|---|---|---|---|",
    ]
    for tool, (label, _) in SOURCES.items():
        data = _load(tool, "fixpov")
        if not data:
            headline.append(f"| {label} | — | not scored yet | | | |")
            continue
        scored = [r for r in data["rows"] if r.get("summary")]
        full = [r for r in scored if r["summary"].get("all_blocked")]
        partial = [r for r in scored if not r["summary"].get("all_blocked")]
        headline.append(
            f"| {label} | {data['claimed_repaired']} | {len(scored)} | "
            f"**{len(full)}** | {len(partial)} | "
            f"{data['mean_score'] if data['mean_score'] is not None else '—'} |"
        )
    md += headline + [""]

    for tool, (label, _) in SOURCES.items():
        rows = _rows(tool)
        if not rows:
            continue
        md += [f"## {label}", "",
               "| case | project | claimed | gt | res | base / freshness |",
               "|---|---|---|---|---|---|"]
        for cid in sorted(rows, key=lambda c: (-(_score(rows[c].get("gt")) is not None), c)):
            r = rows[cid]
            base = r.get("gt") or r.get("res") or {}
            claimed = "repaired" if base.get("claimed_repaired") else "no patch"
            # Union, order-preserving: the two families almost always agree about
            # the base, and a res-only caveat (its manifest drifted, gt's did not)
            # must still survive.
            seen: List[str] = []
            for fragment in _base_note(r.get("gt")) + _base_note(r.get("res")):
                if fragment not in seen:
                    seen.append(fragment)
            note = "; ".join(seen)
            md.append(f"| `{cid}` | {base.get('project_slug', '') or ''} | {claimed} | "
                      f"{_fmt(r.get('gt'), 'fixpov')} | {_fmt(r.get('res'), 'respov')} | {note} |")
        md.append("")

    return "\n".join(md) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, help="write markdown here instead of stdout")
    a = ap.parse_args()
    text = render()
    if a.out:
        a.out.write_text(text, encoding="utf-8")
        print(f"wrote {a.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
