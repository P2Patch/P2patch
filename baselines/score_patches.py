#!/usr/bin/env python3
"""Score a whole baseline tool's patches against our certified POV manifests.

    python3 baselines/score_patches.py san2patch --family fixpov --dry-run
    python3 baselines/score_patches.py san2patch --family both
    python3 baselines/score_patches.py san2patch --family fixpov --case CVE-2017-7601

WHY THIS EXISTS. ``fixpov replay-patch`` / ``respov replay-patch`` already score **one**
caller-supplied diff against a project's certified manifests, and the dashboard wires a
button to them per CVE. But the comparison we actually need is every patch of every
baseline scored by the same oracle — ~30 patches — and clicking 30 buttons is not a
reproducible method. This driver is the batch form: it walks a
baseline's cases, maps each to its ``project_slug``, normalizes the patch
(``baselines/patch_source.py``), shells out to the same CLI the button uses, and writes
each result to the same per-case ``<family>/results.json`` the dashboard already reads.
Nothing here re-implements scoring; it is scheduling and bookkeeping only.

THREE THINGS THIS DELIBERATELY DOES.

*Skips what is already scored.* A full pass is hours of Docker builds, and it will be
interrupted. ``--force`` re-scores. Resumption has to be the default or the driver is
unusable at this size.

*Records why a case was NOT scored, per case, in the roll-up.* A blank cell in the final
comparison table is the failure mode to avoid: "no fixPOV score" can mean the tool found
no patch (expected, not a gap), no POV manifest exists yet (our gap), or the patch would
not apply to the reconstructed tree (a real finding about that patch). Those must not
look alike.

*Groups by project.* ``_ReplayCheckout`` reuses one reconstruction checkout per project
and keeps ignored build output between replays, so the cases of a multi-case project
(libtiff has 13) pay for one cold build instead of thirteen. Ordering by slug is the
whole optimization; the CLI does the caching.

TWO THINGS IT CHECKS THAT ARE EASY TO ASSUME AWAY.

*Which commit the patch is a diff against.* Sharing a case id with a benchmark does not
mean sharing the tree. San2Patch's VulnLoc pins two zziplib CVEs at the commit of
upstream's *first, incomplete* fix, where we pin them before any fix — so their patch
either would not apply to our tree or applied and then would not compile. When the bases
differ, the patch is scored on its own base and the replay re-proves every POV on the
unpatched tree there first (``--base-revision``); a POV that no longer reproduces at that
commit is recorded inconclusive rather than credited to the tool. See
``patch_source.base_plan``.

*Whether the oracle moved since the score was taken.* These POV sets are actively
authored; a manifest that gained POVs after a case was scored leaves a stale number that
"already scored" would happily keep forever. Every skipped row is compared against the
current manifest and reports ``oracle_drift``; ``--recheck-stale`` re-scores those.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
from security_pipeline import paths as _paths  # noqa: E402
sys.path.insert(0, str(REPO_ROOT))

from baselines import patch_source as ps  # noqa: E402

FAMILIES = {
    "fixpov": ("fix_pov", "fix_povs"),
    "respov": ("residual", "residual_povs"),
}
# The fixPOV family used to be "gtpov" and wrote ``<case>/ground_truth/results.json``;
# recorded result trees under baselines/results/ still carry that layout.
LEGACY_FAMILY_ALIASES = {"gtpov": "fixpov"}
LEGACY_RESULTS_SUBDIR = {"fixpov": "ground_truth"}

# Roll-up lands beside each baseline's own results, so a baseline directory stays
# self-describing — same reason San2Patch's RESULTS.md/INDEX.md live with its runs.
ROLLUP_DIR = {
    "san2patch": ps.SAN2PATCH_RESULTS,
}


def _manifest(family: str, slug: str) -> Path:
    return REPO_ROOT / FAMILIES[family][1] / slug / "manifest.json"


def _results_path(family: str, case: ps.Case) -> Path:
    """Where this family's score for ``case`` lives. New scores go under the new
    name; a case scored before the rename is still found under the legacy one."""
    current = case.artifact_dir / FAMILIES[family][0] / "results.json"
    legacy_subdir = LEGACY_RESULTS_SUBDIR.get(family)
    if not current.exists() and legacy_subdir:
        legacy = case.artifact_dir / legacy_subdir / "results.json"
        if legacy.exists():
            return legacy
    return current


def _source_path(slug: str) -> Path:
    return _paths.project_sources_dir(REPO_ROOT) / slug


def _oracle_signature(povs: List[dict]) -> List[List]:
    """What a score is a statement about: which POVs ran, and with what command.

    Deliberately not a hash of the whole manifest — prose fields (descriptions,
    ``exploit_path``) get edited constantly and re-running hours of Docker over a
    reworded sentence is not useful. A POV added, removed, renamed, or given a
    different command or exit-code contract does change the answer.
    """
    return sorted(
        [str(pov.get("id", "")), str(pov.get("command", "")),
         str(pov.get("reproduces_exit_code", 0))]
        for pov in povs or []
    )


def _oracle_drift(manifest_path: Path, summary: dict) -> Optional[str]:
    """How the POV set has changed since ``summary`` was produced, or None."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    current = _oracle_signature(manifest.get("povs") or [])
    scored = _oracle_signature(summary.get("povs") or [])
    if current == scored:
        return None
    now_ids = {row[0] for row in current}
    then_ids = {row[0] for row in scored}
    added, removed = sorted(now_ids - then_ids), sorted(then_ids - now_ids)
    changed = sorted(
        row[0] for row in current
        if row[0] in then_ids and row not in scored
    )
    parts = []
    if added:
        parts.append(f"+{len(added)} new POV(s): {', '.join(added)}")
    if removed:
        parts.append(f"-{len(removed)} removed: {', '.join(removed)}")
    if changed:
        parts.append(f"{len(changed)} changed: {', '.join(changed)}")
    return "; ".join(parts) or "POV set changed"


def _plan(baseline: str, family: str, rows_by_cve: Dict[str, Dict[str, str]], force: bool,
          only: Optional[str], project: Optional[str], recheck_stale: bool) -> List[dict]:
    """One row per case: either a scoreable job, or a skip with a stated reason."""
    rows = []
    for case in ps.iter_cases(baseline, REPO_ROOT):
        if only and case.case_id != only:
            continue
        info = rows_by_cve.get(case.case_id) or {}
        slug = info.get("project_slug") or None
        if project and slug != project:
            continue
        out = _results_path(family, case)
        row = {
            "case_id": case.case_id, "key": case.key, "project_slug": slug,
            "claimed_repaired": case.claimed_repaired,
            "results_path": str(out.relative_to(REPO_ROOT)),
            "action": None, "skip_reason": None, "patch": None,
        }
        if slug:
            # Recorded for every case, matched or not: a table that only shows the
            # mismatches gives no way to tell "we checked and they agree" from
            # "nobody looked".
            row["base"] = ps.base_plan(
                baseline, REPO_ROOT, case, info.get("buggy_commit_id", ""),
                source_path=_source_path(slug),
            )
        if not case.claimed_repaired:
            row["action"], row["skip_reason"] = "skip", "tool reported no patch for this case"
        elif slug is None:
            row["action"], row["skip_reason"] = "skip", "no project_info.csv row for this case id"
        elif not _manifest(family, slug).is_file():
            row["action"], row["skip_reason"] = "skip", f"no curated {family} manifest for {slug}"
            if out.is_file():
                # A manifest that was retired (libjpeg-turbo's residual set was
                # audited down to "no gaps exist", which by design means deleting
                # manifest.json) leaves a results.json behind. Dropping it from the
                # roll-up is right, but silently is not: the number is still on disk
                # and reads as a real score to anything that opens the file.
                row["stale_results"] = True
                row["skip_reason"] += (
                    f" — but {out.relative_to(REPO_ROOT)} still holds a score from when "
                    "one existed; that file is now orphaned and should be deleted"
                )
        elif out.is_file() and not force:
            # Skipped, but NOT absent from the report: load what is already on disk.
            # Without this a case scored by an earlier invocation drops out of the
            # roll-up's counts and renders as "—" in the comparison table, so an
            # interrupted-and-resumed run silently reports fewer results than it has.
            summary = None
            try:
                summary = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
            drift = _oracle_drift(_manifest(family, slug), summary) if summary else None
            if drift and recheck_stale:
                text, err = ps.patch_text(baseline, case)
                if err:
                    row["action"], row["skip_reason"] = "skip", err
                else:
                    row["action"], row["patch"] = "score", text
                row["oracle_drift"] = drift
            else:
                row["action"], row["skip_reason"] = "skip", "already scored (use --force to redo)"
                if summary is not None:
                    row["summary"] = summary
                if drift:
                    # Loud, but not acted on: re-scoring is hours of Docker and the
                    # decision of when to spend it belongs to whoever is running this.
                    row["oracle_drift"] = drift
                    row["skip_reason"] = (
                        f"already scored, but the oracle has since changed ({drift}) — "
                        "re-run with --recheck-stale"
                    )
        else:
            text, err = ps.patch_text(baseline, case)
            if err:
                row["action"], row["skip_reason"] = "skip", err
            else:
                row["action"], row["patch"] = "score", text
        rows.append(row)
    # Group by project so a multi-case project reuses one reconstruction checkout.
    rows.sort(key=lambda r: (r["project_slug"] or "~", r["case_id"]))
    return rows


def _run_one(baseline: str, family: str, row: dict, args: argparse.Namespace) -> dict:
    staged = (REPO_ROOT / row["results_path"]).parent.parent / f"{family}_replay"
    staged.mkdir(parents=True, exist_ok=True)
    patch_file = staged / "staged_patch.diff"
    patch_file.write_text(row["patch"], encoding="utf-8")

    cmd = [
        sys.executable, "-m", "security_pipeline", family, "replay-patch",
        "--project", row["project_slug"],
        "--patch-file", str(patch_file),
        "--out", str(REPO_ROOT / row["results_path"]),
        # The label namespaces this patch's scratch reconstruction dir. Prefixing with
        # the baseline keeps another tool's patch for the SAME project from sharing a
        # checkout with ours -- more than one baseline has a libtiff CVE-2017-7601 patch.
        "--label", f"{baseline}-{row['key']}",
        "--workspace-root", str(REPO_ROOT),
        "--runs-dir", str(args.runs_dir),
        "--command-timeout-seconds", str(args.command_timeout_seconds),
        "--build-timeout-seconds", str(args.build_timeout_seconds),
    ]
    base_revision = (row.get("base") or {}).get("base_revision")
    if base_revision:
        # Only ever set when the benchmark demonstrably pins a different commit
        # (state == "differs"); an unresolved or unknown base leaves this off and
        # the replay uses our buggy_commit_id exactly as it always has.
        cmd += ["--base-revision", base_revision]
    if args.skip_docker_build:
        cmd.append("--skip-docker-build")

    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    out = {"stdout": proc.stdout.strip()[-2000:], "stderr": proc.stderr.strip()[-2000:],
           "returncode": proc.returncode}
    results = REPO_ROOT / row["results_path"]
    if results.is_file():
        try:
            out["summary"] = json.loads(results.read_text(encoding="utf-8"))
        except ValueError:
            out["summary"] = None
    return out


def _rollup(baseline: str, family: str, rows: List[dict]) -> dict:
    scored = [r for r in rows if r.get("summary")]
    key = "all_blocked" if family == "fixpov" else "all_hardened"
    scores = [r["summary"]["score"] for r in scored if r["summary"].get("score") is not None]
    states = [(r.get("base") or {}).get("state") for r in rows if r.get("base")]
    return {
        "baseline": baseline, "family": family,
        "cases": len(rows),
        "claimed_repaired": sum(1 for r in rows if r["claimed_repaired"]),
        "scored": len(scored),
        "skipped": sum(1 for r in rows if r["action"] == "skip"),
        "errored": sum(1 for r in rows if r["action"] == "score" and not r.get("summary")),
        "fully_blocked": sum(1 for r in scored if r["summary"].get(key)),
        "mean_score": round(sum(scores) / len(scores), 4) if scores else None,
        # Headline counts for the two things that used to be invisible: cases the
        # benchmark pins to a different commit than we do, and scores computed
        # against a POV set that has since moved.
        "base_mismatched": sum(1 for state in states if state == "differs"),
        "base_unresolved": sum(1 for state in states if state == "unresolved"),
        "oracle_drifted": sum(1 for r in rows if r.get("oracle_drift")),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline", choices=ps.BASELINE_NAMES)
    ap.add_argument("--family", choices=["fixpov", "respov", "both", *LEGACY_FAMILY_ALIASES],
                    default="fixpov")
    ap.add_argument("--case", help="score only this case id")
    ap.add_argument("--project", help="score only this project slug")
    ap.add_argument("--force", action="store_true", help="re-score cases already scored")
    ap.add_argument("--recheck-stale", action="store_true",
                    help="re-score cases whose POV manifest has changed since they were scored")
    ap.add_argument("--no-rollup", action="store_true",
                    help="score, but do not write pov_scores_<family>.json (for parallel "
                         "per-project workers; rebuild the roll-up with one final pass)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan (what would be scored, and why each skip) and exit")
    ap.add_argument("--runs-dir", type=Path, default=REPO_ROOT / "security_pipeline_runs",
                    help="where reconstruction checkouts are cached")
    ap.add_argument("--skip-docker-build", action="store_true")
    ap.add_argument("--command-timeout-seconds", type=int, default=900)
    ap.add_argument("--build-timeout-seconds", type=int, default=3600)
    a = ap.parse_args()

    rows_by_cve = ps.project_rows(REPO_ROOT)
    a.family = LEGACY_FAMILY_ALIASES.get(a.family, a.family)
    families = ["fixpov", "respov"] if a.family == "both" else [a.family]
    rc = 0

    for family in families:
        rows = _plan(a.baseline, family, rows_by_cve, a.force, a.case, a.project, a.recheck_stale)
        todo = [r for r in rows if r["action"] == "score"]
        print(f"\n=== {a.baseline} / {family} ===")
        print(f"  cases            : {len(rows)}")
        print(f"  to score         : {len(todo)}")
        # Every base reading "unknown" means the benchmark is not cloned, not that
        # the bases agree. Those look identical in the output and only one of them
        # is safe, so say which it is -- a scoring pass run on a machine without
        # vendor/ would otherwise silently reproduce exactly the bug this checks for.
        with_base = [r for r in rows if r.get("base")]
        if with_base and all(r["base"]["state"] == "unknown" for r in with_base):
            print(f"  !! {ps.SAN2PATCH_BENCHMARK} is not cloned: every case's base commit is "
                  f"UNKNOWN, so a benchmark that pins a different revision than ours will not "
                  f"be detected. Run `./setup.sh san2patch-benchmark` first.")
        for r in rows:
            base = r.get("base") or {}
            if base.get("state") == "differs":
                print(f"    base {r['case_id']:<16} benchmark pins {base['benchmark_ref']} "
                      f"(!= our {(base.get('dataset_revision') or '')[:12]}) — scoring there, "
                      f"oracle re-proven on the unpatched tree first")
            elif base.get("state") == "unresolved":
                print(f"    base {r['case_id']:<16} benchmark pins {base['benchmark_ref']}, "
                      f"unresolvable offline — scored on our base; settle it with "
                      f"`git ls-remote` and add it to KNOWN_TAG_COMMITS")
        for r in rows:
            if r["action"] == "skip":
                print(f"    skip {r['case_id']:<16} {r['skip_reason']}")
        if a.dry_run:
            for r in todo:
                base = (r.get("base") or {}).get("base_revision")
                at = f" @ {base[:12]}" if base else ""
                print(f"    would score {r['case_id']:<16} -> {r['project_slug']}{at}")
            continue

        for i, r in enumerate(todo, 1):
            print(f"  [{i}/{len(todo)}] {r['case_id']} ({r['project_slug']}) ... ", flush=True)
            res = _run_one(a.baseline, family, r, a)
            r.pop("patch", None)
            r["summary"] = res.get("summary")
            r["returncode"] = res["returncode"]
            if res.get("summary"):
                s = res["summary"]
                print(f"      score={s.get('score')} total={s.get('total')} "
                      f"blocked={s.get('blocked', s.get('hardened_beyond_fix'))} "
                      f"errored={s.get('errored')}")
            else:
                # A replay that produced no results.json is an infrastructure failure
                # (image build, patch would not apply), not a score of zero -- never
                # let it read as "this patch blocked nothing".
                r["error"] = res["stderr"] or res["stdout"] or "no results.json produced"
                print(f"      FAILED rc={res['returncode']}: {r['error'][:200]}")
                rc = 1

        for r in rows:
            r.pop("patch", None)
        # A skipped-but-already-scored row carries its summary from disk (see _plan),
        # so the roll-up counts it exactly like a freshly scored one.
        summary = _rollup(a.baseline, family, rows)
        print(f"  scored={summary['scored']} errored={summary['errored']} "
              f"mean_score={summary['mean_score']}")
        print(f"  base_mismatched={summary['base_mismatched']} "
              f"base_unresolved={summary['base_unresolved']} "
              f"oracle_drifted={summary['oracle_drifted']}")
        if a.no_rollup:
            # A --project worker's roll-up would cover only that project, and three
            # of them racing on one file is a torn write away from a roll-up that
            # parses but is wrong. Workers write per-case results.json only; one
            # final pass with no --project rebuilds the whole file from disk.
            print(f"  (--no-rollup: per-case results written, roll-up not touched)")
            continue
        out = REPO_ROOT / ROLLUP_DIR[a.baseline] / f"pov_scores_{family}.json"
        out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"  wrote {out.relative_to(REPO_ROOT)}")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
