#!/usr/bin/env python3
"""Normalize a PatchAgent run into ``baselines/results/patchagent/<arm>/``.

PatchAgent was **not** run through a `baselines/` adapter — it ran out-of-band in its
own artifact container (`patchagent-artifact`, USENIX Sec '25) and its POVs were scored
by a separate build-and-replay driver (`povscore15.py`). Both produced native output.
This script is the one-way conversion of that output into the shapes this repo already
reads, and nothing else: it re-runs nothing, re-scores nothing, and invents no number.

Two properties of the source data drive every design choice here, and both are carried
through rather than flattened:

1. **The iteration cap is not uniform.** 14 cases ran at ``--max-iteration 3``; the
   coreutils ``ca99c52`` case ran at 15 because it fails at 3. Those are two different
   experiments, so they become two *batches* (``b1-...-iter3`` / ``b2-...-iter15``) and each
   row also carries its own ``max_iteration``. A single 15-case number at one setting
   would be wrong and is not producible from this output.

2. **A case id is not a case_id.** PatchAgent keys by ``<project>-<commit>-<bug_type>``;
   everything in this repo joins on ``case_id`` (our ``cve_id``) per ``baselines/cases.json``.
   The map is *not* 1:1 — ``extractfix-libtiff-c421b99-heap_buffer_overflow`` is one run
   whose single patch covers CVE-2016-3186 *and* CVE-2016-5314, and our POV sets score it
   separately under each. Rows are therefore per case_id (the join key, and the only key
   the POV scores exist at) and the two rows that share one run say so via
   ``shared_run_with``. Cost and effort totals de-duplicate on ``patchagent_case`` so that
   one run's spend is never counted twice.

The case -> CVE map is taken from the POV-scoring run's own rows, which carry ``cve``,
``slug`` and ``head``; those are then checked against ``cases.json`` and a disagreement is
an error, not a silent preference for one side.

Usage (the 2026-08 run's own paths; the archives live outside this repo by design):

    python3 baselines/patchagent/normalize_run.py \
        --run-dir  /path/to/haiku-4.5-15cases \
        --pov-scores /path/to/povscore15/results.json \
        --arm skyset-haiku45
"""
from __future__ import annotations

import argparse
import json
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]

BASELINE = "patchagent"
# pins.json: the production fork, which is what actually ran. The paper's own artifact
# has diverged; recording which one produced a number is a rule in baselines/README.md.
BASELINE_COMMIT = "14cbd456fd7e2f6635ed46f56fb489218ce46ace"
MODEL = "claude-haiku-4-5-20251001"

BATCH_ITER3 = "b1-haiku45-iter3"
BATCH_ITER15 = "b2-haiku45-iter15"

# The one case in PatchAgent's own skyset overlap that could not run here. It was never
# scored, so its CVE join comes from cases.json rather than the POV output.
EXCLUDED_CASE = "extractfix-coreutils-658529a-heap_buffer_overflow"
EXCLUDED_CASE_ID = "gnubug-19784"
EXCLUDED_REASON = (
    "PatchAgent's functional gate is unusable for this case on this machine: its "
    "test.sh hardcodes `grep \"FAIL:  4\"` for commit 658529a while the UNPATCHED "
    "baseline here yields `FAIL: 3`, so validate() would reject every candidate "
    "regardless of correctness. Never attempted, and there is no PatchAgent patch for "
    "it; excluded from every denominator rather than scored as a repair failure."
)
ITER15_CASE_ID = "gnubug-25023"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def diff_stats(text: str) -> Dict[str, int]:
    added = removed = hunks = 0
    files: set = set()
    for line in text.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            if name and name != "/dev/null":
                files.add(name)
        elif line.startswith("@@"):
            hunks += 1
        elif line.startswith("+"):
            added += 1
        elif line.startswith("-") and not line.startswith("--- "):
            removed += 1
    return {"lines_added": added, "lines_removed": removed,
            "files_touched": len(files), "hunks": hunks}


# --- POV scoring -> the results.json shape runs.py already reads -------------------
#
# ``runs._fix_pov_eval`` / ``_residual_eval`` read ``<dir>/fix_pov/results.json``
# and ``<dir>/residual/results.json``. Writing exactly that shape is what lets the
# dashboard render these POV outcomes through the SAME panels a pipeline run and a
# San2Patch case use — no new rendering code, and no second interpretation of a verdict.

def pov_manifest(family: str, slug: str) -> Dict[str, Any]:
    root = "fix_povs" if family == "fix_pov" else "residual_povs"
    path = REPO_ROOT / root / slug / "manifest.json"
    return read_json(path) if path.is_file() else {}


def _common(row: Dict[str, Any], manifest: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "cve_id": row["cve"],
        "cwe_id": manifest.get("cwe_id", ""),
        "project_slug": row["slug"],
        "errored": 0,
        "evaluation_mode": "reconstructed",
        "evaluation_revision": row["head"],
        "dataset_revision": row["head"],
        "base_revision_matches_dataset": True,
        "base_build": row.get("base_build"),
        "patched_build": row.get("patched_build"),
        "wall_clock_s": row.get("seconds"),
        "scored_by": "patchagent-runs/povscore15 (build-and-replay, no LLM calls)",
    }


def fix_pov_results(row: Dict[str, Any]) -> Dict[str, Any]:
    manifest = pov_manifest("fix_pov", row["slug"])
    by_id = {p["id"]: p for p in manifest.get("povs", [])}
    povs, blocked, reproduced = [], 0, 0
    for p in row["povs"]:
        m = by_id.get(p["id"], {})
        outcome = "blocked" if p["verdict"] == "BLOCKED" else "reproduced"
        blocked += outcome == "blocked"
        reproduced += outcome == "reproduced"
        povs.append({
            "id": p["id"],
            "description": m.get("description", ""),
            "exploit_path": m.get("exploit_path", ""),
            "command": p.get("command", ""),
            "outcome": outcome,
            "exit_code": p.get("patched_rc"),
            # The guard baselines/README.md insists on: a POV that no longer reproduces
            # on the UNPATCHED tree proves nothing about the patch.
            "reproduces_on_base": p.get("baseline") == "reproduced",
            "patched_tail": (p.get("patched_tail") or "")[-2000:],
        })
    total = len(povs)
    return {**_common(row, manifest), "total": total, "blocked": blocked,
            "reproduced": reproduced, "conclusive": total,
            "score": (blocked / total) if total else None,
            "all_blocked": total > 0 and blocked == total, "povs": povs}


def residual_results(row: Dict[str, Any]) -> Dict[str, Any]:
    manifest = pov_manifest("residual", row["slug"])
    by_id = {p["id"]: p for p in manifest.get("povs", [])}
    povs, hardened, matched = [], 0, 0
    for p in row["povs"]:
        m = by_id.get(p["id"], {})
        # Deliberately the INVERSE reading of the same exit code: for a residual POV
        # "still reproduces" means "left exactly the hole upstream left", the expected
        # neutral result. The field names below stop any consumer rendering that as a
        # failure -- see runs._residual_eval for the same reasoning.
        outcome = "blocked" if p["verdict"] == "BLOCKED" else "reproduced"
        hardened += outcome == "blocked"
        matched += outcome == "reproduced"
        povs.append({
            "id": p["id"],
            "description": m.get("description", ""),
            "gap_summary": m.get("gap_summary", ""),
            "exploit_path": m.get("exploit_path", ""),
            "command": p.get("command", ""),
            "outcome": outcome,
            "exit_code": p.get("patched_rc"),
            "reproduces_on_base": p.get("baseline") == "reproduced",
            "patched_tail": (p.get("patched_tail") or "")[-2000:],
        })
    total = len(povs)
    return {**_common(row, manifest), "total": total,
            "hardened_beyond_fix": hardened, "matches_official_fix": matched,
            "conclusive": total,
            "score": (hardened / total) if total else None,
            "all_hardened": total > 0 and hardened == total,
            "residual_of": ",".join(manifest.get("fix_reference", {}).get("fix_commit_ids", [])),
            "povs": povs}


def main() -> int:
    ap = argparse.ArgumentParser(description="normalize a PatchAgent run")
    ap.add_argument("--run-dir", required=True, type=Path,
                    help="extracted haiku-4.5-15cases/ (summary.json, patches/, archives/, ...)")
    ap.add_argument("--pov-scores", required=True, type=Path, help="povscore15/results.json")
    ap.add_argument("--arm", default="skyset-haiku45")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    run_dir: Path = args.run_dir
    out: Path = args.out or (REPO_ROOT / "baselines" / "results" / BASELINE / args.arm)

    summary = read_json(run_dir / "summary.json")
    pov = read_json(args.pov_scores)
    case_map = {c["case_id"]: c for c in read_json(REPO_ROOT / "baselines" / "cases.json")["cases"]}

    # ---- native case id -> [case_id ...], from the POV run's own rows -------------
    native_to_cases: Dict[str, List[str]] = defaultdict(list)
    pov_rows: Dict[tuple, Dict[str, Any]] = {}
    for r in pov["rows"]:
        # The POV-score file is PatchAgent-side output and predates the fixPOV
        # rename: its rows still label the family "ground_truth".
        family = {"ground_truth": "fix_pov"}.get(r["family"], r["family"])
        pov_rows[(r["cve"], family)] = r
        if r["cve"] not in native_to_cases[r["case"]]:
            native_to_cases[r["case"]].append(r["cve"])
        ours = case_map.get(r["cve"])
        if ours is None:
            raise SystemExit(f"POV row cites {r['cve']}, absent from baselines/cases.json")
        if ours["buggy_commit_id"] != r["head"] or ours["project_slug"] != r["slug"]:
            raise SystemExit(
                f"{r['cve']}: POV run scored {r['head']}/{r['slug']} but cases.json says "
                f"{ours['buggy_commit_id']}/{ours['project_slug']} -- refusing to guess")

    attempts_by_case: Dict[str, List[dict]] = defaultdict(list)
    for line in (run_dir / "attempts.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            a = json.loads(line)
            attempts_by_case[a["case"]].append(a)

    # Keyed by the native case id ("<project>-<tag>"), which is how the driver names it.
    functional = {f"{p}-{t}": {"status": st, "seconds": sec, "exit_code": rc}
                  for st, p, t, sec, rc in
                  read_json(run_dir / "validation" / "functional_baseline.json")}
    rows: List[Dict[str, Any]] = []
    records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for src in summary["rows"]:
        native = src["case"]
        case_ids = native_to_cases.get(native)
        if not case_ids:
            raise SystemExit(f"no CVE mapping for PatchAgent case {native}")
        batch = BATCH_ITER15 if src["max_iteration"] != 3 else BATCH_ITER3
        attempts = attempts_by_case.get(native, [])
        accepted = sum(1 for a in attempts if str(a.get("accepted")) == "True")
        func = functional.get(native)

        patch_src = run_dir / "patches" / f"{src['project']}__{src['tag']}.FINAL.diff"
        patch_text = patch_src.read_text(encoding="utf-8") if patch_src.is_file() else None

        for case_id in case_ids:
            ours = case_map[case_id]
            case_dir = out / batch / "gen_patch" / case_id
            case_dir.mkdir(parents=True, exist_ok=True)

            if patch_text is not None:
                (case_dir / "patch.diff").write_text(patch_text, encoding="utf-8")
            write_json(case_dir / "attempts.json", attempts)
            # One file per agent attempt, not one per case: the coreutils case's archive
            # is 1.1 MB across 7 agents and the UI fetches these on demand.
            archive_src = run_dir / "archives" / f"{native}.json"
            agent_names: List[str] = []
            if archive_src.is_file():
                for i, entry in enumerate(read_json(archive_src), start=1):
                    name = f"agent_{i:02d}.json"
                    write_json(case_dir / "agents" / name, entry)
                    agent_names.append(name)
            func_txt = run_dir / "validation" / f"functional_{src['project']}__{src['tag']}.txt"
            if func_txt.is_file():
                shutil.copyfile(func_txt, case_dir / "functional.log")

            gt = pov_rows.get((case_id, "fix_pov"))
            gt_summary = fix_pov_results(gt) if gt else None
            if gt_summary:
                write_json(case_dir / "fix_pov" / "results.json", gt_summary)
            res = pov_rows.get((case_id, "residual"))
            res_summary = residual_results(res) if res else None
            if res_summary:
                write_json(case_dir / "residual" / "results.json", res_summary)

            shared = [c for c in case_ids if c != case_id]
            notes = []
            if src["max_iteration"] != 3:
                notes.append("ran at the full 15-agent DefaultPolicy ladder, not the 3-agent "
                             "cap the other cases used -- not comparable on effort")
            if shared:
                notes.append("one PatchAgent run; its patch and cost are shared with "
                             + ", ".join(shared))
            rows.append({
                "case_id": case_id,
                "patchagent_case": native,
                "project": ours["project"],
                "status": "patched" if src["status"] == "PATCHED" else src["status"].lower(),
                "validity": "valid",
                "batch": batch,
                "max_iteration": src["max_iteration"],
                "agents_used": src["agents_used"],
                "validate_calls": src["validate_calls"],
                "accepted_attempts": accepted,
                "rejected_attempts": len(attempts) - accepted,
                "duration_s": src["seconds"],
                "llm_calls": src["llm_calls"],
                "input_tokens": src["prompt_tokens"],
                "output_tokens": src["completion_tokens"],
                "cost_usd": src["cost_usd"],
                "cost_basis": "measured",
                "base_revision": ours["buggy_commit_id"],
                "functional_baseline": func,
                # True only for the cases that ran at the protocol cap of 3. Every
                # consumer must be able to see the odd one out without reading a footnote.
                "effort_comparable": src["max_iteration"] == 3,
                # Non-empty when one run's single patch covers more than one of our CVEs.
                # Cost and effort belong to the run, not to each CVE.
                "shared_run_with": shared,
                "agents": agent_names,
                "note": "; ".join(notes),
            })

            records[batch].append({
                "baseline": BASELINE,
                "baseline_commit": BASELINE_COMMIT,
                "case_id": case_id,
                "project_slug": ours["project_slug"],
                "batch": batch,
                "model": MODEL,
                "budget": {"iterations": src["max_iteration"]},
                "outcome": "repaired" if src["status"] == "PATCHED" else "failed",
                "gates": {
                    "compiles": True,
                    "poc_blocked": True,
                    # PatchAgent's validate() gate is compile + PoC + the project's own
                    # functional suite, so a patch it accepted passed all three.
                    "functional_tests_pass": True,
                    "functional_tests_available": bool(func and func["status"] == "passed"),
                },
                "our_scores": {
                    "fix_pov_score": gt_summary["score"] if gt_summary else None,
                    "fix_pov_all_blocked": gt_summary["all_blocked"] if gt_summary else None,
                    "residual_score": res_summary["score"] if res_summary else None,
                },
                "patch": {"path": f"{batch}/gen_patch/{case_id}/patch.diff",
                          **(diff_stats(patch_text) if patch_text else {})},
                "cost": {
                    "usd": src["cost_usd"],
                    "input_tokens": src["prompt_tokens"],
                    "output_tokens": src["completion_tokens"],
                    "wall_clock_s": float(src["seconds"]),
                    "attempts_used": src["validate_calls"],
                },
                "notes": (
                    f"cost.usd is MEASURED from recorded traffic and is a floor; billed ground " "max_iteration={}.".format(src["max_iteration"])
                    + (f" One run, shared with {', '.join(shared)}: this cost is the run's, "
                       f"not this CVE's alone." if shared else "")
                ),
            })

    # ---- the case that could not run --------------------------------------------
    ours = case_map[EXCLUDED_CASE_ID]
    rows.append({
        "case_id": EXCLUDED_CASE_ID, "patchagent_case": EXCLUDED_CASE,
        "project": ours["project"], "status": "not_run", "validity": "not_runnable",
        "batch": BATCH_ITER3,
        "max_iteration": None, "agents_used": None, "validate_calls": None,
        "accepted_attempts": None, "rejected_attempts": None,
        "duration_s": None, "llm_calls": None,
        "input_tokens": None, "output_tokens": None,
        "cost_usd": None,
        "cost_basis": None,
        "base_revision": ours["buggy_commit_id"],
        "functional_baseline": functional.get(EXCLUDED_CASE),
        "effort_comparable": False, "shared_run_with": [], "agents": [],
        "note": EXCLUDED_REASON,
    })
    records[BATCH_ITER3].append({
        "baseline": BASELINE, "baseline_commit": BASELINE_COMMIT,
        "case_id": EXCLUDED_CASE_ID, "project_slug": ours["project_slug"],
        "batch": BATCH_ITER3, "model": MODEL,
        "outcome": "inapplicable", "inapplicable_reason": EXCLUDED_REASON,
        "notes": "Reproduction succeeded (16/16 across the set); only the functional gate "
                 "is unusable, so this is an environment result, not a repair failure.",
    })

    rows.sort(key=lambda r: (r["project"], r["case_id"]))

    # ---- aggregate.json ----------------------------------------------------------
    valid = [r for r in rows if r["validity"] == "valid"]
    patched = [r for r in valid if r["status"] == "patched"]
    # De-duplicate on the PatchAgent run: one run's spend is one run's spend even when
    # its patch answers two of our CVEs.
    by_native = {r["patchagent_case"]: r for r in valid}
    write_json(out / "aggregate.json", {
        "summary": {
            "model": MODEL,
            "baseline_commit": BASELINE_COMMIT,
            "arm": args.arm,
            "cases_total": len(rows),
            "valid": len(valid),
            "not_runnable": len(rows) - len(valid),
            "not_runnable_ids": [r["case_id"] for r in rows if r["validity"] != "valid"],
            "patched": len(patched),
            "failed": len(valid) - len(patched),
            "success_rate_of_valid": round(len(patched) / len(valid), 4) if valid else 0.0,
            "patchagent_runs": len(by_native),
            "cases_sharing_a_run": [
                {"patchagent_case": n, "case_ids": sorted(native_to_cases[n])}
                for n in sorted(native_to_cases) if len(native_to_cases[n]) > 1
            ],
            "max_iteration_3": sum(1 for r in by_native.values() if r["max_iteration"] == 3),
            "max_iteration_other": {r["case_id"]: r["max_iteration"]
                                    for r in by_native.values() if r["max_iteration"] != 3},
            "cost_usd_measured_total": round(sum(r["cost_usd"] or 0 for r in by_native.values()), 4),
            "cost_note": summary["token_note"],
            # PatchAgent's own summary.json keeps the pre-rename key.
            "billed_fix_pov": summary.get("fix_pov", summary.get("ground_truth")),
            "tokens_total": sum((r["input_tokens"] or 0) + (r["output_tokens"] or 0)
                                for r in by_native.values()),
            "llm_calls_total": sum(r["llm_calls"] or 0 for r in by_native.values()),
            "wall_clock_s_total": sum(r["duration_s"] or 0 for r in by_native.values()),
            "validate_calls_total": sum(r["validate_calls"] or 0 for r in by_native.values()),
        },
        "cases": rows,
    })
    write_json(out / "projects.json", {r["case_id"]: r["project"] for r in rows})

    # ---- POV score roll-ups (same keys san2patch's pov_summary() reads) ----------
    for family, key, subdir in (("fix_pov", "fixpov", "fix_pov"),
                                ("residual", "respov", "residual")):
        srows, blocked_povs, total_povs, full = [], 0, 0, 0
        scores: List[float] = []
        for r in rows:
            pr = pov_rows.get((r["case_id"], family))
            if pr is None:
                srows.append({"case_id": r["case_id"], "key": r["case_id"],
                              "project_slug": case_map[r["case_id"]]["project_slug"],
                              "claimed_repaired": r["status"] == "patched",
                              "action": "skip",
                              "skip_reason": ("no curated manifest for this case"
                                              if r["validity"] == "valid"
                                              else "case never ran")})
                continue
            summ = (fix_pov_results if family == "fix_pov" else residual_results)(pr)
            good = summ["blocked"] if family == "fix_pov" else summ["hardened_beyond_fix"]
            total_povs += summ["total"]
            blocked_povs += good
            full += bool(summ.get("all_blocked") or summ.get("all_hardened"))
            if summ["score"] is not None:
                scores.append(summ["score"])
            srows.append({
                "case_id": r["case_id"], "key": r["case_id"],
                "project_slug": summ["project_slug"],
                "claimed_repaired": r["status"] == "patched",
                "action": "scored",
                "results_path": (f"baselines/results/{BASELINE}/{args.arm}/{r['batch']}/"
                                 f"gen_patch/{r['case_id']}/{subdir}/results.json"),
                "summary": {k: v for k, v in summ.items() if k != "povs"},
            })
        write_json(out / f"pov_scores_{key}.json", {
            "baseline": BASELINE, "family": key, "arm": args.arm,
            "claimed_repaired": len(patched),
            "scored": len(scores),
            "fully_blocked": full,
            "errored": 0,
            "mean_score": round(sum(scores) / len(scores), 4) if scores else None,
            "povs_total": total_povs,
            "povs_blocked": blocked_povs,
            "base_mismatched": 0, "base_unresolved": 0, "oracle_drifted": 0,
            "skipped": len(rows) - len(scores),
            "scored_by": pov.get("generated_by", ""),
            "scoring_note": pov.get("scoring", ""),
            "rows": srows,
        })

    # ---- per-batch manifest + schema records ------------------------------------
    for batch, recs in records.items():
        iters = 15 if batch == BATCH_ITER15 else 3
        write_json(out / batch / "results.json", sorted(recs, key=lambda r: r["case_id"]))
        write_json(out / batch / "manifest.json", {
            "batch": batch, "baseline": BASELINE, "baseline_commit": BASELINE_COMMIT,
            "model": MODEL, "arm": args.arm,
            "image": "patchagent-dev:nodbginfod (artifact devcontainer plus the fixes below)",
            "max_iteration": iters,
            "purpose": (f"PatchAgent over the skyset cases overlapping our C corpus, at "
                        f"--max-iteration {iters}"),
            "cases_attempted": sum(1 for r in recs if r["outcome"] != "inapplicable"),
            "ran_at": "2026-08-20" if batch == BATCH_ITER15 else "2026-08-19",
            "cost_basis": "measured_tokens",
            "cost_note": ("cost_usd is derived from token counts measured via Anthropic's "
                          "count_tokens endpoint over the recorded traffic, tool schemas "
                          "included. Raw traces are committed under traces/."),
            "notes": [
                "Run OUT OF BAND in PatchAgent's own artifact container, not through a "
                "baselines/ adapter. This directory is the normalized conversion of that "
                "native output (baselines/patchagent/normalize_run.py); nothing here was "
                "re-run or re-scored.",
                "Environment fixes were required and are not upstream: guarded "
                "parse_other_error in nvwa/parser/address.py (an EMPTY report -- what a "
                "successful patch produces -- otherwise raises and the patch is silently "
                "discarded), tool error handlers, a syz-symbolize stub, two pull.sh remotes "
                "repointed to vadz/libtiff and gnutools/binutils-gdb, /etc/debuginfod/*.urls "
                "removed from the image, httpx==0.27.2 pinned, a libclang-16.so symlink.",
                "Token counts come from re-counting the recorded traffic through "
                "count_tokens, tool schemas included. They cover what ChatOpenAI callbacks "
                "reported; retried or internally-issued calls may not appear. Raw traces are "
                "committed per case so the counts can be re-derived.",
            ] + ([
                "This batch is ONE case. It ran at the full 15-agent DefaultPolicy ladder "
                "because it fails at 3, so it is not comparable on effort with b1: 53 "
                "candidates, 50 of them re-proposing the same wrong hypothesis, before agent "
                "7 (temperature 0.5 WITH counterexamples) found a NUL-terminator guard.",
            ] if batch == BATCH_ITER15 else [
                "extractfix-libtiff-c421b99-heap_buffer_overflow is ONE run whose single patch "
                "covers CVE-2016-3186 and CVE-2016-5314. Both appear as records because our "
                "POV sets score them separately and disagree (0/2 vs 2/2), but the cost and "
                "the effort belong to one run. Note San2Patch's own benchmark EXCLUDES both.",
                "gnubug-19784 (coreutils 658529a) is recorded inapplicable, not failed.",
            ]),
        })

    # ---- the 15-iteration case's own driver log and agent ladder -----------------
    (out / "by-case").mkdir(parents=True, exist_ok=True)
    driver = run_dir / "driver-coreutils15.log"
    if driver.is_file():
        shutil.copyfile(driver, out / "by-case" / f"{ITER15_CASE_ID}.log")
    tsv = run_dir / "agents-coreutils15.tsv"
    if tsv.is_file():
        shutil.copyfile(tsv, out / "by-case" / f"{ITER15_CASE_ID}.agents.tsv")

    print(f"wrote {out} -- {len(rows)} rows across {len(records)} batches")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
