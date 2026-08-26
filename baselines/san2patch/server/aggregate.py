#!/usr/bin/env python3
"""Combine every San2Patch batch into one results table, and say which rows are usable.

    python3 aggregate.py /root/autosec-baselines/san2patch/runs

Writes `aggregate.tsv` and `aggregate.json` into that directory.

The point of this script is the VALIDITY column, not the totals. A San2Patch case that
never reached the model still writes a res.txt saying `vuln_test_failed`, which is
indistinguishable from a real repair failure unless you check whether any tokens were
spent on it. That happened for real: an account usage limit was reached mid-batch and
the next cases each "failed" in about four seconds, five tries apiece, with no LLM call
behind any of them. Reporting those as San2Patch failures would understate the tool.

So a row is `valid` only if it consumed input tokens. Everything else is `needs_rerun`,
with the reason carried through from triage.py where one is available.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

# Recorded per case so a later reader can see which arm produced a number.
FIELDS = ["case_id", "status", "validity", "tries", "duration_s", "input_tokens",
          "output_tokens", "cost_usd", "mean_load", "contended", "batch", "note"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".", help="the runs/ directory")
    ap.add_argument("--model", help="only batches whose manifest records this model "
                                    "(required once more than one model has been run, "
                                    "or their results blend into one meaningless table)")
    ap.add_argument("--out", help="basename for the output files (default: aggregate)")
    a = ap.parse_args()
    root = Path(a.root)
    rows: dict[str, dict] = {}
    models_seen: set[str] = set()

    for mf in sorted(root.glob("*/metrics.json")):
        batch = mf.parent.name
        try:
            data = json.loads(mf.read_text())
        except Exception:
            continue
        # Prefer the manifest's model (what was requested) and fall back to metrics'
        # (what the API billed); either identifies the arm.
        bmodel = data.get("model")
        manf = mf.parent / "manifest.json"
        if manf.exists():
            try:
                bmodel = json.loads(manf.read_text()).get("model", bmodel)
            except Exception:
                pass
        if bmodel:
            models_seen.add(bmodel)
        if a.model and bmodel != a.model:
            continue
        triage = {}
        tf = mf.parent / "triage.json"
        if tf.exists():
            try:
                triage = {c["case_id"]: c for c in json.loads(tf.read_text()).get("cases", [])}
            except Exception:
                pass

        for c in data.get("cases", []):
            cid = c["case_id"]
            tok = c.get("input_tokens") or 0
            t = triage.get(cid, {})
            verdict = t.get("verdict")

            # A case that spent no tokens never reached the model, whatever its res.txt
            # says. This is the check that separates an API-limit casualty from a real
            # failure — the two look identical in the status column alone.
            if tok == 0:
                validity, note = "needs_rerun", (t.get("why") or "no LLM calls recorded")
            elif verdict and verdict not in ("genuine",):
                validity, note = "needs_rerun", (t.get("why") or verdict)
            else:
                validity, note = "valid", ""

            row = {
                "case_id": cid, "status": c.get("status"), "validity": validity,
                "tries": c.get("tries"), "duration_s": c.get("duration_s"),
                "input_tokens": c.get("input_tokens"), "output_tokens": c.get("output_tokens"),
                "cost_usd": c.get("cost_usd"), "mean_load": c.get("mean_load"),
                "contended": c.get("contended"), "batch": batch, "note": note,
            }
            row["started_at"] = c.get("started_at")
            prev = rows.get(cid)
            if prev is None:
                rows[cid] = row
            elif prev["validity"] != "valid" and validity == "valid":
                # A re-run replacing a case that never ran: the re-run IS the only attempt.
                rows[cid] = row
            elif prev["validity"] == "valid" and validity == "valid":
                # TWO complete attempts of the same case. Keeping the better one is
                # selection bias — San2Patch already gets 5 tries internally, and taking
                # the best of two such runs makes it best-of-10, which is not what the
                # paper reports. Keep the EARLIEST attempt and record that a later one
                # exists, so the bias is visible instead of baked into the number.
                first, second = sorted([prev, row], key=lambda r: r.get("started_at") or "")
                first = dict(first)
                first["superseded_by"] = {"batch": second["batch"], "status": second["status"]}
                if first["status"] != second["status"]:
                    first["note"] = (f"attempted twice with different outcomes "
                                     f"({first['status']} then {second['status']}); "
                                     f"first attempt counted")
                rows[cid] = first

    ordered = sorted(rows.values(), key=lambda r: (r["validity"] != "valid", r["case_id"]))

    base = a.out or "aggregate"
    with (root / f"{base}.tsv").open("w") as fh:
        fh.write("\t".join(FIELDS) + "\n")
        for r in ordered:
            fh.write("\t".join("" if r.get(k) is None else str(r.get(k)) for k in FIELDS) + "\n")

    valid = [r for r in ordered if r["validity"] == "valid"]
    rerun = [r for r in ordered if r["validity"] != "valid"]
    succ = [r for r in valid if r["status"] == "success"]
    fail = [r for r in valid if r["status"] != "success"]
    cost_s = sum(r["cost_usd"] or 0 for r in succ)
    cost_f = sum(r["cost_usd"] or 0 for r in fail)

    summary = {
        "model_filter": a.model,
        "models_present_in_runs_dir": sorted(models_seen),
        "cases_total": len(ordered),
        "valid": len(valid), "needs_rerun": len(rerun),
        "success": len(succ), "failed": len(fail),
        "success_rate_of_valid": round(len(succ) / len(valid), 4) if valid else None,
        "cost_usd_total": round(cost_s + cost_f, 4),
        "cost_usd_per_success": round(cost_s / len(succ), 4) if succ else None,
        "cost_usd_per_failure": round(cost_f / len(fail), 4) if fail else None,
        "contended_cases": sum(1 for r in valid if r.get("contended")),
        "needs_rerun_ids": [r["case_id"] for r in rerun],
        # Cases that produced two complete attempts. Reported explicitly because the
        # difference between counting the first and counting the best is exactly the
        # difference between a comparable number and an inflated one.
        "attempted_twice": [
            {"case_id": r["case_id"], "counted": r["status"],
             "other_attempt": r["superseded_by"]["status"]}
            for r in ordered if r.get("superseded_by")
        ],
    }
    (root / f"{base}.json").write_text(
        json.dumps({"summary": summary, "cases": ordered}, indent=2) + "\n")

    # Blending two models into one table produces a number that describes neither, and
    # nothing downstream would flag it — so say it here, where it is still fixable.
    if len(models_seen) > 1 and not a.model:
        print(f"  [!] {len(models_seen)} models present ({', '.join(sorted(models_seen))})")
        print("      this table MIXES them — re-run with --model <name> per arm")
    print(f"  model             : {a.model or (sorted(models_seen)[0] if models_seen else 'unknown')}")
    print(f"  cases recorded    : {summary['cases_total']}")
    print(f"    valid           : {summary['valid']}")
    print(f"    needs re-run    : {summary['needs_rerun']}")
    if valid:
        print(f"  of the valid rows : {summary['success']} success / {summary['failed']} failed "
              f"({summary['success_rate_of_valid']:.1%})")
        print(f"  cost              : ${summary['cost_usd_total']:.2f} total; "
              f"${summary['cost_usd_per_success']:.3f}/success, "
              f"${summary['cost_usd_per_failure']:.3f}/failure"
              if succ and fail else f"  cost: ${summary['cost_usd_total']:.2f}")
        if summary["contended_cases"]:
            print(f"  contended timings : {summary['contended_cases']} (exclude from timing claims)")
    if summary["attempted_twice"]:
        print(f"  attempted twice   : {len(summary['attempted_twice'])} "
              f"(first attempt counted, not the better one)")
        for d in summary["attempted_twice"]:
            flag = " <-- DIFFERENT OUTCOMES" if d["counted"] != d["other_attempt"] else ""
            print(f"      {d['case_id']:<16} counted={d['counted']} "
                  f"other={d['other_attempt']}{flag}")
    if rerun:
        print(f"  re-run needed     : {', '.join(summary['needs_rerun_ids'])}")
    print(f"  wrote             : {root/'aggregate.tsv'}, {root/'aggregate.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
