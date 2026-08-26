#!/usr/bin/env python3
"""Build a per-case index over a results directory: one log and one entry per CVE.

    python3 index.py <results-dir> [--model claude-haiku-4.5]

Writes, into <results-dir>:
    INDEX.md            one row per case -> status, cost, and paths to its artifacts
    by-case/<CASE>.log  that case's runtime log, extracted from its batch's run.log

WHY THIS EXISTS: everything is already saved, but nothing is findable. Batch directories
are named `b01-haiku45-tot-20260814-0950`, which says nothing about which cases are inside;
a case that was re-run appears in two batches; and `run.log` is per-BATCH, with five cases
interleaved, so "the log for CVE-2017-5969" is not a file that exists. You have to know the
batch first, which is exactly the thing you are trying to look up.

The extraction is by TIME WINDOW (the case's own start/end from metrics.json), not by
grepping its id, because San2Patch tags many lines with the *previous* case's id — the
`vuln_id_end: X` line that ends a case is logged under its predecessor's tag. Grepping the
id drops those lines; the window keeps them.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
# San2Patch prints the case's benchmark path, which is the only place the subject
# program is recorded — `aggregate.tsv` carries the case id but not the project.
BENCH = re.compile(r"san2patch-benchmark/([A-Za-z0-9_.+-]+)/([A-Za-z0-9_.-]+)/")
# Two cases never print a benchmark path (their logs go straight to the patch);
# their project is read off the file the patch touches instead.
PROJECT_FALLBACK = {"CVE-2016-9264": "libming", "CVE-2017-5969": "libxml2"}


def case_projects(root: Path) -> dict:
    """case_id -> subject program, written to projects.json.

    The dashboard needs a project column and re-deriving it from log text on every
    request would be absurd; this bakes it out once, next to aggregate.json.
    """
    found: dict = {}
    for log in list((root / "by-case").glob("*.log")) + list(root.glob("*/run.log")):
        for project, case in BENCH.findall(log.read_text(errors="replace")):
            found.setdefault(case, set()).add(project)
    out = {c: next(iter(s)) for c, s in found.items() if len(s) == 1}
    for case, project in PROJECT_FALLBACK.items():
        out.setdefault(case, project)
    return dict(sorted(out.items()))


def extract(run_log: Path, start: datetime, end: datetime) -> list[str]:
    """Lines of run_log falling inside [start, end]. Untimestamped lines follow the
    last timestamp seen, so tracebacks and command output stay with their case."""
    out, keep = [], False
    for line in run_log.read_text(errors="replace").splitlines():
        m = TS.match(line.strip())
        if m:
            try:
                t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                pass
            else:
                keep = start <= t <= end
        if keep:
            out.append(line)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root")
    ap.add_argument("--model", help="restrict to one model's batches")
    a = ap.parse_args()
    root = Path(a.root)

    agg = root / "aggregate.json"
    if not agg.exists():
        print(f"no aggregate.json in {root} — run aggregate.py first")
        return 1
    data = json.loads(agg.read_text())
    cases = data["cases"]

    bycase = root / "by-case"
    bycase.mkdir(exist_ok=True)

    rows = []
    for c in cases:
        cid, batch = c["case_id"], c["batch"]
        bdir = root / batch
        gdir = bdir / "gen_diff" / cid

        # per-case log
        logpath = None
        mj = bdir / "metrics.json"
        rl = bdir / "run.log"
        if mj.exists() and rl.exists():
            try:
                mc = next(x for x in json.loads(mj.read_text())["cases"]
                          if x["case_id"] == cid)
                if mc.get("started_at") and mc.get("finished_at"):
                    lines = extract(rl, datetime.fromisoformat(mc["started_at"]),
                                    datetime.fromisoformat(mc["finished_at"]))
                    if lines:
                        p = bycase / f"{cid}.log"
                        p.write_text("\n".join(lines) + "\n")
                        logpath = f"by-case/{cid}.log"
            except (StopIteration, KeyError, ValueError):
                pass

        patch = next(iter(sorted(gdir.glob("*success.diff"))), None)
        traces = sorted(gdir.glob("stage_*/*graph_output.json"))
        rows.append({
            "case": cid, "status": c["status"] or "-", "validity": c["validity"],
            "tries": c["tries"], "cost": c["cost_usd"], "duration": c["duration_s"],
            "contended": c.get("contended"),
            "log": logpath,
            "patch": f"{batch}/gen_diff/{cid}/{patch.name}" if patch else None,
            "case_dir": f"{batch}/gen_diff/{cid}/",
            "traces": len(traces),
            "batch": batch,
        })

    rows.sort(key=lambda r: (r["validity"] != "valid", r["status"] != "success", r["case"]))
    s = data["summary"]

    md = [f"# Per-case index — {s.get('model_filter') or 'all models'}",
          "",
          f"{s['valid']} valid of {s['cases_total']} recorded · "
          f"**{s['success']} repaired / {s['failed']} failed** · ${s['cost_usd_total']:.2f}",
          "",
          "Generated by `index.py`. Every path is relative to this file.",
          "",
          "`by-case/<CASE>.log` is that case's runtime log, sliced out of its batch's",
          "`run.log` by time window — the per-batch log interleaves five cases.",
          "",
          "| case | status | tries | time | cost | log | patch | files |",
          "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        t = f"{r['duration']//60}m{r['duration']%60:02d}s" if r["duration"] else "-"
        if r["contended"]:
            t += " ⚠"
        cost = f"${r['cost']:.3f}" if r["cost"] else "-"
        log = f"[log]({r['log']})" if r["log"] else "-"
        patch = f"[patch]({r['patch']})" if r["patch"] else "-"
        st = r["status"] if r["validity"] == "valid" else f"{r['status']} (INVALID)"
        md += [f"| `{r['case']}` | {st} | {r['tries']} | {t} | {cost} | {log} | "
               f"{patch} | [{r['traces']} traces]({r['case_dir']}) |"]

    md += ["",
           "⚠ = measured while the server was loaded; exclude from timing claims.",
           "",
           "`(INVALID)` = the case never reached the model (API limit or harness fault).",
           "It is **not** a repair failure — exclude it from any success rate.",
           ""]

    twice = s.get("attempted_twice") or []
    if twice:
        md += ["## Cases attempted twice", "",
               "These ran to completion more than once, because a re-run was triggered by",
               "an API-limit incident that turned out not to have affected them. **The",
               "first attempt is the one counted** — San2Patch already retries 5 times",
               "internally, so counting the better of two full runs would be best-of-10",
               "and not comparable with the paper's 5.", "",
               "| case | counted | other attempt |", "|---|---|---|"]
        for d in twice:
            flag = " ← differs" if d["counted"] != d["other_attempt"] else ""
            md += [f"| `{d['case_id']}` | **{d['counted']}** | {d['other_attempt']}{flag} |"]
        md += [""]

    # Void records: directories that exist but hold no attempt. Listed so nobody reads one
    # as a result — its res.txt says `vuln_test_failed` exactly like a real failure does.
    void = []
    for mj in sorted(root.glob("*/metrics.json")):
        try:
            for c in json.loads(mj.read_text())["cases"]:
                if not c.get("input_tokens"):
                    void.append(f"{mj.parent.name}/gen_diff/{c['case_id']}/")
        except Exception:
            pass
    if void:
        md += ["## Void records — do not read these as results", "",
               "These directories exist but contain **no attempt**: the account usage limit",
               "was reached, so the case burned its 5 retries in ~4 seconds without an LLM",
               "call. Each still holds a `res.txt` reading `vuln_test_failed`, identical to",
               "a genuine failure. They are kept as the record of the incident; the real",
               "result for each case is elsewhere in this index.", ""]
        md += [f"- `{v}`" for v in void]
        md += [""]

    md += [
           "## Per-batch files",
           "",
           "| file | what it holds |",
           "|---|---|",
           "| `run.log` | the whole batch, all cases interleaved |",
           "| `metrics.tsv` | per case: status, tries, duration, tokens, cost, load |",
           "| `triage.json` | why each non-success case failed |",
           "| `usage.jsonl` | every API call: tokens, latency, status |",
           "| `load.jsonl` | server load sampled every 30s |",
           "| `manifest.json` | model, image digest, commit, host, missing ids |",
           "| `env.txt` | container config, secrets redacted |",
           ""]
    (root / "INDEX.md").write_text("\n".join(md))
    projects = case_projects(root)
    (root / "projects.json").write_text(json.dumps(projects, indent=2) + "\n")

    print(f"  cases indexed : {len(rows)}")
    print(f"  projects      : {len(projects)} -> {root/'projects.json'}")
    print(f"  per-case logs : {sum(1 for r in rows if r['log'])} -> {bycase}")
    print(f"  wrote         : {root/'INDEX.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
