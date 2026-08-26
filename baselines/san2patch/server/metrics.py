#!/usr/bin/env python3
"""Extract per-case timing (and token/cost, when available) from a San2Patch batch.

    python3 metrics.py /root/autosec-baselines/san2patch/runs/<batch>

Writes `metrics.tsv` and `metrics.json` beside the batch's `run.log`.

TIMING needs no instrumentation: San2Patch timestamps every log line to the second and tags it
with the case id, so start/end and per-stage boundaries are recoverable from `run.log` alone.

TOKENS/COST are only filled in if a usage log exists (`usage.jsonl`, written by the logging
proxy — see README). Without it those columns are null rather than guessed: an invented cost
number is worse than a missing one, and San2Patch persists no accounting of its own.

Stdlib only, to match the rest of this repo.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\[([^\]]+)\]\s+(\w+)\s+(.*)$")
START = re.compile(r"Starting patching stage (\d+) try (\d+) for vuln_id: (\S+)")
DONE = re.compile(r"Patch (success|failed) for vuln_id: (\S+)")
# The ONLY terminal marker a *failed* case emits. San2Patch logs `Patch success for
# vuln_id: X` on success but merely a bare `Patch failed.` on failure — no case id — so
# DONE alone leaves every failed case with no end, hence no duration, no tokens and no
# cost. Those cases still consumed both, and a cost-per-case that silently covers only
# the successes is a wrong number, not a missing one.
#
# Note this line is emitted under the *previous* case's log tag, so it must be matched
# on the message and trusted over the tag — which is also why stage attribution below
# cannot use the tag for it.
END = re.compile(r"vuln_id_end: (\S+)")

# Marker -> the stage it closes. Used for the per-case stage breakdown.
STAGE_MARKERS = [
    ("Patch applied successfully", "apply"),
    ("Building the project", "build"),
    ("Vulnerability test passed", "vuln_test"),
    ("Functionality test passed", "func_test"),
    ("Build test failed", "build_failed"),
]

# USD per million tokens. Update when pricing changes; recorded in the output so a
# number can always be traced back to the rates it was computed with.
PRICES = {
    "claude-haiku-4-5-20251001": {"in": 1.00, "out": 5.00},
    "claude-sonnet-5": {"in": 3.00, "out": 15.00},
    "gpt-4o-2024-08-06": {"in": 2.50, "out": 10.00},
    "gpt-4o-mini": {"in": 0.15, "out": 0.60},
    # Verify against the provider's page before quoting a cost in the paper — these
    # change, and an unpriced model is reported loudly (cost_note) rather than as $0.
    "deepseek-chat": {"in": 0.27, "out": 1.10},
    "deepseek-reasoner": {"in": 0.55, "out": 2.19},
}


def parse_log(path: Path) -> dict:
    cases: dict[str, dict] = {}
    order: list[str] = []
    for raw in path.read_text(errors="replace").splitlines():
        m = TS.match(raw.strip())
        if not m:
            continue
        ts, tag, level, msg = m.groups()
        t = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

        s = START.search(msg)
        if s:
            cid = s.group(3)
            c = cases.setdefault(cid, {"case_id": cid, "start": t, "end": None,
                                       "tries": 0, "events": [], "status": None})
            if cid not in order:
                order.append(cid)
            c["tries"] += 1
            continue

        d = DONE.search(msg)
        if d:
            cid = d.group(2)
            c = cases.setdefault(cid, {"case_id": cid, "start": t, "end": None,
                                       "tries": 0, "events": [], "status": None})
            c["end"] = t
            c["status"] = "success" if d.group(1) == "success" else "failed"
            continue

        e = END.search(msg)
        if e:
            cid = e.group(1)
            c = cases.setdefault(cid, {"case_id": cid, "start": t, "end": None,
                                       "tries": 0, "events": [], "status": None})
            c["end"] = t
            # A case that reached its end without a success line exhausted its retries.
            c["status"] = c["status"] or "failed"
            continue

        # Attribute stage markers by the log tag, which carries the case id.
        cid = tag.strip()
        if cid in cases:
            for marker, name in STAGE_MARKERS:
                if marker in msg:
                    cases[cid]["events"].append({"at": t.isoformat(), "stage": name})
                    if cases[cid]["end"] is None or t > cases[cid]["end"]:
                        cases[cid]["end"] = t
                    break
    return {"cases": cases, "order": order}


def load_usage(batch: Path) -> dict:
    """usage.jsonl -> per-case token totals, attributed by timestamp.

    Cases run serially at WORKERS=1, so a request falling inside a case's [start, end]
    window belongs to it. With WORKERS>1 this attribution is not sound and is skipped.
    """
    f = batch / "usage.jsonl"
    if not f.exists():
        return {}
    calls = []
    for line in f.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
            calls.append((datetime.fromisoformat(r["ts"]).replace(tzinfo=None), r))
        except Exception:
            continue
    return {"calls": calls}


def load_loadavg(batch: Path):
    """load.jsonl -> [(ts, load1, cores)], for per-case contention attribution."""
    f = batch / "load.jsonl"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(errors="replace").splitlines():
        try:
            r = json.loads(line)
            out.append((datetime.fromisoformat(r["ts"]).replace(tzinfo=None),
                        float(r["load1"]), int(r["cores"])))
        except Exception:
            continue
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    batch = Path(sys.argv[1])
    log = batch / "run.log"
    if not log.exists():
        print(f"no run.log in {batch}", file=sys.stderr)
        return 1

    parsed = parse_log(log)
    usage = load_usage(batch)
    loads = load_loadavg(batch)
    workers = 1
    mf = batch / "manifest.json"
    model = None
    if mf.exists():
        try:
            m = json.loads(mf.read_text())
            workers = int(m.get("workers", 1))
            model = m.get("model")
        except Exception:
            pass

    rows = []
    for cid in parsed["order"]:
        c = parsed["cases"][cid]
        dur = int((c["end"] - c["start"]).total_seconds()) if c["end"] else None
        row = {
            "case_id": cid,
            "status": c["status"],
            "tries": c["tries"],
            "started_at": c["start"].isoformat(),
            "finished_at": c["end"].isoformat() if c["end"] else None,
            "duration_s": dur,
            "stages": c["events"],
            "input_tokens": None, "output_tokens": None, "cost_usd": None,
        }
        # Mean load over THIS case's window. `contended` marks a duration_s that should
        # not be compared against an idle-machine measurement — it is a caveat on the
        # timing only; tokens, cost and status are unaffected by how busy the box was.
        if loads and c["end"]:
            w = [(l, n) for t, l, n in loads if c["start"] <= t <= c["end"]]
            if w:
                cores = w[0][1]
                mean = sum(l for l, _ in w) / len(w)
                row["mean_load"] = round(mean, 2)
                row["cores"] = cores
                row["contended"] = mean > cores * 0.7
        if usage and workers == 1 and c["end"]:
            tin = tout = 0
            api_model = None
            for t, r in usage["calls"]:
                if c["start"] <= t <= c["end"]:
                    tin += r.get("input_tokens", 0) or 0
                    tout += r.get("output_tokens", 0) or 0
                    api_model = api_model or r.get("model")
            if tin or tout:
                row["input_tokens"], row["output_tokens"] = tin, tout
                row["api_model"] = api_model
                # Price by the model the API actually billed, not the CLI alias in the
                # manifest — `claude-haiku-4.5` (San2Patch's own name for it) is not a
                # key in PRICES, and silently yielding no cost is worse than being loud.
                p = PRICES.get(api_model or "") or PRICES.get(model or "")
                if p:
                    row["cost_usd"] = round(tin / 1e6 * p["in"] + tout / 1e6 * p["out"], 6)
                else:
                    row["cost_note"] = f"no price for model {api_model or model!r}"
        rows.append(row)

    (batch / "metrics.json").write_text(json.dumps({
        "batch": batch.name, "model": model, "workers": workers,
        "prices_usd_per_mtok": PRICES.get(model or "") if model else None,
        "token_source": "usage.jsonl (proxy)" if usage else None,
        "cases": rows,
    }, indent=2) + "\n")

    cols = ["case_id", "status", "tries", "duration_s", "input_tokens", "output_tokens",
            "cost_usd", "mean_load", "contended", "api_model"]
    with (batch / "metrics.tsv").open("w") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join("" if r.get(c) is None else str(r.get(c)) for c in cols) + "\n")

    done = [r for r in rows if r["duration_s"] is not None]
    print(f"  cases            : {len(rows)}")
    if done:
        tot = sum(r['duration_s'] for r in done)
        print(f"  total wall-clock : {tot//60}m{tot%60}s")
        print(f"  mean per case    : {tot//len(done)}s")
    costed = [r for r in rows if r.get("cost_usd") is not None]
    if costed:
        tc = sum(r["cost_usd"] for r in costed)
        ti = sum(r["input_tokens"] for r in costed)
        to = sum(r["output_tokens"] for r in costed)
        print(f"  tokens           : {ti:,} in / {to:,} out")
        print(f"  cost             : ${tc:.4f} total, ${tc/len(costed):.4f}/case ({len(costed)} cases)")
    elif not usage:
        print("  tokens/cost      : not available (no usage.jsonl — see README)")
    else:
        print("  cost             : tokens captured but no price entry — see cost_note in metrics.json")
    cont = [r for r in rows if r.get("contended")]
    if cont:
        print(f"  contended        : {len(cont)}/{len(rows)} case(s) measured under load "
              f">70% of cores — their duration_s is not comparable to an idle run")
    print(f"  wrote            : {batch/'metrics.tsv'}, {batch/'metrics.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
