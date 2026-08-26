#!/usr/bin/env python3
"""Classify every non-success case in a batch: our fault, or the tool's?

    python3 triage.py /root/autosec-baselines/san2patch/runs/<batch>

A batch that runs unattended for hours is only useful if a failure can be attributed
afterwards. A case that failed because our metering proxy hiccuped is **not** a San2Patch
result and must never be reported as one; a case that failed because the patch was wrong
is exactly the result we are after. This separates them from evidence rather than guesswork.

Verdicts:

  genuine        The tool ran, reached the API, and produced a real outcome
                 (build_failed / vuln_test_failed / func_test_failed). Report it.
  proxy_suspect  A proxy_error record, or a heartbeat gap, falls inside this case's window.
                 Its LLM calls did not reach Anthropic. Re-run before reporting.
  harness        Never got as far as the model: missing src/, inner container down, etc.
  no_llm_calls   The case window contains no successful API call at all — always wrong,
                 whatever the cause.
  unknown        Not enough evidence. Treated as needing a re-run, not as a failure.

Exit code is non-zero when anything needs a re-run, so it can gate a report step.
Stdlib only.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Evidence that the scaffolding actually worked for this case: the patch was applied, the
# project built, or a test ran. A case that got this far has a working harness, so any
# later docker error is incidental to a normal failed repair — not the cause of it.
#
# This guard exists because HARNESS_PATTERNS below is deliberately broad, and without it
# `Error occurred while running CMD: docker exec` (which fires whenever a patch fails to
# apply and the tree is reset) reclassified three genuine failures as harness problems.
# Each had made 200+ LLM calls and reached a real vuln_test_failed verdict; discarding
# them would have understated San2Patch's failure rate with our own bug.
HARNESS_WORKED = re.compile(
    r"Patch applied successfully|Build completed|Vulnerability test|Functionality test")

HARNESS_PATTERNS = [
    (re.compile(r"git reset --hard.*No such file|cd .*/src.*No such file"), "missing src/ tree"),
    (re.compile(r"Error occurred while running CMD: docker exec"), "inner container command failed"),
    (re.compile(r"Cannot connect to the Docker daemon"), "inner dockerd down"),
]
# When metering is on, the container's ONLY LLM endpoint is our proxy, so any
# connection-level error is by definition a failure to reach it — LangChain reports
# these as a bare "Connection error." with no address, which is why matching on the
# proxy's IP (as an earlier version did) silently missed every real occurrence.
# An account-level usage limit is neither the tool's fault nor a proxy fault, and it has a
# distinctive signature: the case dies in seconds having spent nothing. It gets its own
# verdict because the remedy is different — raise the limit and re-run, rather than
# investigate anything. Checked before everything else: when it fires, no other signal
# about the case means anything.
API_LIMIT = re.compile(r"specified API usage limits|usage limits.*regain access|"
                       r"credit balance is too low|rate_limit_error")

PROXY_PATTERNS = [
    (re.compile(r"proxy_error|usage_proxy:"), "proxy returned 502"),
    (re.compile(r"Connection refused.*172\.17\.0\.1|Failed to establish a new connection.*172\.17\.0\.1"),
     "container could not reach the proxy"),
    (re.compile(r"Error when invoking chain: Connection error|APIConnectionError|Connection error\.\."),
     "connection error reaching the proxy (metering was enabled, so this is our endpoint)"),
]


def last_mention(log: str, cid: str, after: datetime):
    """Timestamp of the last log line naming this case. Evidence, not a guess."""
    best = None
    for line in log.splitlines():
        if cid not in line:
            continue
        m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line.strip())
        if not m:
            continue
        try:
            t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
        if t >= after and (best is None or t > best):
            best = t
    return best


def load(batch: Path):
    m = json.loads((batch / "metrics.json").read_text()) if (batch / "metrics.json").exists() else {"cases": []}
    calls, hbs, perrs = [], [], []
    uf = batch / "usage.jsonl"
    if uf.exists():
        for line in uf.read_text(errors="replace").splitlines():
            try:
                r = json.loads(line)
                t = datetime.fromisoformat(r["ts"]).replace(tzinfo=None)
            except Exception:
                continue
            k = r.get("kind", "call")
            (perrs if k == "proxy_error" else hbs if k == "heartbeat" else calls).append((t, r))
    log = (batch / "run.log").read_text(errors="replace") if (batch / "run.log").exists() else ""
    return m, calls, hbs, perrs, log


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    batch = Path(sys.argv[1])
    metrics, calls, hbs, perrs, log = load(batch)

    # Largest heartbeat gap tells us the longest window the proxy was provably not alive.
    hb_times = sorted(t for t, _ in hbs)
    gaps = []
    for a, b in zip(hb_times, hb_times[1:]):
        if (b - a) > timedelta(seconds=90):      # 3x the 30s heartbeat
            gaps.append((a, b))

    hb_interval = 30  # must match usage_proxy.py --heartbeat
    all_times = sorted([t for t, _ in calls] + [t for t, _ in hbs] + [t for t, _ in perrs])

    out, needs_rerun = [], 0
    for c in metrics.get("cases", []):
        cid, status = c["case_id"], c.get("status")
        if status == "success":
            continue
        # A missing finished_at used to become `start + 1 hour`, which is not a fallback
        # but an invention: the silence check then compared the proxy's real last record
        # against a case end that never happened, and reported `proxy_suspect` for a case
        # that had simply exhausted its retries. Take the end from the log instead — the
        # last timestamped line naming this case is evidence — and if even that is absent,
        # say so and skip the timing checks rather than guess.
        try:
            s = datetime.fromisoformat(c["started_at"])
        except Exception:
            out.append({"case_id": cid, "verdict": "unknown", "why": "unparseable start time"})
            needs_rerun += 1
            continue
        e, end_known = None, True
        if c.get("finished_at"):
            try:
                e = datetime.fromisoformat(c["finished_at"])
            except Exception:
                e = None
        if e is None:
            e, end_known = last_mention(log, cid, s), False
        if e is None:
            e, end_known = s, False

        window_calls = [r for t, r in calls if s <= t <= e and r.get("status") == 200]
        window_perrs = [r for t, r in perrs if s <= t <= e]
        window_gaps = [(a, b) for a, b in gaps if not (b < s or a > e)]

        # Case-scoped slice of the log, for harness-pattern matching.
        seg = "\n".join(l for l in log.splitlines() if cid in l)

        verdict, why = None, None
        # An API-limit casualty is defined by having made NO attempt, not by a limit error
        # appearing near it. San2Patch tags many lines with the *previous* case's id, so a
        # limit error that killed the NEXT case leaks into this one's segment: two cases
        # that had completed full 5-try attempts (458k and 311k tokens) and genuinely
        # failed, minutes before the limit, were labelled api_limit on that basis. They
        # were then re-run and passed, which quietly turned a 5-try protocol into
        # best-of-10 for those cases. Require the absence of real work before believing it.
        if API_LIMIT.search(seg) and len(window_calls) <= 2:
            verdict, why = "api_limit", "account usage limit reached — no attempt was made"
        # A killed proxy writes nothing further — no proxy_error, no heartbeat — so the
        # decisive evidence is silence lasting past the end of the case. This is checked
        # PER CASE (the last record at or before this case's end), not against the batch's
        # global last record, which would only ever catch the final case.
        #
        # It cannot false-positive on a case whose tail is a long build/test with no LLM
        # traffic: heartbeats are emitted every hb_interval regardless of activity, so a
        # live proxy always leaves a record within that window.
        #
        # Only meaningful against a REAL case end. With an inferred one this check is
        # comparing the proxy against a time we made up, which is how it once produced a
        # confident `proxy_suspect` for a case that failed to apply its own patch.
        prior = [t for t in all_times if t <= e]
        last_record = max(prior) if prior else None
        if end_known and last_record and last_record < e - timedelta(seconds=hb_interval * 2):
            verdict = "proxy_suspect"
            why = (f"proxy went silent at {last_record.time()} but the case ran to "
                   f"{e.time()} — its last LLM calls could not have reached the API")
        if verdict is None and window_perrs:
            verdict, why = "proxy_suspect", f"{len(window_perrs)} proxy_error record(s) inside the case window"
        elif window_gaps:
            verdict, why = "proxy_suspect", f"heartbeat gap {window_gaps[0][0].time()}–{window_gaps[0][1].time()} overlaps the case"
        else:
            for pat, desc in PROXY_PATTERNS:
                if pat.search(seg):
                    verdict, why = "proxy_suspect", desc
                    break
        if verdict is None and not HARNESS_WORKED.search(seg):
            for pat, desc in HARNESS_PATTERNS:
                if pat.search(seg):
                    verdict, why = "harness", desc
                    break
        if verdict is None and calls and not window_calls:
            verdict, why = "no_llm_calls", "no successful API call inside the case window"
        if verdict is None:
            verdict = "genuine" if status in ("failed", None) else "genuine"
            why = f"reached the API ({len(window_calls)} calls); outcome is the tool's"

        if verdict != "genuine":
            needs_rerun += 1
        out.append({"case_id": cid, "status": status, "verdict": verdict, "why": why,
                    "llm_calls": len(window_calls), "window": [s.isoformat(), e.isoformat()],
                    "end_from": "log" if end_known else "inferred from last log mention"})

    (batch / "triage.json").write_text(json.dumps({
        "batch": batch.name,
        "proxy_errors_total": len(perrs),
        "heartbeat_gaps": [[a.isoformat(), b.isoformat()] for a, b in gaps],
        "cases": out,
    }, indent=2) + "\n")

    print(f"  non-success cases : {len(out)}")
    for v in ("genuine", "api_limit", "proxy_suspect", "harness", "no_llm_calls", "unknown"):
        n = sum(1 for r in out if r["verdict"] == v)
        if n:
            print(f"    {v:15} {n}")
    if perrs:
        print(f"  proxy_error records: {len(perrs)}  <-- these calls never reached Anthropic")
    if gaps:
        print(f"  heartbeat gaps     : {len(gaps)}  <-- proxy was not alive during these")
    for r in out:
        if r["verdict"] != "genuine":
            print(f"    [{r['verdict']}] {r['case_id']}: {r['why']}")
    print(f"  wrote             : {batch/'triage.json'}")
    if needs_rerun:
        print(f"\n  {needs_rerun} case(s) need a re-run before they can be reported.")
    return 1 if needs_rerun else 0


if __name__ == "__main__":
    raise SystemExit(main())
