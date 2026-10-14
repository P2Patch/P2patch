#!/usr/bin/env python3
"""Render the residual-gap audit as an overview table plus one file per PoV.

Two layers, because they answer different questions:

``REPORT.md``            one row per PoV — what everything is, at a glance
``reports/<slug>__<pov>.md``  everything known about ONE PoV, self-contained,
                         for someone auditing that single claim by hand

Both are **generated**. Never hand-edit them; edit the inputs and re-run:

    residual_povs/triage/verdicts.json   human verdicts   (triage/add_verdict.py)
    residual_povs/verification/*.json    executed records (`respov reverify`)
    residual_povs/TRIAGE.json            machine sweep    (triage/sweep_upstream.py)

Each row carries three independent marks rather than one blended score, because
a claim is only as strong as its weakest one:

  read     a person read upstream's current code and history
  ran      we re-executed the PoV ourselves — reproduces on the unpatched tree
           AND after the official fix — recorded outside the manifest
  control  the PoV was shown falsifiable: `blocked` on a tree where the gap is
           known closed. Without it, a PoV that exits 0 on every tree is
           indistinguishable from a real gap.

    python3 residual_povs/triage/render_report.py
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES_DIR = ROOT / "residual_povs"
TRIAGE_PATH = RES_DIR / "TRIAGE.json"
VERIFICATION_DIR = RES_DIR / "verification"
REPORT_PATH = RES_DIR / "REPORT.md"
DETAIL_DIR = RES_DIR / "reports"

STATUS_TITLE = {
    "open-at-head": "Still open in upstream's current code",
    "fixed-later": "Closed later by upstream itself",
    "superseded-in-release": "Never shipped open — an artifact of the chosen baseline",
    "disputed": "Disputed — by design under the project's threat model",
    "unsound": "Unsound instrument — exclude from the score",
    "needs-manual": "Needs a human — machine evidence is not decisive",
    "untriaged": "Not yet triaged",
}
STATUS_ORDER = list(STATUS_TITLE)
STATUS_MARK = {
    "open-at-head": "🔴 open", "fixed-later": "🔵 fixed later",
    "superseded-in-release": "⚪ superseded", "disputed": "🟡 disputed",
    "unsound": "🟠 unsound", "needs-manual": "⚫ manual", "untriaged": "· untriaged",
}
SIGNAL_NOTE = {
    "fix_intact": "the official fix's own added lines are still verbatim at HEAD",
    "fix_changed": "some of the official fix's lines are gone at HEAD — upstream revised it",
    "file_absent": "the guarded file is not at that path (moved, refactored, or the dataset URL is dead)",
    "not_checked": "no upstream sweep has run",
    "no_patch": "no official_fix.patch recorded",
}


def load_triage() -> dict:
    if not TRIAGE_PATH.exists():
        raise SystemExit("residual_povs/TRIAGE.json missing — run triage/sweep_upstream.py first")
    return json.loads(TRIAGE_PATH.read_text(encoding="utf-8"))


def load_executions() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not VERIFICATION_DIR.is_dir():
        return out
    for path in sorted(VERIFICATION_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        slug = data.get("project_slug") or path.stem
        for pov_id, rec in (data.get("povs") or {}).items():
            rec = dict(rec)
            rec["_trees_meta"] = data.get("trees") or {}
            rec["_generated_at"] = data.get("generated_at", "")
            out[f"{slug}::{pov_id}"] = rec
    return out


def manifest_for(slug: str) -> dict:
    p = RES_DIR / slug / "manifest.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def pov_entry(manifest: dict, pov_id: str) -> dict:
    for pov in manifest.get("povs", []):
        if pov.get("id") == pov_id:
            return pov
    return {}


def lag(days) -> str:
    if days is None:
        return "—"
    if days < 60:
        return f"{days}d"
    if days < 400:
        return f"{round(days / 30.4)}mo"
    return f"{days / 365:.1f}y"


def marks(row: dict, rec: dict) -> tuple[str, str, str]:
    read = "read" if row.get("verified_by") else "–"
    trees = (rec or {}).get("trees") or {}
    baseline = [t for t in ("unpatched", "official-fix") if t in trees]
    ran = "–"
    if baseline:
        ran = "ran" if all(trees[t]["verdict"] == "as_expected" for t in baseline) else "RAN?"
    control = {"passed": "ctrl", "failed": "CTRL-FAIL"}.get(
        (rec or {}).get("falsifiability_control", "not_run"), "–")
    return read, ran, control


def detail_name(row: dict) -> str:
    return f"{row['project_slug']}__{row['pov_id']}.md"


# --------------------------------------------------------------------------- #
# per-PoV detail                                                              #
# --------------------------------------------------------------------------- #
def render_detail(row: dict, rec: dict) -> str:
    slug, pov_id = row["project_slug"], row["pov_id"]
    manifest = manifest_for(slug)
    pov = pov_entry(manifest, pov_id)
    val = pov.get("validation") or {}
    fix_ref = manifest.get("fix_reference") or {}
    ev = row.get("upstream_evidence") or {}
    o: list[str] = []
    w = o.append

    w(f"# `{pov_id}`")
    w("")
    w(f"**{slug}** · {row.get('cve_id') or '—'} · {row.get('cwe_id') or '—'}")
    w("")
    read, ran, ctrl = marks(row, rec)
    w(f"| status | claim class | confidence | read | ran | control |")
    w(f"|---|---|---|---|---|---|")
    w(f"| **{STATUS_MARK.get(row['status'], row['status'])}** | {row.get('claim_class') or '—'} | "
      f"{row.get('confidence') or '—'} | {read} | {ran} | {ctrl} |")
    w("")
    w(f"> {STATUS_TITLE.get(row['status'], row['status'])}")
    w("")

    w("## The gap")
    w("")
    w(row.get("gap_summary") or pov.get("gap_summary") or "_not recorded_")
    w("")
    if pov.get("description"):
        w(f"**PoV.** {pov['description']}")
        w("")
    if pov.get("exploit_path"):
        w("**Exploit path.**")
        w("")
        w(f"```\n{pov['exploit_path']}\n```")
        w("")
    if pov.get("covers_alert_paths"):
        w("**Covers.**")
        for c in pov["covers_alert_paths"]:
            w(f"- {c}")
        w("")

    w("## The official fix it survives")
    w("")
    commits = row.get("official_fix_commits") or fix_ref.get("fix_commit_ids") or []
    if commits:
        w(f"- Commit(s): {', '.join('`' + c[:12] + '`' for c in commits)}")
    if row.get("official_fix_commit"):
        w(f"- Recorded as closing this CVE: `{row['official_fix_commit']}`"
          + (f" ({row['official_fix_date']})" if row.get("official_fix_date") else ""))
    if fix_ref.get("official_fix_patch"):
        w(f"- Patch: `residual_povs/{slug}/{fix_ref['official_fix_patch']}`")
    w("")
    if fix_ref.get("fix_summary"):
        w("**What the fix does, and where it stops:**")
        w("")
        w(f"> {fix_ref['fix_summary']}")
        w("")

    w("## Upstream today")
    w("")
    liveness = ev.get("liveness") or {}
    w(f"- Repository: `{ev.get('repo') or '—'}`"
      + (f" · last push {liveness['pushed_at']}" if liveness.get("pushed_at") else "")
      + (" · **archived**" if liveness.get("archived") else "")
      + (f" · ★{liveness['stars']}" if liveness.get("stars") is not None else ""))
    sig = ev.get("signal", "not_checked")
    w(f"- Machine sweep: `{sig}` — {SIGNAL_NOTE.get(sig, '')}")
    w(f"  <br><sub>A lead, not a verdict: cxf read `fix_intact` and was in fact fixed later, "
      f"upstream having added an escape elsewhere in the same file.</sub>")
    if ev.get("files"):
        w("")
        w("| guarded file | state | fix lines present / missing |")
        w("|---|---|---|")
        for f in ev["files"]:
            w(f"| `{f['path']}` | {f['state']} | "
              f"{f.get('present', '—')} / {f.get('missing', '—')} of {f.get('signature_lines', '—')} |")
        for f in ev["files"]:
            if f.get("missing_examples"):
                w("")
                w(f"Lines of the official fix no longer at HEAD in `{f['path'].split('/')[-1]}`:")
                w("")
                for m in f["missing_examples"]:
                    w(f"- `{m}`")
    w("")

    w("## Verdict")
    w("")
    if row.get("later_fix_commit"):
        w(f"- **Closed later by** `{row['later_fix_commit']}`"
          + (f" ({row['later_fix_date']})" if row.get("later_fix_date") else ""))
        if row.get("later_fix_release"):
            w(f"- **First shipped in** {row['later_fix_release']}")
        if row.get("delta_days") is not None:
            w(f"- **Lag** {lag(row['delta_days'])} ({row['delta_days']} days) from the official fix")
    if row.get("releases_exposed"):
        w(f"- **Releases exposed:** {row['releases_exposed']}")
    if row.get("corroboration"):
        w(f"- **Corroboration:** {row['corroboration']}")
    w("")
    if row.get("notes"):
        w("### Findings")
        w("")
        w(row["notes"])
        w("")
    if row.get("evidence_urls"):
        w("### Evidence")
        w("")
        for u in row["evidence_urls"]:
            w(f"- {u}")
        w("")
    if row.get("verified_by"):
        w(f"<sub>Verified by: {row['verified_by']}</sub>")
        w("")

    if row.get("reachability"):
        w("## Reachability")
        w("")
        verdict_note = {
            "reportable": "an attacker can reach this through a public entry point",
            "code-quality-only": "real defect, but no attacker-reachable path was found",
            "by-design": "the 'attacker' already holds the privilege this would grant",
            "needs-more-work": "not settled — see below",
        }
        w(f"**{row['reachability']}** — {verdict_note.get(row['reachability'], '')}")
        w("")
        if row.get("reachability_notes"):
            w(row["reachability_notes"])
            w("")
        w("<sub>Reachability is judged separately from status: \"the defect is still in the "
          "code\" and \"someone can exploit it\" are different claims, and only the second "
          "justifies a disclosure.</sub>")
        w("")

    w("## Executed evidence")
    w("")
    trees = (rec or {}).get("trees") or {}
    if not trees:
        w("**Not re-executed yet.** The only run on record is the manifest's own "
          "certification, which was written by the process that certified it.")
        w("")
    else:
        w("| tree | revision | expected | outcome | exit | verdict |")
        w("|---|---|---|---|---|---|")
        for key, t in trees.items():
            rev = (t.get("revision") or "")[:12]
            w(f"| `{key}` | `{rev}` | {t['expectation']} | **{t['outcome']}** | "
              f"{t.get('exit_code') if t.get('exit_code') is not None else '—'} | {t['verdict']} |")
        w("")
        fc = (rec or {}).get("falsifiability_control", "not_run")
        if fc == "passed":
            w("> **Falsifiability control passed.** This PoV is not a tautology: it is blocked "
              "on a tree where the gap is closed and reproduces where it is not.")
        elif fc == "failed":
            w("> ⚠ **Falsifiability control FAILED** — the PoV still reproduced on a tree where "
              "upstream is claimed to have closed the gap. Either the claim or the PoV is wrong; "
              "resolve before citing this row.")
        else:
            w("> Falsifiability control **not run**. An `errored` control is a toolchain failure "
              "(a PoV written for a 2018 tree usually will not build against a 2024 one) and is "
              "evidence for nothing.")
        w("")

    w("## Certification on record")
    w("")
    if val:
        w(f"- Certified: **{bool(val.get('certified'))}**")
        for phase in ("before", "after"):
            p = val.get(phase) or {}
            if p:
                w(f"- `{phase}` ({p.get('at', '?')}): {p.get('outcome')} (exit {p.get('exit_code')})")
        if val.get("content_hash"):
            w(f"- Content fingerprint: `{val['content_hash'][:16]}…`")
        if val.get("ran_at"):
            w(f"- Recorded: {val['ran_at']}")
    else:
        w("_no validation block in the manifest_")
    w("")

    w("## Redo it yourself")
    w("")
    w("```bash")
    w(f"# the suite, the PoV source, the official fix patch")
    w(f"ls residual_povs/{slug}/")
    w(f"# re-execute the certification, independently of the manifest")
    w(f"python -m security_pipeline respov reverify --project {slug}")
    if row.get("later_fix_commit"):
        w(f"# the falsifiability control — must come back BLOCKED")
        w(f"python -m security_pipeline respov reverify --project {slug} \\")
        w(f"    --skip-baseline --at {row['later_fix_commit']} --at-pov {pov_id}")
    if row["status"] == "open-at-head":
        w(f"# the open claim, executed — must come back REPRODUCED")
        w(f"python -m security_pipeline respov reverify --project {slug} \\")
        w(f"    --skip-baseline --still-open <default-branch> --at-pov {pov_id}")
    w(f"# refresh the upstream evidence for this suite")
    w(f"python3 residual_povs/triage/sweep_upstream.py --slug {slug}")
    w("```")
    w("")
    w("---")
    w("")
    w("<sub>Generated by `residual_povs/triage/render_report.py`. Do not hand-edit — "
      "record verdicts with `triage/add_verdict.py` and execution with `respov reverify`.</sub>")
    return "\n".join(o) + "\n"


# --------------------------------------------------------------------------- #
# overview                                                                     #
# --------------------------------------------------------------------------- #
def render_overview(data: dict, ex: dict[str, dict]) -> str:
    rows = data["povs"]
    o: list[str] = []
    w = o.append

    executed = [r for r in rows if (ex.get(r["pov_uid"]) or {}).get("trees")]
    controls = [r for r in rows if (ex.get(r["pov_uid"]) or {}).get("falsifiability_control") == "passed"]
    contra = [r for r in rows if (ex.get(r["pov_uid"]) or {}).get("summary") == "contradicts"]
    by_status: dict[str, list[dict]] = {}
    for r in rows:
        by_status.setdefault(r["status"], []).append(r)

    w("# Residual-gap audit — overview")
    w("")
    w(f"*Generated {data.get('generated_at', '')}. One row per certified residual PoV. "
      "Click a PoV for its full dossier.*")
    w("")
    w("A **residual PoV** is an exploit that still reproduces after a project's official CVE "
      "fix. Certification proves it is a usable instrument; it does not prove the gap mattered. "
      "This audit closes that distance, and each row is graded on three independent marks:")
    w("")
    w("| mark | meaning |")
    w("|---|---|")
    w("| `read` | a person read upstream's current code and history for this PoV |")
    w("| `ran` | we re-executed the PoV — reproduces unpatched **and** after the official fix — "
      "recorded outside the manifest |")
    w("| `ctrl` | proven falsifiable: `blocked` on a tree where the gap is known closed |")
    w("")

    w("## Where it stands")
    w("")
    w(f"- **{len(rows)} certified residual PoVs** across "
      f"**{len({r['project_slug'] for r in rows})} CVE suites**")
    w(f"- **{len(executed)}/{len(rows)} re-executed** independently; "
      f"**{len(controls)} falsifiability controls passed**")
    if contra:
        w(f"- ⚠ **{len(contra)} PoV(s) contradicted their expected outcome** — read those first")
    w("")
    w("| status | PoVs | meaning |")
    w("|---|---|---|")
    for st in STATUS_ORDER:
        if by_status.get(st):
            w(f"| {STATUS_MARK.get(st, st)} | {len(by_status[st])} | {STATUS_TITLE[st]} |")
    w("")
    w("**Only `fixed-later` and `open-at-head` support an upstream-miss claim.** "
      "`superseded-in-release` means no released tree ever had the gap — it is an artifact of "
      "which commit the benchmark treats as the official fix. `unsound` means no patch can block "
      "the PoV without deleting the feature, so it scores every patch for a reason unrelated to "
      "the patch, and must be excluded from the residual score.")
    w("")

    w("## Every PoV")
    w("")
    w("| project | PoV | CVE | status | class | reach | lag | read | ran | ctrl | detail |")
    w("|---|---|---|---|---|---|---|:--:|:--:|:--:|---|")
    for r in sorted(rows, key=lambda x: (
            STATUS_ORDER.index(x["status"]) if x["status"] in STATUS_ORDER else 99,
            x["project_slug"], x["pov_id"])):
        rec = ex.get(r["pov_uid"]) or {}
        read, ran, ctrl = marks(r, rec)
        proj = r["project_slug"].split("_CVE")[0].split("_bugzilla")[0]
        reach = {"reportable": "**yes**", "code-quality-only": "code-only",
                 "by-design": "by-design", "needs-more-work": "?"}.get(r.get("reachability", ""), "—")
        w(f"| `{proj}` | `{r['pov_id']}` | {r.get('cve_id') or '—'} | "
          f"{STATUS_MARK.get(r['status'], r['status'])} | {r.get('claim_class') or '—'} | "
          f"{reach} | {lag(r.get('delta_days'))} | {read} | {ran} | {ctrl} | "
          f"[dossier](reports/{detail_name(r)}) |")
    w("")

    for st in STATUS_ORDER:
        group = by_status.get(st)
        if not group:
            continue
        w(f"## {STATUS_TITLE[st]} — {len(group)} PoVs")
        w("")
        if st == "fixed-later":
            w("Upstream itself later closed the path the PoV drives. The lag between the official "
              "CVE fix and that later commit is the detection-lead measurement.")
        elif st == "open-at-head":
            w("The same defect is still in upstream's current code. **Open at head is not the same "
              "as exploitable** — several of these drive a library API or a CLI tool rather than a "
              "product entry point, and each needs reachability established before disclosure.")
        elif st == "superseded-in-release":
            w("No released tree ever carried the gap: the benchmark's chosen \"official fix\" commit "
              "is not what upstream shipped. Valid instruments; no upstream-miss claim.")
        w("")
        w("| project · PoV | lag | corroboration | detail |")
        w("|---|---|---|---|")
        for r in sorted(group, key=lambda x: (x["project_slug"], x["pov_id"])):
            corr = (r.get("corroboration") or "—")
            corr = corr[:100] + ("…" if len(corr) > 100 else "")
            proj = r["project_slug"].split("_CVE")[0].split("_bugzilla")[0]
            w(f"| `{proj}` · `{r['pov_id']}` | {lag(r.get('delta_days'))} | {corr} | "
              f"[dossier](reports/{detail_name(r)}) |")
        w("")

    w("## What this report cannot say")
    w("")
    w("- **`ran` is not `ctrl`.** A PoV that reproduces on both baseline trees has an "
      "independently re-proved certification, and nothing more.")
    w("- **An `errored` execution is evidence for nothing.** A PoV written against a 2018 revision "
      "usually will not build against a 2024 one — the per-CVE Docker image pins an old toolchain "
      "— so the control reports `inconclusive`, never `blocked`.")
    w("- **Open at head ≠ exploitable.** Before any disclosure: attacker-controlled input must "
      "reach the sink through a public entry point, preconditions must be realistic, and a trust "
      "boundary must actually be crossed. Containers here run as root; a gap needing root is not "
      "a finding.")
    w("- **A synthetic tree is not a shipped release.** Certification runs against "
      "`buggy_commit + official_fix.patch`, which never shipped.")
    w("")
    return "\n".join(o) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    data = load_triage()
    ex = load_executions()

    DETAIL_DIR.mkdir(parents=True, exist_ok=True)
    for stale in DETAIL_DIR.glob("*.md"):
        stale.unlink()
    for row in data["povs"]:
        (DETAIL_DIR / detail_name(row)).write_text(
            render_detail(row, ex.get(row["pov_uid"]) or {}), encoding="utf-8")

    REPORT_PATH.write_text(render_overview(data, ex), encoding="utf-8")
    print(f"wrote {REPORT_PATH.relative_to(ROOT)} "
          f"and {len(data['povs'])} dossiers in {DETAIL_DIR.relative_to(ROOT)}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
