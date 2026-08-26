#!/usr/bin/env python3
"""Generate the full re-execution plan for every residual suite.

Emits a self-contained bash script that runs `respov reverify` over the whole
corpus. The plan is *derived from the verdicts*, not hand-written, so each claim
gets the tree that could refute it:

  every suite          the baseline pair — unpatched, and buggy + official_fix —
                       which re-proves the certification independently of the
                       manifest that recorded it
  fixed-later POVs     `--at <later-fix commit>`, scoped with --at-pov, expecting
                       **blocked**: the falsifiability control
  open-at-head POVs    `--still-open <default branch>`, scoped, expecting
                       **reproduced**: the open claim, executed rather than read

Three things the generator has to get right, each learned the hard way:

* **Scope the expectation per POV.** DependencyCheck has one POV upstream closed
  in 2019 and one it never closed; a suite-wide "must be blocked" reported the
  second as a contradiction while it was in fact confirming our claim.
* **Do not trust the dataset's repo URL for control revisions.** zip4j's row
  points at a synthetic decompiled-source repo, binutils' 404s, libtiff's GitHub
  repo is an archived mirror of a GitLab project. `REPO_OVERRIDES` carries the
  corrections, and the reason for each.
* **Retry a control in a modern toolchain before believing `errored`.** A per-CVE
  builder image is pinned to its era and usually cannot build a tree years newer,
  which surfaces as `errored` — evidence for nothing. Java suites get one retry
  in a stock Maven image.

    python3 residual_povs/triage/plan_execution.py > run_all.sh
    python3 residual_povs/triage/plan_execution.py --baseline-only > run_baselines.sh
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES_DIR = ROOT / "residual_povs"
TRIAGE = RES_DIR / "TRIAGE.json"

# Where a control revision actually lives, when it is not the dataset's URL.
REPO_OVERRIDES = {
    "srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2": (
        "srikanth-lingala/zip4j",
        "dataset points at iris-sast/zip4j, a synthetic repo of decompiled sources JARs",
    ),
    "git__binutils-gdb_CVE-2017-15025_515f23e63c00": (
        "gnutools/binutils-gdb",
        "dataset URL github.com/git/binutils-gdb 404s; this is the live GitHub mirror",
    ),
    "jeremylong__DependencyCheck_CVE-2018-12036_3.1.2": (
        "dependency-check/DependencyCheck",
        "jeremylong/DependencyCheck is archived; development moved",
    ),
    "vadz__libtiff_CVE-2016-5321_0ba5d8814a17": (
        "https://gitlab.com/libtiff/libtiff",
        "canonical home is GitLab; vadz/libtiff is an archived mirror",
    ),
    "vadz__libtiff_CVE-2017-5225_393881da1a7f": (
        "https://gitlab.com/libtiff/libtiff", "canonical home is GitLab"),
    "vadz__libtiff_CVE-2017-7601_3144e57770c1": (
        "https://gitlab.com/libtiff/libtiff", "canonical home is GitLab"),
    "vadz__libtiff_bugzilla-2611_9a72a69e035e": (
        "https://gitlab.com/libtiff/libtiff", "canonical home is GitLab"),
    "vadz__libtiff_CVE-2016-5314_c421b993abe1": (
        "https://gitlab.com/libtiff/libtiff", "canonical home is GitLab"),
    "gnome__libxml2_CVE-2017-5969_362b3229": (
        "https://gitlab.gnome.org/GNOME/libxml2",
        "canonical home is GNOME GitLab",
    ),
}

# Suites whose later fix has no reachable git revision at all.
NO_CONTROL = {
    "skyrpex__potrace_CVE-2013-7437_189777a2bd50":
        "upstream potrace has no public git — the fix shipped only in release tarballs",
}

SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


def gh_json(path: str):
    proc = subprocess.run(["gh", "api", path], capture_output=True, text=True,
                          errors="replace", check=False)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def resolve(slug: str, ref: str, repo: str | None) -> str | None:
    """Expand a short SHA to a full one. A short SHA can fail to check out even
    when the API resolves it, so the plan always carries the full form."""
    if not ref or not SHA_RE.match(ref):
        return ref or None
    target = repo or ""
    if "://" in target or not target:
        return ref            # non-GitHub or unknown: pass through, git resolves it
    data = gh_json(f"repos/{target}/commits/{ref}")
    return (data or {}).get("sha") or ref


def default_branch(repo: str | None) -> str | None:
    if not repo or "://" in repo:
        return None
    data = gh_json(f"repos/{repo}")
    return (data or {}).get("default_branch")


def project_repo(slug: str) -> str | None:
    """owner/name from the dataset, unless overridden."""
    if slug in REPO_OVERRIDES:
        return REPO_OVERRIDES[slug][0]
    import csv
    with (ROOT / "dataset/project_info.csv").open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("project_slug", "").strip() == slug:
                owner = (row.get("github_username") or "").strip()
                name = (row.get("github_repository_name") or "").strip()
                return f"{owner}/{name}" if owner and name else None
    return None


def is_java(slug: str) -> bool:
    manifest = json.loads((RES_DIR / slug / "manifest.json").read_text(encoding="utf-8"))
    blob = (manifest.get("build_command", "") or "") + " ".join(manifest.get("setup_commands", []) or [])
    if "mvn" in blob or "gradle" in blob:
        return True
    return any((RES_DIR / slug / "povs" / f).suffix == ".java"
               for f in [] ) or any(p.suffix == ".java" for p in (RES_DIR / slug / "povs").glob("*"))


def emit_suite(out: list[str], slug: str, body: list[str]) -> None:
    """Write one suite's commands into its own script under $OUT/suites/."""
    out.append(f'SUITES+=("{slug}")')
    out.append(f'cat > "$OUT/suites/{slug}.sh" <<\'SUITE_EOF\'')
    out.append("source /root/fullrun_common.sh")
    out.extend(body)
    out.append("SUITE_EOF")
    out.append("")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline-only", action="store_true",
                    help="emit only the unpatched / official-fix pass")
    ap.add_argument("--jobs", type=int, default=3, help="suites to run concurrently")
    args = ap.parse_args()

    rows = json.loads(TRIAGE.read_text(encoding="utf-8"))["povs"]
    suites: dict[str, list[dict]] = {}
    for r in rows:
        suites.setdefault(r["project_slug"], []).append(r)

    out: list[str] = []
    w = out.append
    w("#!/usr/bin/env bash")
    w("# GENERATED by residual_povs/triage/plan_execution.py — do not hand-edit.")
    w("# Full re-execution of every certified residual POV, with the claim-specific")
    w("# tree that could refute each one.")
    w("set -u")
    w("cd /root/autosec")
    w('OUT="/root/fullrun_$(date +%Y%m%d_%H%M%S)"; mkdir -p "$OUT"')
    w('LOG="$OUT/run.log"; IMG=maven:3.9-eclipse-temurin-17')
    w('mkdir -p "$OUT/suites"; SUITES=()')
    w('docker pull -q "$IMG" >/dev/null 2>&1 || true')
    w('echo "$OUT" > /root/fullrun_latest.txt')
    w("")
    w("# Per-suite scripts run in their own shell (xargs), so the shared env and")
    w("# helpers must be sourceable rather than inherited.")
    w('cat > /root/fullrun_common.sh <<COMMON_EOF')
    w('cd /root/autosec')
    w('OUT="$OUT"; LOG="$OUT/run.log"; IMG=maven:3.9-eclipse-temurin-17')
    w('COMMON_EOF')
    w("cat >> /root/fullrun_common.sh <<'COMMON_EOF'")
    w("# baseline pass for one suite: re-prove the certification independently")
    w("baseline() {")
    w('  echo "=== BASELINE $1" | tee -a "$LOG"')
    w('  timeout 5400 python3 -m security_pipeline respov reverify --project "$1" >>"$LOG" 2>&1')
    w('  echo "    exit=$?" | tee -a "$LOG"')
    w("}")
    w("")
    w("# control pass: run it in the project image, and only if that comes back")
    w("# `errored` (a toolchain failure, which is evidence for nothing) retry once")
    w("# in a stock modern Maven image.")
    w("control() {")
    w('  local slug="$1"; shift')
    w('  echo "=== CONTROL $slug $*" | tee -a "$LOG"')
    w('  timeout 5400 python3 -m security_pipeline respov reverify --project "$slug" --skip-baseline "$@" >>"$LOG" 2>&1')
    w('  local rc=$?')
    w('  if [ "${JAVA:-0}" = "1" ] && python3 - "$slug" <<\'PYEOF\'')
    w("import json, sys, pathlib")
    w('p = pathlib.Path("residual_povs/verification") / (sys.argv[1] + ".json")')
    w("d = json.loads(p.read_text()) if p.exists() else {}")
    w('errored = any(t.get("state") == "setup_failed" or (t.get("totals") or {}).get("errored")')
    w('              for k, t in (d.get("trees") or {}).items() if k.startswith(("at:", "open:")))')
    w("sys.exit(0 if errored else 1)")
    w("PYEOF")
    w("  then")
    w('    echo "    retrying control in $IMG" | tee -a "$LOG"')
    w('    timeout 5400 python3 -m security_pipeline respov reverify --project "$slug" --skip-baseline --control-image "$IMG" "$@" >>"$LOG" 2>&1')
    w('    rc=$?')
    w("  fi")
    w('  echo "    exit=$rc" | tee -a "$LOG"')
    w("}")
    w("COMMON_EOF")
    w("")

    planned = skipped = 0
    for slug in sorted(suites):
        povs = suites[slug]
        repo = project_repo(slug)
        java = is_java(slug)
        body: list[str] = []
        body.append(f"# {slug} ({len(povs)} POV)")
        if slug in REPO_OVERRIDES:
            body.append(f"#   repo override: {REPO_OVERRIDES[slug][0]} — {REPO_OVERRIDES[slug][1]}")
        body.append(f"JAVA={'1' if java else '0'}")
        body.append(f'baseline "{slug}"')
        planned += 1
        w = body.append

        if args.baseline_only:
            emit_suite(out, slug, body)
            w = out.append
            continue

        fixed = [r for r in povs if r["status"] == "fixed-later" and r.get("later_fix_commit")]
        openish = [r for r in povs if r["status"] == "open-at-head"]

        if slug in NO_CONTROL:
            w(f"#   no control possible: {NO_CONTROL[slug]}")
            skipped += 1
        elif fixed:
            ref = fixed[0]["later_fix_commit"].split()[0]
            full = resolve(slug, ref, repo)
            if not full or not SHA_RE.match(full):
                w(f"#   control skipped: later_fix_commit {ref!r} is not a resolvable revision")
                skipped += 1
            else:
                scope = " ".join(f'--at-pov {r["pov_id"]}' for r in fixed)
                repo_arg = f' --repo "{repo}"' if repo else ""
                w(f'control "{slug}"{repo_arg} --at {full} {scope}')
                planned += 1

        if openish:
            branch = default_branch(repo) if repo else None
            if not branch:
                w("#   still-open control skipped: could not resolve a default branch")
                skipped += 1
            else:
                scope = " ".join(f'--at-pov {r["pov_id"]}' for r in openish)
                repo_arg = f' --repo "{repo}"' if repo else ""
                w(f'control "{slug}"{repo_arg} --still-open {branch} {scope}')
                planned += 1
        emit_suite(out, slug, body)
        w = out.append

    w("# ---- dispatch ----")
    w("# Suites are independent (own image key, own workdir, own record file), so")
    w("# they shard cleanly. Docker memory is the limiter, not cores: budget ~3 GB")
    w("# per concurrent Maven/JVM build, the same rule --jobs uses elsewhere.")
    w('run_all() {')
    w('  for s in "${SUITES[@]}"; do')
    w('    printf "%s\\n" "$s"')
    w('  done | xargs -P ' + str(args.jobs) + ' -I{} bash "$OUT/suites/{}.sh"')
    w('}')
    w('run_all')
    w('echo "FULL RUN DONE $(date -Is)" | tee -a "$LOG"')
    w('cp -r residual_povs/verification "$OUT/verification" 2>/dev/null || true')
    print("\n".join(out))
    print(f"# planned invocations: {planned}; skipped controls: {skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
