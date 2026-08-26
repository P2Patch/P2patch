#!/usr/bin/env python3
"""Collect upstream evidence for every certified residual POV.

The residual oracle is one-sided (reproduce-before AND reproduce-after), so a
certification proves the POV is a usable *instrument* and nothing more. Turning
an instrument into a publishable claim needs upstream history: is the gap still
in the project's current code, or did upstream close it later — and when?

This script does the cheap, mechanical half of that (Stage 2 of
``RESIDUAL_GAP_TRIAGE.md``) for **all** suites rather than the seven that were
hand-traced, and it does it as *evidence collection, not classification*:

1. read every residual manifest and pair it with its upstream repo
   (``dataset/project_info.csv``);
2. parse ``official_fix.patch`` for the files the official fix touched and for
   the lines it *added* — those added lines are the fix's own signature;
3. fetch each of those files at upstream HEAD and check whether the fix's
   signature lines are still there verbatim;
4. list the recent commits touching each file as leads for the commit that
   changed it.

The signal it produces is deliberately weak and named as such:

``fix_intact``    every signature line still present at HEAD  -> the official
                  fix is unchanged, so a gap *inside* that fix is probably still
                  open. Candidate ``open``.
``fix_changed``   some signature lines are gone -> upstream rewrote the fix at
                  some point. Candidate ``fixed-later``.
``file_absent``   the guarded file no longer exists at that path (rename,
                  refactor, module move). Always needs a human.
``no_patch``      no official_fix.patch (documented negatives).

A candidate is not a finding. Only a human-verified row — with the closing
commit read and the release it shipped in checked — becomes ``fixed-later`` or
``open`` in ``TRIAGE.json``; this script only fills the ``upstream_evidence``
block that a human then reads. Nothing here overwrites a human verdict: rows
already carrying ``verified_by: human`` keep their status and gain only fresh
evidence.

Usage:
    python3 residual_povs/triage/sweep_upstream.py            # all suites
    python3 residual_povs/triage/sweep_upstream.py --slug perwendel__spark_CVE-2016-9177_2.5.1
    python3 residual_povs/triage/sweep_upstream.py --offline  # rebuild rows, no network

Requires the ``gh`` CLI, authenticated (it is only used for read-only API GETs).
"""
from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RES_DIR = ROOT / "residual_povs"
TRIAGE_PATH = RES_DIR / "TRIAGE.json"
VERDICTS_PATH = RES_DIR / "triage" / "verdicts.json"
VERIFICATION_DIR = RES_DIR / "verification"
PROJECT_INFO = ROOT / "dataset" / "project_info.csv"

# Lines that carry a fix's meaning. A `+` line that is only a brace, a comment
# or an import tells us nothing about whether the fix is still in place.
_TRIVIAL = re.compile(r"^[\s{}()\[\];]*$|^(//|/\*|\*|#|import |package |@)")
_MIN_SIGNATURE_LEN = 12


def sh(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(args, capture_output=True, text=True,
                          errors="replace", timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def gh_api(path: str, retries: int = 2) -> tuple[bool, object]:
    """GET an API path. Returns (ok, parsed-json-or-error-string)."""
    for attempt in range(retries + 1):
        code, out, err = sh(["gh", "api", path])
        if code == 0:
            try:
                return True, json.loads(out)
            except json.JSONDecodeError:
                return False, "unparseable response"
        if "rate limit" in (err or "").lower() and attempt < retries:
            time.sleep(20)
            continue
        return False, (err or "").strip().splitlines()[-1] if err else f"exit {code}"
    return False, "unreachable"


def load_project_index() -> dict[str, dict]:
    """slug -> {owner, repo, url, buggy_commit_id, fix_commit_ids}."""
    index: dict[str, dict] = {}
    with PROJECT_INFO.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            slug = (row.get("project_slug") or "").strip()
            if slug:
                # Prefer github_url over the username/repo columns: they can disagree,
                # and the URL is the one that is kept current. binutils is the worked
                # example — the columns still say `git`/`binutils-gdb` (a repo that
                # 404s) while github_url already points at the live `gnutools` mirror,
                # so building owner/name from the columns made the sweep report the
                # guarded file as absent when it was there all along.
                url = (row.get("github_url") or "").strip()
                owner = (row.get("github_username") or "").strip()
                repo = (row.get("github_repository_name") or "").strip()
                if url.startswith("https://github.com/"):
                    parts = url[len("https://github.com/"):].strip("/").split("/")
                    if len(parts) >= 2:
                        owner, repo = parts[0], parts[1]
                index[slug] = {
                    "owner": owner,
                    "repo": repo,
                    "url": (row.get("github_url") or "").strip(),
                    "buggy_commit_id": (row.get("buggy_commit_id") or "").strip(),
                    "fix_commit_ids": (row.get("fix_commit_ids") or "").strip(),
                    "cve_id": (row.get("cve_id") or "").strip(),
                }
    return index


def parse_official_fix(patch_path: Path) -> dict[str, list[str]]:
    """file path -> the meaningful lines the official fix ADDS to it."""
    if not patch_path.exists():
        return {}
    added: dict[str, list[str]] = {}
    current: str | None = None
    for raw in patch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip().split("\t")[0]
            if target.startswith("b/"):
                target = target[2:]
            current = None if target == "/dev/null" else target
            if current:
                added.setdefault(current, [])
        elif raw.startswith("+") and not raw.startswith("+++") and current:
            body = raw[1:].strip()
            if len(body) >= _MIN_SIGNATURE_LEN and not _TRIVIAL.match(body):
                added[current].append(body)
    return added


def fetch_file(owner: str, repo: str, path: str, ref: str | None = None) -> tuple[bool, str]:
    q = f"repos/{owner}/{repo}/contents/{path}"
    if ref:
        q += f"?ref={ref}"
    ok, payload = gh_api(q)
    if not ok or not isinstance(payload, dict) or "content" not in payload:
        return False, payload if isinstance(payload, str) else "no content field"
    try:
        return True, base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
    except Exception as exc:                                   # pragma: no cover
        return False, f"decode failed: {exc}"


def recent_commits(owner: str, repo: str, path: str, limit: int = 8) -> list[dict]:
    ok, payload = gh_api(f"repos/{owner}/{repo}/commits?path={path}&per_page={limit}")
    if not ok or not isinstance(payload, list):
        return []
    out = []
    for c in payload:
        commit = c.get("commit", {})
        out.append({
            "sha": (c.get("sha") or "")[:8],
            "date": (commit.get("author", {}).get("date") or "")[:10],
            "subject": (commit.get("message") or "").split("\n")[0][:140],
        })
    return out


def repo_liveness(owner: str, repo: str) -> dict:
    ok, payload = gh_api(f"repos/{owner}/{repo}")
    if not ok or not isinstance(payload, dict):
        return {"error": payload if isinstance(payload, str) else "unavailable"}
    return {
        "archived": payload.get("archived"),
        "pushed_at": (payload.get("pushed_at") or "")[:10],
        "stars": payload.get("stargazers_count"),
        "full_name": payload.get("full_name"),
        "default_branch": payload.get("default_branch"),
    }


def sweep_suite(slug: str, project: dict, offline: bool) -> dict:
    res_dir = RES_DIR / slug
    manifest = json.loads((res_dir / "manifest.json").read_text(encoding="utf-8"))
    signatures = parse_official_fix(res_dir / "official_fix.patch")

    owner, repo = project.get("owner", ""), project.get("repo", "")
    evidence: dict = {
        "repo": f"{owner}/{repo}" if owner and repo else None,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": [],
        "liveness": None,
        "signal": "no_patch" if not signatures else None,
    }
    if offline or not (owner and repo):
        evidence["signal"] = evidence["signal"] or "not_checked"
        return evidence

    evidence["liveness"] = repo_liveness(owner, repo)

    intact_total = missing_total = 0
    for path, sig_lines in signatures.items():
        ok, body = fetch_file(owner, repo, path)
        record: dict = {"path": path, "signature_lines": len(sig_lines)}
        if not ok:
            record["state"] = "file_absent"
            record["detail"] = body
            record["commit_leads"] = recent_commits(owner, repo, path)
            evidence["files"].append(record)
            continue
        present = [line for line in sig_lines if line in body]
        missing = [line for line in sig_lines if line not in body]
        intact_total += len(present)
        missing_total += len(missing)
        record["state"] = "fix_intact" if not missing else "fix_changed"
        record["present"] = len(present)
        record["missing"] = len(missing)
        record["missing_examples"] = missing[:4]
        if missing:
            record["commit_leads"] = recent_commits(owner, repo, path)
        evidence["files"].append(record)

    if evidence["signal"] is None:
        states = {f["state"] for f in evidence["files"]}
        if states == {"fix_intact"}:
            evidence["signal"] = "fix_intact"
        elif "file_absent" in states:
            evidence["signal"] = "file_absent"
        else:
            evidence["signal"] = "fix_changed"
    evidence["signature_lines_intact"] = intact_total
    evidence["signature_lines_missing"] = missing_total
    return evidence


def load_verdicts() -> dict[str, dict]:
    """Human-authored triage verdicts, keyed by ``<slug>::<pov_id>``.

    Kept in its own file so a re-sweep can never overwrite a person's reading of
    upstream history with a machine signal — the sweep owns
    ``upstream_evidence`` and nothing else.
    """
    if not VERDICTS_PATH.exists():
        return {}
    data = json.loads(VERDICTS_PATH.read_text(encoding="utf-8"))
    return {uid: row for uid, row in data.get("verdicts", {}).items()}


def load_executions() -> dict[str, dict]:
    """Execution records written by ``respov reverify``, keyed by POV uid."""
    out: dict[str, dict] = {}
    if not VERIFICATION_DIR.exists():
        return out
    for path in sorted(VERIFICATION_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        slug = data.get("project_slug") or path.stem
        for pov_id, record in (data.get("povs") or {}).items():
            out[f"{slug}::{pov_id}"] = record
    return out


def build_rows(offline: bool, only: str | None) -> dict:
    projects = load_project_index()
    verdicts = load_verdicts()
    executions = load_executions()
    existing = {}
    if TRIAGE_PATH.exists():
        prior = json.loads(TRIAGE_PATH.read_text(encoding="utf-8"))
        existing = {row["pov_uid"]: row for row in prior.get("povs", [])}

    rows: list[dict] = []
    suites = sorted(p.parent.name for p in RES_DIR.glob("*/manifest.json")
                    if p.parent.name != "_template")
    for slug in suites:
        if only and slug != only:
            # keep prior rows for suites we are not re-sweeping
            rows.extend(r for r in existing.values() if r["project_slug"] == slug)
            continue
        manifest = json.loads((RES_DIR / slug / "manifest.json").read_text(encoding="utf-8"))
        project = projects.get(slug, {})
        if offline:
            # Keep whatever the last online sweep found: an offline rebuild exists to
            # re-merge verdicts and execution records, not to erase evidence.
            evidence = next(
                (r["upstream_evidence"] for r in existing.values()
                 if r["project_slug"] == slug and r.get("upstream_evidence", {}).get("files")),
                {"signal": "not_checked", "files": [], "repo": None},
            )
        else:
            evidence = sweep_suite(slug, project, offline)
        print(f"  {slug}: {evidence.get('signal')}", file=sys.stderr)
        for pov in manifest.get("povs", []):
            uid = f"{slug}::{pov['id']}"
            prior = dict(existing.get(uid, {}))
            prior.update(verdicts.get(uid, {}))
            row = {
                "pov_uid": uid,
                "project_slug": slug,
                "pov_id": pov["id"],
                "cve_id": manifest.get("cve_id") or project.get("cve_id", ""),
                "cwe_id": manifest.get("cwe_id", ""),
                "certified": bool(pov.get("validation", {}).get("certified")),
                "content_hash": pov.get("validation", {}).get("content_hash", ""),
                "gap_summary": pov.get("gap_summary", ""),
                "official_fix_commits": manifest.get("fix_reference", {}).get("fix_commit_ids", []),
                # --- human triage fields: only a person writes these ---
                "status": prior.get("status", "untriaged"),
                "claim_class": prior.get("claim_class", ""),
                "later_fix_commit": prior.get("later_fix_commit", ""),
                "later_fix_date": prior.get("later_fix_date", ""),
                "later_fix_release": prior.get("later_fix_release", ""),
                "official_fix_date": prior.get("official_fix_date", ""),
                "delta_days": prior.get("delta_days", None),
                "releases_exposed": prior.get("releases_exposed", ""),
                "corroboration": prior.get("corroboration", ""),
                "notes": prior.get("notes", ""),
                "reachability": prior.get("reachability", ""),
                "reachability_notes": prior.get("reachability_notes", ""),
                "verified_by": prior.get("verified_by", ""),
                "evidence_urls": prior.get("evidence_urls", []),
                # --- execution control (filled by `respov reverify`) ---
                "execution": executions.get(uid, prior.get("execution", {})),
                # --- machine evidence, refreshed every sweep ---
                "upstream_evidence": evidence,
            }
            rows.append(row)

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": (
            "Generated: do not hand-edit. upstream_evidence is machine-collected and "
            "is a lead, not a verdict; status/later_fix_* come from "
            "residual_povs/triage/verdicts.json (human-authored); execution comes from "
            "`respov reverify` records under residual_povs/verification/. "
            "'untriaged' means nobody has read the upstream history for that POV yet."
        ),
        "sources": {
            "verdicts": str(VERDICTS_PATH.relative_to(ROOT)),
            "executions": str(VERIFICATION_DIR.relative_to(ROOT)),
        },
        "povs": sorted(rows, key=lambda r: r["pov_uid"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--slug", help="only sweep this suite (keeps every other row)")
    ap.add_argument("--offline", action="store_true", help="rebuild rows without network")
    args = ap.parse_args()

    print("sweeping residual suites...", file=sys.stderr)
    data = build_rows(offline=args.offline, only=args.slug)
    TRIAGE_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    by_signal: dict[str, int] = {}
    for row in data["povs"]:
        sig = row["upstream_evidence"].get("signal") or "unknown"
        by_signal[sig] = by_signal.get(sig, 0) + 1
    by_status: dict[str, int] = {}
    for row in data["povs"]:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    print(f"\nwrote {TRIAGE_PATH.relative_to(ROOT)}: {len(data['povs'])} POVs", file=sys.stderr)
    print(f"  machine signal: {by_signal}", file=sys.stderr)
    print(f"  human status  : {by_status}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
