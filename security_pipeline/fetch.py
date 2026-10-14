from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import paths
from .logging_io import ensure_dir
from .metadata import load_alert, load_project_info, load_project_info_by_slug


class FetchError(RuntimeError):
    pass


def _run_git(
    command: Sequence[str],
    action: str,
    cwd: Optional[Path] = None,
    timeout_seconds: int = 300,
) -> None:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise FetchError(f"{action} timed out after {timeout_seconds}s")
    if completed.returncode != 0:
        raise FetchError(f"{action} failed: {completed.stderr or completed.stdout}")


def fetch_source(
    github_url: str,
    commit_id: str,
    target_dir: Path,
    patches_dir: Optional[Path] = None,
    timeout_seconds: int = 300,
) -> None:
    """Fetch a single project the same way IRIS's fetch script did.

    Rather than cloning a release tag (``--branch``), which is fragile because
    the dataset's ``github_tag`` column is only a cosmetic version label and is
    not guaranteed to be a real git ref, this shallow-clones the default branch,
    then fetches and checks out the exact buggy commit, then applies the
    project's patch if one exists.
    """
    if target_dir.exists():
        print(f"  Skipping (already exists): {target_dir.name}")
        return

    if not commit_id:
        raise FetchError("no buggy_commit_id available to check out")

    ensure_dir(target_dir.parent)

    # 1) Shallow-clone the default branch.
    _run_git(
        ["git", "clone", "--depth", "1", github_url, str(target_dir)],
        action="git clone",
        timeout_seconds=timeout_seconds,
    )
    # 2) Fetch the exact buggy commit by SHA (works even when no tag points at it).
    _run_git(
        ["git", "fetch", "--depth", "1", "origin", commit_id],
        action="git fetch",
        cwd=target_dir,
        timeout_seconds=timeout_seconds,
    )
    # 3) Check out the buggy commit.
    _run_git(
        ["git", "checkout", commit_id],
        action="git checkout",
        cwd=target_dir,
        timeout_seconds=timeout_seconds,
    )

    # 4) Apply the project's patch if one is provided (buildability fixups).
    if patches_dir is not None:
        patch_path = patches_dir / f"{target_dir.name}.patch"
        if patch_path.exists():
            print(f"  Applying patch: {patch_path.name}")
            _run_git(
                ["git", "apply", str(patch_path)],
                action="git apply",
                cwd=target_dir,
                timeout_seconds=timeout_seconds,
            )


def fetch_project(
    workspace_root: Path,
    project_slug: str,
    projects_dir: Optional[Path] = None,
    timeout_seconds: int = 300,
) -> Path:
    """Fetch one project by dataset slug into ``dataset/project-sources/<slug>``.

    This is the slug-addressed entry point (the dashboard's clone button uses it);
    ``fetch_projects`` below is the alert-driven batch form. Both read the repo
    URL and buggy commit from ``dataset/project_info.csv`` and apply the
    project's buildability patch from ``dataset/patches/`` if there is one.
    """
    if projects_dir is None:
        projects_dir = paths.project_sources_dir(workspace_root)
    patches_dir = paths.patches_dir(workspace_root)
    project_info_path = paths.project_info_csv(workspace_root)
    if not project_info_path.exists():
        raise FetchError(f"project_info.csv not found at {project_info_path}")

    row = load_project_info_by_slug(project_info_path).get(project_slug)
    if row is None:
        raise FetchError(f"project slug not found in project_info.csv: {project_slug}")
    github_url = row.get("github_url", "")
    if not github_url:
        raise FetchError(f"no github_url for {project_slug}")

    target_dir = projects_dir / project_slug
    buggy_commit_id = row.get("buggy_commit_id", "")
    short_commit = buggy_commit_id[:12] if buggy_commit_id else "N/A"
    print(f"Fetching {project_slug} (commit: {short_commit})...")
    fetch_source(github_url, buggy_commit_id, target_dir, patches_dir, timeout_seconds)
    return target_dir


def fetch_projects(
    workspace_root: Path,
    alerts_dir: Path,
    projects_dir: Optional[Path] = None,
    limit: Optional[int] = None,
    timeout_seconds: int = 300,
) -> List[Dict[str, str]]:
    if projects_dir is None:
        projects_dir = paths.project_sources_dir(workspace_root)

    patches_dir = paths.patches_dir(workspace_root)

    project_info_path = paths.project_info_csv(workspace_root)
    if not project_info_path.exists():
        raise FetchError(f"project_info.csv not found at {project_info_path}")

    project_rows = load_project_info(project_info_path)

    alert_paths = sorted(alerts_dir.glob("*.json"))
    if limit is not None:
        alert_paths = alert_paths[:limit]

    results: List[Dict[str, str]] = []
    for alert_path in alert_paths:
        try:
            alert = load_alert(alert_path)
        except json.JSONDecodeError as exc:
            print(f"  Skipping invalid JSON: {alert_path.name}: {exc}", file=sys.stderr)
            continue

        cve_id = alert.get("cve_id")
        if not cve_id:
            print(f"  Skipping alert without cve_id: {alert_path.name}", file=sys.stderr)
            continue

        row = project_rows.get(cve_id)
        if row is None:
            print(f"  No project_info.csv row for {cve_id}", file=sys.stderr)
            continue

        project_slug = row["project_slug"]
        github_url = row.get("github_url", "")
        buggy_commit_id = row.get("buggy_commit_id", "")

        if not github_url:
            print(f"  No github_url for {cve_id}", file=sys.stderr)
            continue

        target_dir = projects_dir / project_slug
        short_commit = buggy_commit_id[:12] if buggy_commit_id else "N/A"
        print(f"Fetching {project_slug} (commit: {short_commit})...")
        try:
            fetch_source(github_url, buggy_commit_id, target_dir, patches_dir, timeout_seconds)
            results.append({"cve_id": cve_id, "project_slug": project_slug, "status": "ok"})
        except FetchError as exc:
            print(f"  Failed: {exc}", file=sys.stderr)
            results.append({"cve_id": cve_id, "project_slug": project_slug, "status": "failed", "error": str(exc)})

    return results
