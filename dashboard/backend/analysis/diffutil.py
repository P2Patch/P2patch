"""Minimal unified-diff parsing and patch-overlap helpers (dependency-free)."""
from __future__ import annotations

import re
from typing import List

DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


def is_test_path(path: str) -> bool:
    low = path.lower()
    return "/test/" in low or low.endswith("test.java") or "tests" in low or "/test/" in f"/{low}"


class FileDiff:
    def __init__(self, path: str, old_path: str) -> None:
        self.path = path
        self.old_path = old_path
        self.is_test = is_test_path(path)
        self.hunks: List[str] = []
        self.added = 0
        self.removed = 0

    def text(self) -> str:
        header = f"--- a/{self.old_path}\n+++ b/{self.path}\n"
        return header + "\n".join(self.hunks)

    def to_json(self) -> dict:
        return {
            "path": self.path,
            "is_test": self.is_test,
            "added": self.added,
            "removed": self.removed,
            "hunks": self.hunks,
        }


def parse_diff(diff: str) -> List[FileDiff]:
    """Split a unified git diff into per-file entries with their hunks."""
    files: List[FileDiff] = []
    current: FileDiff | None = None
    hunk: List[str] | None = None

    def flush_hunk() -> None:
        nonlocal hunk
        if current is not None and hunk:
            current.hunks.append("\n".join(hunk))
        hunk = None

    for line in (diff or "").splitlines():
        m = DIFF_GIT_RE.match(line)
        if m:
            flush_hunk()
            current = FileDiff(path=m.group(2), old_path=m.group(1))
            files.append(current)
            continue
        if current is None:
            continue
        if HUNK_RE.match(line):
            flush_hunk()
            hunk = [line]
            continue
        if hunk is not None:
            hunk.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                current.added += 1
            elif line.startswith("-") and not line.startswith("---"):
                current.removed += 1
    flush_hunk()
    return files


def changed_files(diff: str, include_tests: bool = True) -> List[str]:
    return [f.path for f in parse_diff(diff) if include_tests or not f.is_test]


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def structural_overlap(our_diff: str, official_files: List[str]) -> dict:
    """How much does our patch touch the same files as the official fix?

    Compared on basenames so different source roots (worktree vs upstream) still
    match. This is the single most predictive cheap signal for intent alignment.
    """
    ours = {_basename(p) for p in changed_files(our_diff, include_tests=False)}
    official = {_basename(p) for p in official_files}
    if not official:
        return {"overlap_files": [], "ours_only": sorted(ours), "official_only": [], "jaccard": 0.0}
    inter = ours & official
    union = ours | official
    return {
        "overlap_files": sorted(inter),
        "ours_only": sorted(ours - official),
        "official_only": sorted(official - ours),
        "jaccard": round(len(inter) / len(union), 3) if union else 0.0,
        "covers_all_official": official.issubset(ours),
    }
