#!/usr/bin/env python3
"""Merge execution records from another host into the local ones.

Execution evidence accumulates on whichever machine happened to run a tree: the
baseline pair on the server, a control retried locally in a stock image, a
rescoped re-run somewhere else. A plain `rsync` of
``residual_povs/verification/`` replaces whole files and therefore *destroys*
evidence — that is not hypothetical, it silently dropped a passing
falsifiability control that only existed locally.

So the sync is a merge, per tree, with an explicit conflict rule:

* a tree present on only one side is kept;
* a tree present on both is resolved by **informativeness, not recency** — a
  tree that ran beats one that failed setup, and a conclusive outcome
  (reproduced / blocked) beats `errored`, because `errored` is a toolchain
  failure and is evidence for nothing. Recency only breaks a tie between two
  equally informative records.

    python3 residual_povs/triage/sync_verification.py --from /path/to/pulled
    python3 residual_povs/triage/sync_verification.py --from host:/root/autosec/residual_povs/verification --ssh-key ~/.ssh/id_x
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "residual_povs" / "verification"

# Higher wins. `errored` is deliberately below every conclusive outcome.
OUTCOME_RANK = {"errored": 0, "blocked": 2, "reproduced": 2}
STATE_RANK = {"setup_failed": 0, "image_build_failed": 0, "ran": 2}


def tree_rank(tree: dict) -> int:
    return STATE_RANK.get(tree.get("state", ""), 1)


def pov_tree_rank(entry: dict) -> int:
    return OUTCOME_RANK.get(entry.get("outcome", ""), 1)


def merge_file(local_path: Path, incoming: dict) -> tuple[dict, list[str]]:
    changes: list[str] = []
    if not local_path.exists():
        return incoming, [f"new record {local_path.name}"]
    local = json.loads(local_path.read_text(encoding="utf-8"))

    merged_trees = dict(local.get("trees") or {})
    for key, tree in (incoming.get("trees") or {}).items():
        cur = merged_trees.get(key)
        if cur is None or tree_rank(tree) > tree_rank(cur):
            merged_trees[key] = tree
            changes.append(f"tree {key}")
        elif tree_rank(tree) == tree_rank(cur) and tree.get("duration_s", 0) and not cur.get("state"):
            merged_trees[key] = tree

    merged_povs = {}
    for pov_id in set(local.get("povs", {})) | set(incoming.get("povs", {})):
        lp = (local.get("povs") or {}).get(pov_id, {})
        ip = (incoming.get("povs") or {}).get(pov_id, {})
        trees = dict(lp.get("trees") or {})
        for key, entry in (ip.get("trees") or {}).items():
            cur = trees.get(key)
            if cur is None or pov_tree_rank(entry) > pov_tree_rank(cur):
                if cur is not None and pov_tree_rank(entry) > pov_tree_rank(cur):
                    changes.append(f"{pov_id}/{key}: {cur.get('outcome')} -> {entry.get('outcome')}")
                trees[key] = entry
        verdicts = [t["verdict"] for t in trees.values() if t.get("verdict") not in (None, "not_applicable")]
        control = [k for k, t in trees.items()
                   if t.get("expectation") == "block" and t.get("outcome") != "errored"]
        merged_povs[pov_id] = {
            "pov_id": pov_id,
            "trees": trees,
            "summary": ("contradicts" if "contradicts" in verdicts
                        else "as_expected" if verdicts and all(v == "as_expected" for v in verdicts)
                        else "inconclusive"),
            "falsifiability_control": (
                "passed" if any(trees[k].get("outcome") == "blocked" for k in control)
                else "failed" if control else "not_run"),
        }

    merged = dict(incoming)
    merged["trees"] = merged_trees
    merged["povs"] = merged_povs
    return merged, changes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from", dest="source", required=True,
                    help="local dir, or host:/path to pull over ssh first")
    ap.add_argument("--ssh-key", default=None)
    args = ap.parse_args()

    tmp: Path | None = None
    src = Path(args.source)
    if ":" in args.source and not src.exists():
        tmp = Path(tempfile.mkdtemp(prefix="respov_sync_"))
        rsh = f"ssh -i {args.ssh_key}" if args.ssh_key else "ssh"
        proc = subprocess.run(["rsync", "-az", "-e", rsh, args.source.rstrip("/") + "/", str(tmp) + "/"],
                              capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise SystemExit(f"rsync failed: {proc.stderr.strip()[:400]}")
        src = tmp

    LOCAL.mkdir(parents=True, exist_ok=True)
    total = 0
    for path in sorted(src.glob("*.json")):
        incoming = json.loads(path.read_text(encoding="utf-8"))
        merged, changes = merge_file(LOCAL / path.name, incoming)
        (LOCAL / path.name).write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
        if changes:
            total += len(changes)
            print(f"{path.name}: {'; '.join(changes[:4])}"
                  + (f" (+{len(changes) - 4} more)" if len(changes) > 4 else ""))
    print(f"merged {total} tree updates into {LOCAL.relative_to(ROOT)}/")
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
