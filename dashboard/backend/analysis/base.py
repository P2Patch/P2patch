"""Shared infra for analysis agents: disk-backed job status + a Claude runner."""
from __future__ import annotations

import json
import os
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import config  # noqa: F401 - side effect: puts REPO_ROOT on sys.path
from security_pipeline.claude_agents import parse_claude_stdout

_spawn_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def analysis_dir(run_dir: Path, agent: str) -> Path:
    d = run_dir / "analysis" / agent
    d.mkdir(parents=True, exist_ok=True)
    return d


def hardening_signals(detail: dict) -> Optional[dict]:
    """Objective account of an iterative-hardening run, for the eval judges.

    Returns ``None`` for non-hardening runs so their judge input stays
    byte-identical to before. When present, it reports how many *confirmed*
    bypass variants the exploiter found against the baseline patch and whether
    the FINAL patch blocks every one (and keeps the original POV blocked) — the
    empirical evidence the completeness / variant-coverage rubric dimensions
    need but the single ``pov_after_patch`` check cannot supply.

    Reads only the harden command records, so the flags reflect what actually
    executed in the container, not the loop's own step labels. "blocked" flags are
    sourced from the post-loop ``harden_final_replay_r*`` runs, so they certify the
    FINAL patch (not the intermediate per-round one). Flags are tri-state: ``true``
    verified blocked, ``false`` an observed exit-0 reproduction, ``null`` when the
    check is missing or timed out (inconclusive — never a proven hole).
    """
    summary = detail.get("hardening")
    # Require real loop evidence: a hardening-profile run rejected before the loop
    # still carries a summary (zero rounds), and must not fabricate a "we looped"
    # section for the judge.
    if not summary or not summary.get("rounds"):
        return None
    cmds = {c.get("name"): c for c in detail.get("commands", [])}

    def _blocked(name: str) -> Optional[bool]:
        """Tri-state: True non-timeout non-zero, False non-timeout exit 0, None else."""
        c = cmds.get(name)
        if not c or c.get("timed_out"):
            return None
        return c.get("exit_code") != 0

    def _reproduced(name: str) -> bool:
        """A variant counts as a bypass only on a definite non-timeout exit 0."""
        c = cmds.get(name)
        return bool(c) and not c.get("timed_out") and c.get("exit_code") == 0

    def _tri_all(flags: list) -> Optional[bool]:
        if not flags:
            return None
        if any(f is False for f in flags):
            return False  # at least one proven reproduction
        if any(f is None for f in flags):
            return None  # otherwise all-blocked, but with an inconclusive check
        return True

    variants = []
    for r in summary.get("rounds", []):
        n = r.get("round")
        # A round only yields a real variant when its probe reproduced on the
        # already-patched code; a "stable" round produced no such bypass.
        if _reproduced(f"harden_variant_before_r{n}"):
            variants.append(
                {
                    "round": n,
                    "reproduced_on_patched_code": True,
                    "blocked_by_final_patch": _blocked(f"harden_final_replay_r{n}"),
                }
            )

    # Original POV re-checked against the final patch = the last hardened round's
    # recheck (no later round alters the patch).
    last_round = max((v["round"] for v in variants), default=None)
    original_blocked = _blocked(f"harden_original_recheck_r{last_round}") if last_round else None
    return {
        "status": summary.get("status"),
        "max_rounds": summary.get("max_rounds"),
        "rounds_attempted": summary.get("rounds_attempted"),
        "variants_found": len(variants),
        "all_variants_blocked": _tri_all([v["blocked_by_final_patch"] for v in variants]),
        "original_still_blocked": original_blocked,
        "stopped_because_no_new_bypass": summary.get("status") == "stable",
        "variants": variants,
    }


def _read_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def get_status(run_dir: Path, agent: str) -> dict:
    status = _read_json(run_dir / "analysis" / agent / "status.json")
    if status is None:
        return {"state": "absent"}
    return status


def get_result(run_dir: Path, agent: str) -> Optional[dict]:
    return _read_json(run_dir / "analysis" / agent / "result.json")


def _set_status(run_dir: Path, agent: str, **fields) -> None:
    path = analysis_dir(run_dir, agent) / "status.json"
    current = _read_json(path) or {}
    current.update(fields)
    path.write_text(json.dumps(current, indent=2), encoding="utf-8")


def run_in_background(
    run_dir: Path,
    agent: str,
    fn: Callable[[], dict],
    *,
    force: bool = False,
) -> dict:
    """Start ``fn`` on a worker thread unless it's already running or cached.

    Returns the current status immediately. ``fn`` must return the JSON-able
    result payload; it is persisted to result.json and status flips to done.
    """
    with _spawn_lock:
        status = get_status(run_dir, agent)
        if status.get("state") == "running":
            return status
        if status.get("state") == "done" and not force and get_result(run_dir, agent) is not None:
            return status
        _set_status(run_dir, agent, state="running", started_at=_now(), finished_at=None, error=None)

    def worker() -> None:
        try:
            result = fn()
            (analysis_dir(run_dir, agent) / "result.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            _set_status(run_dir, agent, state="done", finished_at=_now())
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
            _set_status(run_dir, agent, state="error", finished_at=_now(), error=f"{type(exc).__name__}: {exc}")

    threading.Thread(target=worker, name=f"analysis-{agent}", daemon=True).start()
    return get_status(run_dir, agent)


def run_claude_json(
    *,
    agent_name: str,
    system_prompt: str,
    schema_json: str,
    input_md: str,
    run_dir: Path,
    out_dir: Path,
    claude_bin: str = "claude",
    effort: str = "high",
    model: Optional[str] = None,
    timeout: int = 1800,
) -> dict:
    """Invoke a headless Claude agent that returns JSON matching ``schema_json``.

    Mirrors how security_pipeline runs its agents, but read-only: no worktree or
    Docker. Raw stdout and the rendered input are written to ``out_dir``.
    """
    (out_dir / "input.md").write_text(input_md, encoding="utf-8")
    agents = {agent_name: {"description": f"P2Patch Lab {agent_name} analysis agent.", "prompt": system_prompt}}
    command = [
        claude_bin,
        "-p",
        "--agent",
        agent_name,
        "--agents",
        json.dumps(agents),
        "--permission-mode",
        "bypassPermissions",
        "--output-format",
        "json",
        "--json-schema",
        schema_json,
        "--add-dir",
        str(run_dir),
        "--setting-sources",
        "user",
    ]
    # Renamed from AUTOSEC_ANALYSIS_MODEL; the old name still works so an
    # already-configured host keeps its model choice after the rename.
    model = model or os.environ.get("P2PATCH_ANALYSIS_MODEL") or os.environ.get(
        "AUTOSEC_ANALYSIS_MODEL"
    )
    if model:
        command += ["--model", model]
    if effort:
        command += ["--effort", effort]
    command.append(input_md)

    completed = subprocess.run(
        command,
        cwd=str(run_dir),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    (out_dir / "raw_stdout.txt").write_text(completed.stdout or "", encoding="utf-8")
    if completed.stderr:
        (out_dir / "raw_stderr.txt").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"claude exited with code {completed.returncode}: {(completed.stderr or '')[:400]}")
    return parse_claude_stdout(completed.stdout)
