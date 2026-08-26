"""Patch Evaluation agent: score our patch against the official fix (LLM judge).

Layered: deterministic structural-overlap + execution signals feed a
reference-anchored LLM judge that scores 8 rubric dimensions with cited evidence.
The aggregate score is computed here (not by the model) so it stays principled.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import config
import runs
from . import base, diffutil, ensemble, reference_patch

AGENT = "patch_eval"
_HERE = Path(__file__).resolve().parent
DIM_LABELS = {
    "vulnerability_elimination": "Vulnerability elimination",
    "root_cause": "Root cause vs symptom",
    "completeness": "Completeness / variants",
    "developer_intent": "Developer-intent alignment",
    "functional_correctness": "Functional correctness",
    "no_new_defects": "No new defects",
    "minimality": "Minimality",
    "mitigation_soundness": "Mitigation soundness",
}


def _cap(text: str, limit: int = 24000) -> str:
    if text and len(text) > limit:
        return text[:limit] + f"\n… [truncated {len(text) - limit} chars]"
    return text or ""


def _exec_signals(detail: dict) -> dict:
    cmds = {c["name"]: c for c in detail.get("commands", [])}
    pov_before = cmds.get("pov_before_patch")
    pov_after = cmds.get("pov_after_patch")
    regs = [c for n, c in cmds.items() if n.startswith("regression")]
    return {
        "run_status": detail.get("status"),
        "pov_before_reproduced": bool(pov_before) and pov_before.get("exit_code") == 0,
        "pov_after_present": pov_after is not None,
        "pov_after_still_reproduces": bool(pov_after) and pov_after.get("exit_code") == 0,
        "regressions_ran": len(regs),
        "regressions_passed": all(c.get("exit_code") == 0 for c in regs) if regs else None,
    }


def _aggregate(dimensions: list, gates: dict) -> dict:
    scores = [d.get("score", 0) for d in dimensions if isinstance(d.get("score"), int)]
    mean = sum(scores) / len(scores) if scores else 0.0
    if mean >= 4.3:
        band = "good"
    elif mean >= 3.3:
        band = "acceptable"
    elif mean >= 2.3:
        band = "incomplete"
    else:
        band = "bad"
    gate_ok = gates.get("vulnerability_eliminated") and gates.get("no_regressions")
    if not gate_ok and band in ("good", "acceptable"):
        band = "incomplete"
    return {"mean": round(mean, 2), "score": round(mean / 5 * 100), "band": band, "gates_passed": bool(gate_ok)}


def _hardening_section(hardening: Optional[dict]) -> list:
    if not hardening:
        return []
    return [
        "## Iterative hardening (bypass variants found against OUR patch, then re-blocked)",
        "The pipeline looped exploiter↔patcher after the baseline patch: each round the "
        "exploiter searched for a NEW bypass of the current patch and, when it found one that "
        "reproduced on the patched code, the patcher strengthened the fix. `variants_found` "
        "confirmed bypasses beyond the original POV; `all_variants_blocked` = the FINAL patch "
        "(the diff below) blocks each. Weigh this for completeness (#3) and "
        "vulnerability_elimination (#1) — it is direct evidence about additional sinks/encodings.",
        "```json",
        json.dumps(hardening, indent=2),
        "```\n",
    ]


def _render_input(
    gt: dict, ref: dict, our_diff: str, detail: dict, overlap: dict, signals: dict,
    hardening: Optional[dict] = None,
) -> str:
    trace = detail.get("alert_trace") or {}
    parts = [
        "# Patch evaluation task\n",
        f"**CVE:** {gt.get('cve_id')}  **CWE:** {gt.get('cwe_id')} — {gt.get('cwe_name')}",
        f"**Project:** {gt.get('project_slug')}\n",
        "## Taint trace (source → sink)",
        "```json",
        _cap(json.dumps(trace, indent=2), 6000),
        "```\n",
        "## Execution results (from the pipeline)",
        "```json",
        json.dumps(signals, indent=2),
        "```\n",
        *_hardening_section(hardening),
        "## Structural overlap (our changed files vs official fix files)",
        "```json",
        json.dumps(overlap, indent=2),
        "```\n",
        "## OUR patch (patch_only.diff)",
        "```diff",
        _cap(our_diff),
        "```\n",
        "## OFFICIAL reference fix (production files only)",
        "```diff",
        _cap(ref.get("reference_diff", "") or "(no reference diff available)"),
        "```\n",
        "## Official fix localization (file / class / method / lines)",
        "```json",
        _cap(json.dumps(ref.get("localizations", []), indent=2), 6000),
        "```\n",
        "Score the 8 dimensions per the rubric and return ONLY the JSON.",
    ]
    return "\n".join(parts)


def _prepare(run_id: str, run_dir: Path, gt: dict):
    """Build the deterministic judge input once — shared across all samples."""
    detail = runs.get_run(run_id) or {}
    our_diff = runs.get_diff(run_id, "patch_only") or ""
    ref = reference_patch.get_or_build(run_id, run_dir, gt)
    overlap = diffutil.structural_overlap(our_diff, ref.get("production_files", []))
    signals = _exec_signals(detail)
    hardening = base.hardening_signals(detail)

    system_prompt = (_HERE / "prompts" / "patch_eval.md").read_text(encoding="utf-8")
    schema_json = (_HERE / "schemas" / "patch_eval.json").read_text(encoding="utf-8")
    input_md = _render_input(gt, ref, our_diff, detail, overlap, signals, hardening)
    extras = {
        "structural_overlap": overlap,
        "execution_signals": signals,
        "hardening_signals": hardening,
        "reference": {
            "production_files": ref.get("production_files", []),
            "commits": [c.get("sha") for c in ref.get("commits", [])],
        },
    }
    return system_prompt, schema_json, input_md, extras


def _sample(system_prompt: str, schema_json: str, input_md: str, run_dir: Path, out_dir: Path) -> dict:
    """One judge pass: parse, label dimensions, compute the deterministic overall."""
    parsed = base.run_claude_json(
        agent_name="patch_eval",
        system_prompt=system_prompt,
        schema_json=schema_json,
        input_md=input_md,
        run_dir=run_dir,
        out_dir=out_dir,
    )
    dims = parsed.get("dimensions", [])
    for d in dims:
        d["label"] = DIM_LABELS.get(d.get("key"), d.get("key"))
    parsed["overall"] = _aggregate(dims, parsed.get("gates", {}))
    return parsed


def evaluate(run_id: str, run_dir: Path, gt: dict, *, samples: int = 1) -> dict:
    system_prompt, schema_json, input_md, extras = _prepare(run_id, run_dir, gt)
    out_dir = base.analysis_dir(run_dir, AGENT)
    result = ensemble.run(
        out_dir=out_dir,
        samples=samples,
        dim_labels=DIM_LABELS,
        sample_fn=lambda d: _sample(system_prompt, schema_json, input_md, run_dir, d),
    )
    result.update(extras)
    return result


def start(run_id: str, run_dir: Path, gt: dict, *, samples: int = 1, force: bool = False) -> dict:
    return base.run_in_background(
        run_dir, AGENT, lambda: evaluate(run_id, run_dir, gt, samples=samples), force=force
    )
