"""Assess-only replay of the objective patch gates against finished runs.

The `baseline` profile originally stopped at the patcher: an alert-only patch,
no regression gate and no verifier. That withheld more than the study's variable
— a `full` patch was judged by "survives the test suite and a reviewer" while a
`baseline` patch was judged by nothing — so both gates are now part of the
profile. This module brings the runs recorded *before* that change up to the same
standard, by re-running those gates against a finished run's existing patch.

**It never re-patches.** ``PatchCorrectionLoop`` sends a failing gate back to the
patcher, which is right for a live run and wrong here: these runs' fixPOV
and residual scores were computed against the diff on disk, so a correcting
patcher would leave every number already recorded for the run describing a patch
that no longer exists. The retrofit answers exactly one question — *would this
patch have cleared the gates?* — via :func:`stages.assess_predicates`, and leaves
the run's ``status``/``reason`` alone. A gate failure is recorded, not applied.

The tree that gets scored is reconstructed the way ``fixpov replay`` reconstructs
one (``buggy_commit_id`` + the run's ``patch_only.diff``), with the preserved
worktree as the fallback; ``_ReplayCheckout`` in ``cli.py`` documents why, and
the caller passes the prepared paths in. The pristine base of that same
reconstruction is handed over as ``baseline_checkout_path`` so the regression
gate's scaffold-vs-genuine triage has unpatched code to compare against — the
usual ``git archive HEAD`` route is unavailable because a reconstructed checkout
carries the patch in its working tree, not in a commit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .gates import GateError, validate_verifier_output
from .logging_io import ensure_dir, write_json
from .models import ExperimentConfig, JsonDict, PipelineState, ProjectMetadata, RunOptions
from .stages import (
    StageContext,
    StageError,
    VerifierStage,
    assess_predicates,
    build_base_context,
    regressions_pass_predicate,
)

# What a retrofit replays by default: the gates the current `baseline` profile
# runs but the recorded runs did not. The verifier needs no POV (it has an
# alert-only evidence mode) and runs the project's tests itself as part of its
# review, which is why `baseline` has no separate regression stage.
RETROFIT_GATES: Tuple[str, ...] = ("verifier",)

# Everything a retrofit *can* replay. `regression` is not a baseline stage and is
# not replayed by default, but it stays available via `--gates` for arms that do
# have it (`hardening`) and for runs already assessed with it.
AVAILABLE_GATES: Tuple[str, ...] = ("regression", "verifier")

# Where the retrofit's own artifact lands, a sibling of fix_pov/ and
# residual/ so a run's post-hoc evaluations all read the same way.
RESULTS_SUBDIR = "gates"


class RetrofitError(RuntimeError):
    """The run cannot be assessed at all (no patch, no recorded patcher output)."""


# --------------------------------------------------------------------------- #
# Reading what a finished run recorded
# --------------------------------------------------------------------------- #


def read_state(run_dir: Path) -> JsonDict:
    try:
        state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RetrofitError(f"cannot read state.json: {exc}") from exc
    if not isinstance(state, dict):
        raise RetrofitError("state.json is not an object")
    return state


def patcher_output_from_state(state: JsonDict) -> JsonDict:
    """The patch the run finished with.

    Takes the *last* patcher agent, so a run that self-corrected is assessed on
    the patch it ended up with rather than its first attempt. Correction agents
    are named ``patcher_correction[_<gate>]_a<N>`` and appear in order.
    """
    agents = state.get("agents")
    if not isinstance(agents, list):
        raise RetrofitError("state.json records no agents")
    patchers = [
        agent
        for agent in agents
        if isinstance(agent, dict)
        and str(agent.get("agent_name", "")).startswith("patcher")
        and isinstance(agent.get("parsed_output"), dict)
    ]
    if not patchers:
        raise RetrofitError("state.json records no patcher output to assess")
    return dict(patchers[-1]["parsed_output"])


def regression_commands_from(patcher_output: JsonDict) -> List[str]:
    commands = patcher_output.get("regression_commands")
    if not isinstance(commands, list):
        return []
    return [str(command) for command in commands if str(command).strip()]


# --------------------------------------------------------------------------- #
# The assessment itself
# --------------------------------------------------------------------------- #


def retrofit_run(
    *,
    run_dir: Path,
    project: ProjectMetadata,
    alert: JsonDict,
    finding_id: str,
    checkout_path: Path,
    baseline_checkout_path: Optional[Path],
    docker: Any,
    options: RunOptions,
    agent_runner: Any,
    gates: Sequence[str] = RETROFIT_GATES,
    profile: str = "baseline",
) -> JsonDict:
    """Replay ``gates`` against ``run_dir``'s existing patch. Returns a summary.

    ``checkout_path`` is the patched tree to assess and ``baseline_checkout_path``
    its pristine counterpart (None to let the regression gate export one itself,
    which only works when the tree is the run's own git worktree). Nothing is
    written to ``run_dir`` here — see :func:`record_retrofit`.
    """
    state = read_state(run_dir)
    patcher_output = patcher_output_from_state(state)

    # A scratch state object collects only what this assessment produces; it is
    # merged into the run's real state.json afterwards. Reusing the run's own
    # state would mean rewriting history rather than appending to it.
    scratch = PipelineState(
        run_id=run_dir.name,
        alert_path=run_dir,
        project=project,
        run_dir=run_dir,
        profile=profile,
        # 1 == no re-patching, belt to assess_predicates' braces: nothing in this
        # module reaches PatchCorrectionLoop, and if that ever changes the budget
        # still forbids a correction attempt.
        max_correction_attempts=1,
    )

    ctx = StageContext(
        options=options,
        experiment=ExperimentConfig(
            profile=profile, stages=tuple(gates), patcher_evidence="alert_only"
        ),
        agent_runner=agent_runner,
        alert=alert,
        project=project,
        finding_id=finding_id,
        run_dir=run_dir,
        worktree_path=checkout_path,
        state=scratch,
        persist=lambda: None,
        docker=docker,
        patcher_output=patcher_output,
        regression_commands=regression_commands_from(patcher_output),
        baseline_checkout_path=baseline_checkout_path,
    )
    ctx.base_context = build_base_context(
        alert, project, finding_id, run_dir, checkout_path, docker
    )

    results: Dict[str, JsonDict] = {}

    if "regression" in gates:
        results["regression"] = _assess_regression(ctx)

    if "verifier" in gates:
        # The verifier is shown whatever the regression gate just produced, the
        # same evidence a live run's verifier gets. When the regression gate was
        # not requested, ctx.regression_results is empty and the payload says so.
        results["verifier"] = _assess_verifier(ctx)

    passed = [name for name, outcome in results.items() if outcome["status"] == "passed"]
    failed = [name for name, outcome in results.items() if outcome["status"] == "failed"]
    errored = [name for name, outcome in results.items() if outcome["status"] == "errored"]

    return {
        "run_id": run_dir.name,
        "gates": results,
        "gates_passed": sorted(passed),
        "gates_failed": sorted(failed),
        "gates_errored": sorted(errored),
        # The headline: would this patch have survived the gates its profile now
        # runs? Only true when every requested gate was actually assessed and
        # passed — an errored gate is not a pass.
        "all_gates_passed": bool(results) and not failed and not errored,
        "steps": list(scratch.steps),
        "commands": list(scratch.commands),
        "agents": list(scratch.agents),
    }


def _assess_regression(ctx: StageContext) -> JsonDict:
    """Run the run's own regression commands once and classify the outcome.

    Failures are triaged against the pristine baseline exactly as in a live run
    (``regressions_pass_predicate``), so an injected PoV test or a pre-existing
    failure is still reported as scaffold rather than as this patch's fault.
    """
    try:
        failure = assess_predicates(ctx, [regressions_pass_predicate()])
    except StageError as exc:
        # e.g. the run recorded no regression commands and the project has no
        # default test command. Not the patch's fault, so not a gate failure.
        ctx.state.add_step("patch_and_regression", "errored", reason=exc.reason)
        return {"status": "errored", "detail": exc.reason, "commands": []}

    commands = list(ctx.regression_commands)
    if failure is None:
        ctx.state.add_step("patch_and_regression", "ok", regression_commands=commands)
        return {"status": "passed", "detail": "", "commands": commands}

    _, result = failure
    ctx.state.add_step(
        "patch_and_regression", "failed", regression_commands=commands, detail=result.summary
    )
    return {"status": "failed", "detail": result.summary, "commands": commands}


def _assess_verifier(ctx: StageContext) -> JsonDict:
    """Run the verifier agent once and record its verdict without enforcing it.

    ``VerifierStage`` raises on a rejection because in a live run that rejection
    *is* the verdict. Here it is a measurement, so the StageError is caught and
    reported. The stage is reused rather than reimplemented so the retrofit and a
    live run put the same prompt in front of the same agent.
    """
    try:
        VerifierStage().run(ctx)
    except StageError as exc:
        status = "failed" if exc.category == "agent_failure" else "errored"
        # An agent that crashed or was refused never rendered a verdict; only an
        # actual "rejected" is a gate failure. Distinguish them by whether the
        # agent produced parseable output at all.
        verdict = ""
        agents = ctx.state.agents
        if agents:
            parsed = agents[-1].get("parsed_output")
            if isinstance(parsed, dict):
                verdict = str(parsed.get("verdict", ""))
        if not verdict:
            status = "errored"
        ctx.state.add_step("verifier", "rejected" if status == "failed" else "errored",
                           reason=exc.reason)
        return {"status": status, "detail": exc.reason, "verdict": verdict or "unavailable"}

    output = ctx.verifier_output or {}
    ctx.state.add_step("verifier", "accepted")
    return {
        "status": "passed",
        "detail": str(output.get("summary", "")),
        "verdict": str(output.get("verdict", "accepted")),
    }


# --------------------------------------------------------------------------- #
# Writing the result back into the run
# --------------------------------------------------------------------------- #


def merge_stages(existing: Sequence[str], added: Sequence[str], profile: str) -> List[str]:
    """Union of a run's recorded stages and the ones just assessed, in order.

    The dashboard rail filters a canonical STAGE_ORDER by membership, so ordering
    here is for legibility rather than correctness — but a stage list that reads
    out of order invites the reader to believe the verifier ran before the
    patcher. When the profile is known, its declared order wins.
    """
    from .stages import PROFILES

    merged = list(existing)
    for stage in added:
        if stage not in merged:
            merged.append(stage)
    canonical = PROFILES.get(profile)
    if not canonical:
        return merged
    rank = {name: index for index, name in enumerate(canonical)}
    # Unknown stages (a --stages override) sort after the profile's own, keeping
    # their relative order instead of being dropped or interleaved arbitrarily.
    return sorted(merged, key=lambda name: (rank.get(name, len(rank)), merged.index(name)))


# What each gate owns in a run's artifacts, by name prefix. Only the gates being
# re-assessed have their previous entries dropped, so a retrofit that replays
# just the verifier keeps the regression commands an earlier one recorded — and
# so a `full` run's genuine verifier agent survives a regression-only retrofit.
_GATE_ARTIFACTS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "regression": {
        "commands": ("regression_",),
        "steps": ("patch_and_regression", "regression_triage"),
        "agents": (),
    },
    "verifier": {
        "commands": (),
        "steps": ("verifier",),
        "agents": ("verifier",),
    },
}


def record_retrofit(run_dir: Path, summary: JsonDict, gates: Sequence[str]) -> JsonDict:
    """Persist a retrofit into the run's artifacts. Returns the cumulative headline.

    Appends the assessment's steps/commands/agents to ``state.json`` and adds the
    replayed gates to the recorded stage list, so the dashboard rail shows them.
    ``status`` and ``reason`` are deliberately untouched in both ``state.json``
    and ``verdict.json``: this run's verdict was reached under the gates that
    existed when it ran, and a post-hoc measurement is not a re-judgement. The
    outcome lives in the ``retrofit_gates`` field instead.

    A retrofit may cover only *some* gates — a partial ``--gates``, or the
    automatic retry of a gate a previous attempt errored on. Everything here is
    therefore a merge over the previously recorded assessment rather than a
    replacement: replaying the verifier alone must not erase the regression
    result standing beside it.
    """
    gates = tuple(gates)
    results_path = ensure_dir(run_dir / RESULTS_SUBDIR) / "results.json"
    prior = _read_json(results_path)
    merged = _merge_summary(prior, summary, gates)
    write_json(results_path, merged)

    headline = {
        "gates": sorted(merged["gates"]),
        "gates_passed": merged["gates_passed"],
        "gates_failed": merged["gates_failed"],
        "gates_errored": merged["gates_errored"],
        "all_gates_passed": merged["all_gates_passed"],
        "evaluation_mode": merged.get("evaluation_mode", ""),
    }

    updated = False
    for path in (run_dir / "state.json", run_dir / "verdict.json"):
        document = _read_json(path)
        if document is None:
            continue
        profile = str(document.get("profile") or "baseline")
        if path.name == "state.json":
            # Withdraw exactly what the previous retrofit contributed and put the
            # cumulative set back. Identity rather than name prefix: the names
            # involved ("verifier", "regression_N") are not unique to this module,
            # and a prefix purge applied to a run that ran those gates itself
            # would delete the artifacts it is actually judged on.
            for key in ("commands", "steps", "agents"):
                document[key] = _replace_fragments(
                    _as_list(document.get(key)),
                    _as_list(prior.get(f"_{key}") if prior else None),
                    merged.get(f"_{key}") or [],
                )
            updated = True
        document["stages"] = merge_stages(document.get("stages") or [], gates, profile)
        document["retrofit_gates"] = headline
        write_json(path, document)

    headline["state_updated"] = updated
    return headline


def _as_list(entries: Any) -> List[JsonDict]:
    return list(entries) if isinstance(entries, list) else []


def _replace_fragments(
    existing: List[JsonDict], prior_entries: List[JsonDict], new_entries: Sequence[JsonDict]
) -> List[JsonDict]:
    """``existing`` with one occurrence of each prior entry removed, then extended."""
    remaining = list(existing)
    for entry in prior_entries:
        try:
            remaining.remove(entry)
        except ValueError:
            pass  # already gone (hand-edited state, or an interrupted write)
    return remaining + list(new_entries)


def _merge_summary(prior: Optional[JsonDict], summary: JsonDict, gates: Tuple[str, ...]) -> JsonDict:
    """This assessment layered over the previously recorded one.

    Per-gate detail and the artifacts each gate owns are replaced only for the
    gates just assessed; everything else carries forward. The pass/fail/error
    lists are then recomputed from the merged per-gate detail, so they always
    describe the whole picture rather than the last invocation.
    """
    prior = prior if isinstance(prior, dict) else {}
    prior_gates = prior.get("gates") if isinstance(prior.get("gates"), dict) else {}

    gate_detail: Dict[str, JsonDict] = dict(prior_gates)
    gate_detail.update(summary.get("gates") or {})

    merged: JsonDict = {
        "run_id": summary.get("run_id", prior.get("run_id", "")),
        "gates": gate_detail,
        "evaluation_mode": summary.get("evaluation_mode", prior.get("evaluation_mode", "")),
    }
    if summary.get("reconstruction_skipped"):
        merged["reconstruction_skipped"] = summary["reconstruction_skipped"]

    by_status = lambda status: sorted(  # noqa: E731
        name for name, outcome in gate_detail.items()
        if isinstance(outcome, dict) and outcome.get("status") == status
    )
    merged["gates_passed"] = by_status("passed")
    merged["gates_failed"] = by_status("failed")
    merged["gates_errored"] = by_status("errored")
    merged["all_gates_passed"] = bool(gate_detail) and not (
        merged["gates_failed"] or merged["gates_errored"]
    )

    # The state fragments, keyed with a leading underscore so they read as
    # internal to the merge rather than as part of the reported result.
    for key, entry_key in (("commands", "name"), ("steps", "name"), ("agents", "agent_name")):
        kept = _without_gates(prior.get(f"_{key}"), gates, key, entry_key)
        merged[f"_{key}"] = kept + list(summary.get(key) or [])
    return merged


def _owned_prefixes(gates: Sequence[str], key: str) -> Tuple[str, ...]:
    owned: List[str] = []
    for gate in gates:
        owned.extend(_GATE_ARTIFACTS.get(gate, {}).get(key, ()))
    return tuple(owned)


def _without_gates(
    entries: Any, gates: Sequence[str], key: str, entry_key: str
) -> List[JsonDict]:
    """``entries`` minus everything owned by ``gates``. Non-dict entries survive."""
    if not isinstance(entries, list):
        return []
    prefixes = _owned_prefixes(gates, key)
    if not prefixes:
        return list(entries)
    return [
        entry
        for entry in entries
        if not isinstance(entry, dict)
        or not any(str(entry.get(entry_key, "")).startswith(prefix) for prefix in prefixes)
    ]


def _read_json(path: Path) -> Optional[JsonDict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None
