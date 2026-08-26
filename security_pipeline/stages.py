"""Stage-based pipeline: each step of the exploit → patch → verify flow is a
discrete ``Stage`` over a shared ``StageContext``, and an ``ExperimentConfig``
selects which stages run in what order.

This is what lets an experiment drop or reorder agents without editing the
orchestrator. The full pipeline, the alert-only *baseline*, and the
*evaluated baseline* (exploiter runs to build the scorer but its output is
withheld from the patcher) are all just different stage lists + a
``patcher_evidence`` knob — see ``PROFILES`` below.

Stages declare ``requires``/``produces`` context tokens so a misconfigured
recipe is rejected up front (``resolve_experiment``) instead of dereferencing a
``None`` mid-run.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Type

from .claude_agents import ClaudeAgentRunner
from .docker_runner import POV_SANITIZER_ENV, DockerRunner
from .gates import (
    GateError,
    filter_duplicate_pov_commands,
    normalize_shell_command,
    validate_exploiter_output,
    validate_patcher_output,
    validate_verifier_output,
)
from .logging_io import ensure_dir, write_json, write_text
from .regression_diff import classify_regression_failure, parse_junit_reports
from .models import (
    AgentResult,
    CommandResult,
    ExperimentConfig,
    JsonDict,
    PipelineState,
    ProjectMetadata,
    RunOptions,
)
from .workspace import (
    SourceSnapshot,
    TreeSnapshot,
    WorkspaceError,
    collect_git_diff,
    collect_patch_only_diff,
    hash_path_tree,
    restore_path_tree,
    restore_worktree_sources,
    run_local_command,
    snapshot_path_tree,
    snapshot_worktree_sources,
)


class StageError(RuntimeError):
    """Raised by a stage to reject the run. ``category`` mirrors the failure
    classes used in verdict.json (infra_build_error | api_refusal |
    agent_failure | pipeline)."""

    def __init__(self, reason: str, category: str = "pipeline") -> None:
        super().__init__(reason)
        self.reason = reason
        self.category = category


class ExperimentConfigError(ValueError):
    """A profile/stage list that cannot be run as configured."""


# --------------------------------------------------------------------------- #
# Rendering + shared helpers (moved here from pipeline so stages own them and
# there is no import cycle back to the orchestrator).
# --------------------------------------------------------------------------- #

POV_ROOT_PARTS = (".security-pipeline", "pov")


def json_block(data: Any) -> str:
    return "```json\n" + json.dumps(data, indent=2, sort_keys=True) + "\n```"


def redact_alert_for_agent(alert: JsonDict) -> JsonDict:
    return {key: value for key, value in alert.items() if key != "cve_id"}


def build_base_context(
    alert: JsonDict,
    project: ProjectMetadata,
    finding_id: str,
    run_dir: Path,
    worktree_path: Path,
    docker: Optional[DockerRunner],
) -> JsonDict:
    return {
        "finding_id": finding_id,
        "alert": redact_alert_for_agent(alert),
        "project": project.to_agent_json_dict(finding_id),
        "run_dir": str(run_dir),
        "worktree_path": str(worktree_path),
        "pov_root": str(worktree_path.joinpath(*POV_ROOT_PARTS)),
        "default_build_command": project.build_command,
        "default_test_command": project.test_command,
        "docker": {
            "image_tag": docker.image_tag if docker else "",
            "wrapper_path": "",
            "command_contract": (
                "Agent output commands must be shell commands for /workspace/repo inside the project container. "
                "Do not return a host-level docker run command."
            ),
        },
    }


# --------------------------------------------------------------------------- #
# Prompt payload budgets.
#
# A task input is re-sent on every turn, and an agent takes ~35 of them, so a fat
# payload is paid for over and over. Measured over the first 30 runs: the median
# input.md was 51 KB and the worst 117 KB, of which 70 KB was one patch diff and
# 46 KB (elsewhere) was the raw log of a failing `mvn test`. Neither is read in
# full by anyone. The alert itself is deliberately NOT clipped — it defines the
# scope of a complete fix, and truncating it would change the task.
# --------------------------------------------------------------------------- #

# Per stream (stdout / stderr) of one command result embedded in a prompt.
PROMPT_LOG_HEAD_CHARS = 1500
PROMPT_LOG_TAIL_CHARS = 6000
# A patch diff echoed back to the patcher. It already knows what it wrote, and
# the worktree is right there if it needs the exact text.
PROMPT_DIFF_CHARS = 30000


def clip_text(text: str, head: int, tail: int, label: str = "output") -> str:
    """Keep the head and tail of a long log, with the elision made explicit.

    Tail-heavy on purpose: a Maven/Gradle failure summary lands at the end, while
    the head is enough to identify which command produced it.
    """
    if not text or len(text) <= head + tail:
        return text
    dropped = len(text) - head - tail
    return (
        f"{text[:head]}\n"
        f"\n... [{dropped} characters of {label} elided by the orchestrator; "
        f"head and tail kept] ...\n\n"
        f"{text[-tail:]}"
    )


def command_evidence(result: CommandResult) -> JsonDict:
    """A CommandResult for embedding in a prompt, with its logs clipped."""
    payload = result.to_json_dict()
    for stream in ("stdout", "stderr"):
        value = payload.get(stream)
        if isinstance(value, str):
            payload[stream] = clip_text(
                value, PROMPT_LOG_HEAD_CHARS, PROMPT_LOG_TAIL_CHARS, f"{stream}"
            )
    return payload


def clip_diff(diff: str) -> str:
    return clip_text(diff, PROMPT_DIFF_CHARS // 3, PROMPT_DIFF_CHARS * 2 // 3, "diff")


def write_diffs(run_dir: Path, worktree_path: Path) -> None:
    git_dir = ensure_dir(run_dir / "git")
    write_text(git_dir / "full.diff", collect_git_diff(worktree_path))
    write_text(git_dir / "patch_only.diff", collect_patch_only_diff(worktree_path))
    write_text(
        git_dir / "pov.diff",
        collect_git_diff(worktree_path, include_prefixes=("/".join(POV_ROOT_PARTS),)),
    )


def render_exploiter_input(context: JsonDict) -> str:
    return (
        "# Exploiter Task\n\n"
        "Create a real proof-of-vulnerability test for the finder alert. "
        "Use the project worktree and Docker wrapper described below.\n\n"
        f"{json_block(context)}\n\n"
        "Return only JSON matching the exploiter schema."
    )


def render_patcher_input(
    context: JsonDict,
    exploiter_output: Optional[JsonDict],
    pov_before: Optional[CommandResult],
) -> str:
    """Compose the patcher input from whatever evidence the experiment allows.

    When ``exploiter_output`` is provided (patcher_evidence == "full") the
    validated POV is embedded and the patcher is told to use it. When it is
    ``None`` (alert-only baseline) only the alert-bearing context is sent and the
    patcher is told no POV exists. The patcher *system prompt* is identical in
    both arms — only this task input differs — so wording is not a confound.
    """
    payload: JsonDict = {"context": context}
    has_evidence = exploiter_output is not None
    if has_evidence:
        payload["exploiter_output"] = exploiter_output
        if pov_before is not None:
            payload["pov_before_patch"] = command_evidence(pov_before)
        intro = (
            "A validated proof-of-vulnerability (POV) is included below. It proves ONE reachable "
            "path to the sink and is a regression witness — NOT the specification of what to fix. "
            "The finder alert defines the scope: fix the root cause at the sink or trust boundary so "
            "that EVERY source-to-sink path in the alert is blocked, not only the single path the POV "
            "exercises. Re-run the POV command as often as you need to check your fix, but do "
            "not edit files under .security-pipeline/pov."
        )
    else:
        intro = (
            "Only the finder alert is provided; no exploit evidence or POV is available. "
            "Reason about the vulnerability from the alert alone and patch it."
        )
    return (
        "# Patcher Task\n\n"
        f"{intro}\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the patcher schema."
    )


def render_exploiter_retry_input(
    context: JsonDict,
    previous_output: JsonDict,
    check_label: str,
    detail: str,
    evidence: List[CommandResult],
    attempt_num: int,
) -> str:
    """Ask the exploiter to fix its own POV after the orchestrator rejected it.

    Same exploiter system prompt as the first pass — only this task input differs.
    The objective failure (POV did not reproduce, or the output failed a gate) is
    fed back verbatim so the exploiter fixes the real problem instead of guessing.
    """
    payload: JsonDict = {
        "context": context,
        "your_previous_attempt": previous_output,
        "failing_check": {
            "check": check_label,
            "detail": detail,
            "evidence": [command_evidence(result) for result in evidence],
        },
    }
    return (
        f"# Exploiter Task — fix your POV (attempt {attempt_num})\n\n"
        "Your previous proof-of-vulnerability was REJECTED by an objective check "
        "(below). The code is still unpatched, so a correct POV must exit 0 here. "
        "Diagnose why it failed — wrong entry point, unreachable payload, build or "
        "harness error, wrong exit-code convention — and produce a POV that really "
        "reproduces the vulnerability from the finder alert. For Java projects, drive "
        "the real product class/request flow and prove an observed security effect; "
        "do not stop at library/string behavior unless that is the alerted public API's "
        "security contract. For C/C++ parser or memory-safety findings, feed malformed "
        "external input through a CLI/exported API/parser path; do not fabricate internal "
        "structs, call private helpers, or treat any non-zero exit as reproduction — check "
        "for the specific signal or sanitizer output, and never redirect the crash output "
        "to /dev/null. If your harness is a compiled binary, `pov_command` must (re)build "
        "it from source every run, not just execute one built once — for a statically "
        "linked project that binary is frozen against whatever the product code was at "
        "compile time and will 'still reproduce' no matter what the patcher fixes. "
        "Replace or repair the files under `.security-pipeline/pov`; do not leave a broken POV behind. If "
        "after investigating you conclude the alert is not exploitable, return "
        "`status: \"no_pov\"` with an explanation rather than a contrived POV.\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the exploiter schema."
    )


def render_variant_exploiter_input(
    context: JsonDict,
    original_exploiter_output: JsonDict,
    patch_diff: str,
    round_num: int,
) -> str:
    """Ask the exploiter to find a *new* bypass of the already-applied patch.

    Same exploiter system prompt as the first pass — only this task input differs
    — so it reuses the schema. When the patch already blocks everything the
    exploiter can construct, it returns ``status: "no_pov"`` and the loop stops.
    """
    payload = {
        "context": context,
        "original_pov": original_exploiter_output,
        "current_patch_diff": clip_diff(patch_diff),
    }
    return (
        f"# Exploiter Task — bypass hunt (hardening round {round_num})\n\n"
        "The vulnerability you originally proved has since been PATCHED (current patch diff below). "
        "Find a DIFFERENT way to still trigger the same vulnerable behavior on the patched code: an "
        "alternate encoding, parameter, payload, or sibling source-to-sink path the patch fails to "
        "cover.\n\n"
        "- Create the variant as a NEW proof-of-vulnerability file under `.security-pipeline/pov/`; "
        "do not overwrite or modify the existing POV.\n"
        "- `pov_command` must exit 0 when the variant reproduces on the CURRENT patched code and "
        "non-zero once a correct fix blocks it.\n"
        "- The variant must remain faithful to the original vulnerability: Java variants must drive "
        "a real product flow and prove a runtime security effect; C/C++ memory-safety variants must "
        "use malformed external input through a CLI/exported API/parser path, not hand-built corrupt "
        "internal structs.\n"
        "- If the variant's oracle is a crash, distinguish the vulnerability crash from harness/build/"
        "usage failures by its specific signal or sanitizer output; do not make a wrapper that maps "
        "every non-zero exit to success, and do not redirect the crash output to /dev/null.\n"
        "- If the patch already blocks every variant you can construct, return `status: \"no_pov\"` "
        "with an explanation. Do not invent a contrived or unreachable payload just to produce one.\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the exploiter schema."
    )


def render_hardening_patcher_input(
    context: JsonDict,
    current_patcher_output: JsonDict,
    variant_exploiter_output: JsonDict,
    variant_before: CommandResult,
    patch_diff: str,
    round_num: int,
) -> str:
    """Ask the patcher to strengthen its existing fix so a new bypass variant is
    also blocked, without weakening the protection already in place."""
    payload = {
        "context": context,
        "your_current_patch": current_patcher_output,
        "current_patch_diff": clip_diff(patch_diff),
        "bypass_variant": variant_exploiter_output,
        "bypass_reproduction": command_evidence(variant_before),
    }
    return (
        f"# Patcher Task — strengthen the fix (hardening round {round_num})\n\n"
        "Your earlier patch is applied in the worktree, but the exploiter found a NEW "
        "proof-of-vulnerability that still bypasses it (below, confirmed to reproduce on the current "
        "code). Strengthen the fix at the root cause so this variant AND the original path are both "
        "blocked. Do not weaken or revert the protection already in place, and do not edit files "
        "under `.security-pipeline/pov`.\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the patcher schema."
    )


def render_correction_patcher_input(
    context: JsonDict,
    current_patcher_output: JsonDict,
    check_label: str,
    detail: str,
    evidence: List[CommandResult],
    attempt_num: int,
) -> str:
    """Ask the patcher to fix its own patch after an objective check failed.

    Same patcher system prompt as the first pass — only this task input differs.
    The failing check (POV still reproduces, or a regression test broke) is fed
    back verbatim so the patcher fixes the real problem instead of guessing.
    """
    payload = {
        "context": context,
        "your_current_patch": current_patcher_output,
        "failing_check": {
            "check": check_label,
            "detail": detail,
            "evidence": [command_evidence(result) for result in evidence],
        },
    }
    return (
        f"# Patcher Task — fix your patch (correction attempt {attempt_num})\n\n"
        "Your patch is applied in the worktree, but an OBJECTIVE check still fails "
        "(below). Fix the patch so this check passes. Do NOT re-open the "
        "vulnerability or weaken any protection already in place, do NOT remove "
        "regression tests you previously declared, and do NOT edit files under "
        "`.security-pipeline/pov`.\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the patcher schema."
    )


def render_verifier_input(
    context: JsonDict,
    exploiter_output: Optional[JsonDict],
    patcher_output: JsonDict,
    pov_before: Optional[CommandResult],
    pov_after: Optional[CommandResult],
    regression_results: List[CommandResult],
) -> str:
    """Task input for the verifier, in one of two evidence modes.

    With a POV (`full`, `baseline_eval`, `hardening`) the verifier holds an
    objective witness: it can rerun the exploit and confirm it no longer
    reproduces. The alert-only `baseline` has no exploiter and therefore no POV,
    so the same agent is asked a deliberately weaker question — is this diff a
    plausible, minimal fix for the alert, and do the tests still pass — and the
    payload says so via ``evidence_mode``.

    The POV keys are *omitted* rather than sent as nulls, and the pov diff path
    with them. A verifier handed a POV-shaped hole reads the absent evidence as
    evidence: it reports "the POV still reproduces / could not be confirmed
    blocked" and rejects a patch it was never given the means to check.
    """
    git_dir = Path(context["run_dir"]) / "git"
    orchestrator_results: JsonDict = {
        "regressions": [command_evidence(result) for result in regression_results],
    }
    if pov_before is not None:
        orchestrator_results["pov_before_patch"] = command_evidence(pov_before)
    if pov_after is not None:
        orchestrator_results["pov_after_patch"] = command_evidence(pov_after)
    has_pov = bool(orchestrator_results.keys() - {"regressions"})

    diff_paths = {
        "full_diff": str(git_dir / "full.diff"),
        "patch_only_diff": str(git_dir / "patch_only.diff"),
    }
    if has_pov:
        diff_paths["pov_diff"] = str(git_dir / "pov.diff")

    payload = {
        "context": context,
        "evidence_mode": "pov" if has_pov else "alert_only",
        "exploiter_output": exploiter_output,
        "patcher_output": patcher_output,
        "diff_paths": diff_paths,
        "orchestrator_results": orchestrator_results,
    }
    if has_pov:
        instructions = (
            "Review the patch and logs. Rerun the POV and regression commands if needed using "
            "the Docker wrapper. Accept only when the diff is appropriate, the POV no longer "
            "reproduces, and regressions pass."
        )
    else:
        instructions = (
            "This run is the alert-only baseline: **no exploiter ran, so there is no POV** and "
            "no POV logs exist. Their absence is the experiment design, not a missing result — "
            "do not treat it as a failed or unconfirmed exploit check, and do not reject on that "
            "basis. Report \"no POV (alert-only baseline)\" in `pov_result`.\n\n"
            "**No regression gate ran either, so checking the patch did not break the project "
            "is your job.** Run the project's tests yourself in the container — "
            "`patcher_output.regression_commands` are the commands the patcher declared, and "
            "`context.default_test_command` / `context.default_build_command` are the project's "
            "defaults — and report what you ran and what happened in `regression_result`. Do not "
            "run `clean`: build output carries over between commands and re-building from scratch "
            "costs minutes.\n\n"
            "Then judge the diff against the alert: accept when it is an appropriate, minimal fix "
            "for the reported vulnerability and the project still builds and tests."
        )
    return (
        "# Verifier Task\n\n"
        f"{instructions}\n\n"
        f"{json_block(payload)}\n\n"
        "Return only JSON matching the verifier schema."
    )


def agent_stage_error(agent: AgentResult) -> StageError:
    """Turn an unsuccessful agent run into a StageError, distinguishing an
    Anthropic cyber-safety refusal from a genuine crash/parse failure."""
    if agent.refused:
        return StageError(
            f"{agent.agent_name} blocked by Anthropic cyber-safety policy: {agent.refusal_reason}",
            category="api_refusal",
        )
    return StageError(f"{agent.agent_name} failed: {agent.parse_error}", category="agent_failure")


# --------------------------------------------------------------------------- #
# Shared mutable context threaded through every stage.
# --------------------------------------------------------------------------- #


@dataclass
class StageContext:
    options: RunOptions
    experiment: ExperimentConfig
    agent_runner: ClaudeAgentRunner
    alert: JsonDict
    project: ProjectMetadata
    finding_id: str
    run_dir: Path
    worktree_path: Path
    state: PipelineState
    # Persist state.json; wired by the runner so stages can checkpoint progress
    # for the live monitor without a back-reference to the pipeline.
    persist: Callable[[], None]
    base_context: Optional[JsonDict] = None
    docker: Optional[DockerRunner] = None
    # Produced artifacts — each stage fills the fields it owns.
    exploiter_output: Optional[JsonDict] = None
    pov_command: Optional[str] = None
    # Every POV command the patcher must never smuggle in as a "regression test"
    # (the original POV plus any confirmed hardening bypass variant).
    protected_pov_commands: List[str] = field(default_factory=list)
    pov_before: Optional[CommandResult] = None
    # POV integrity guard state, re-baselined immediately before every patcher
    # invocation (see ``baseline_pov``) so it measures one patcher run, nothing else.
    pov_hash_before: Optional[str] = None
    pov_snapshot: Optional[TreeSnapshot] = None
    # Product-source guard state, re-baselined immediately before every exploiter
    # invocation (see ``baseline_sources``). The mirror image of the POV guard:
    # the patcher may not touch the POV, and the exploiter may not touch the
    # product code it is supposed to be attacking.
    source_snapshot: Optional[SourceSnapshot] = None
    # Build-output paths probed once from the project image; see build_outputs().
    _build_outputs: Optional[List[str]] = None
    # Pristine pre-patch checkout, materialized on demand by the regression gate
    # so a failing test command can be replayed against unpatched code.
    baseline_checkout_path: Optional[Path] = None
    pov_after: Optional[CommandResult] = None
    patcher_output: Optional[JsonDict] = None
    regression_commands: List[str] = field(default_factory=list)
    regression_results: List[CommandResult] = field(default_factory=list)
    verifier_output: Optional[JsonDict] = None
    # fixPOV evaluation summary (non-gating metric). None until the
    # fix_pov_eval stage runs; stays None when no manifest exists.
    fix_pov_results: Optional[JsonDict] = None
    # Residual-gap POV summary (non-gating bonus metric: did the patch close a
    # hole the *official* fix leaves open). None until residual_eval runs.
    residual_results: Optional[JsonDict] = None

    def pov_root(self) -> Path:
        return self.worktree_path.joinpath(*POV_ROOT_PARTS)

    def baseline_pov(self) -> None:
        """Re-baseline the POV integrity guard against the tree as it stands now.

        Must be called immediately before every patcher invocation. The guard's
        invariant is "the POV is byte-identical across a patcher run", so the
        baseline has to be taken per-run: a single run-wide baseline made every
        legitimate POV the exploiter added later (a hardening bypass variant)
        look like the *next* patcher's tampering, one stage after the fact.
        """
        self.pov_snapshot = snapshot_path_tree(self.pov_root())
        self.pov_hash_before = hash_path_tree(self.pov_root())

    def enforce_pov_integrity(self, agent_label: str) -> List[str]:
        """Undo anything the patcher just did to the POV sources; record it.

        Restoring beats rejecting. The POV is text we hold a snapshot of, so the
        invariant is fully recoverable, and a patcher that neutered its witness
        simply meets the original POV at the next gate and gets sent back with a
        real failure — instead of the whole run (possibly several hardening
        rounds deep) being thrown away. Build output is excluded from the
        comparison, because re-running the POV to self-verify is expected.
        """
        if self.pov_command is None or self.pov_snapshot is None:
            return []  # alert-only arm: no POV to protect
        changed = self._restore_guarded(
            lambda: restore_path_tree(self.pov_root(), self.pov_snapshot), agent_label
        )
        if changed:
            self.state.add_step(
                "pov_guard",
                "restored",
                agent=agent_label,
                paths=changed[:20],
                count=len(changed),
            )
        return changed

    def build_outputs(self) -> Sequence[str]:
        """Paths the project's own build produces, cached for the run.

        Probed from the built image rather than from the worktree, because the
        worktree never has a build-only state to compare against: the first
        thing that touches it is an agent, which edits *and* builds. Best
        effort — the empty set restores the pre-existing behaviour.
        """
        if self._build_outputs is None:
            try:
                self._build_outputs = sorted(self.docker.image_build_outputs())
            except Exception:  # noqa: BLE001 - a guard hint, never worth a run
                self._build_outputs = []
        return self._build_outputs

    def _restore_guarded(self, restore, agent_label: str):
        """Run a guard's restore, reclaiming container-root ownership if it EPERMs.

        Every project container runs as root, so anything a container created in
        the bind-mounted worktree lands root-owned on the host while the pipeline
        itself runs unprivileged. ``reclaim_ownership`` fixes that, but it only
        ran once, in the pipeline's closing ``finally`` — so a *mid-run* guard
        that had to delete a path a container had just created (a hardening
        round's ``pov/work_bypass/`` output) hit PermissionError and crashed the
        whole run. Reclaiming lazily, only when a restore actually EPERMs, keeps
        the common path free of an extra container per guard call.
        """
        try:
            return restore()
        except PermissionError:
            self.state.add_step("ownership_reclaim", "retry", agent=agent_label)
            with contextlib.suppress(Exception):
                self.docker.reclaim_ownership()
            return restore()

    def baseline_sources(self) -> None:
        """Re-baseline the product-source guard against the tree as it stands.

        Called immediately before every exploiter invocation, for the same reason
        ``baseline_pov`` is per-patcher-run: in a hardening round the tree already
        carries the patch, and the invariant being enforced is "this one exploiter
        run changed no product code", not "the tree matches the original source".
        """
        try:
            self.source_snapshot = snapshot_worktree_sources(
                self.worktree_path, build_outputs=self.build_outputs()
            )
        except WorkspaceError as exc:
            # The guard reads the worktree's git index, which every real run has
            # (``create_worktree`` initializes one). Rather than fail a run over a
            # tree that somehow has none, disable the guard and say so, so the gap
            # is visible in state.json instead of silently assumed closed.
            self.source_snapshot = None
            self.state.add_step("source_guard", "unavailable", reason=str(exc))

    def enforce_source_integrity(self, agent_label: str) -> List[str]:
        """Undo anything the exploiter just did outside its own POV tree.

        The exploiter is instructed not to patch product code or normal tests. It
        is not the agent being measured for a fix, so an edit it leaves behind is
        never wanted: in a hardening round it would ride along in the final diff
        the verifier and the offline judges score, and the "no new bypass found"
        exit would call that patch stable without ever inspecting it. Restores
        rather than rejects, matching the POV guard.
        """
        if self.source_snapshot is None:
            return []
        try:
            changed = self._restore_guarded(
                lambda: restore_worktree_sources(
                    self.worktree_path,
                    self.source_snapshot,
                    build_outputs=self.build_outputs(),
                ),
                agent_label,
            )
        except WorkspaceError as exc:
            self.state.add_step("source_guard", "unavailable", agent=agent_label, reason=str(exc))
            return []
        if changed:
            self.state.add_step(
                "source_guard",
                "restored",
                agent=agent_label,
                paths=changed[:20],
                count=len(changed),
            )
        return changed

    def patcher_retry_reset(self) -> Optional[Callable[[], None]]:
        """Snapshot the product tree now; return a callable that reverts to it.

        Passed as ``on_retry_reset`` to every patcher invocation. A transient API
        failure (content-filter false positive, dropped connection) can leave the
        worktree with a half-applied patch — the dolphinscheduler content-filter
        block landed after two file edits had already been written. Before the
        agent runner re-rolls the same pinned model it calls this to roll those
        partial edits back, so the retry starts from the same tree the blocked
        attempt saw and its Edits' ``old_string``s still match. Reuses the source
        guard's snapshot/restore (product tree only; the POV under
        ``.security-pipeline/`` is left to the POV guard). Returns None when no
        snapshot is possible — the retry then just re-rolls without a reset.
        """
        try:
            snapshot = snapshot_worktree_sources(self.worktree_path)
        except WorkspaceError:
            return None

        def _reset() -> None:
            try:
                restore_worktree_sources(self.worktree_path, snapshot)
            except WorkspaceError:
                pass

        return _reset


@dataclass
class PredicateResult:
    """Outcome of checking one invariant against the currently-applied patch."""

    passed: bool
    # Human/agent-readable explanation, fed back to the patcher when it fails.
    summary: str
    # Docker runs performed by the check, recorded on the run for observability.
    commands: List[CommandResult] = field(default_factory=list)


@dataclass
class Predicate:
    """An invariant a valid patch must satisfy (POV blocked, tests pass, ...).

    ``check`` runs it against the live worktree and returns a PredicateResult.
    A recoverable failure returns ``passed=False``; a deterministic problem that
    retrying cannot fix (e.g. no test command configured) raises ``StageError``.
    """

    label: str
    check: Callable[["StageContext"], PredicateResult]


# --------------------------------------------------------------------------- #
# Stages
# --------------------------------------------------------------------------- #


class Stage:
    """One pipeline step. ``requires``/``produces`` are context tokens used to
    validate a recipe before it runs; ``run`` raises ``StageError`` to reject."""

    name: str = ""
    requires: Tuple[str, ...] = ()
    produces: Tuple[str, ...] = ()

    def run(self, ctx: StageContext) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class WorktreeStage(Stage):
    """Materialize the isolated build environment and its agent-facing description.

    Beyond exporting the source into a fresh git worktree, this constructs the
    (deterministic, build-independent) Docker image tag + wrapper and the
    ``base_context`` every agent stage reads, then writes context.json. It is a
    prerequisite of every real profile.
    """

    name = "worktree"
    produces = ("worktree",)

    def run(self, ctx: StageContext) -> None:
        from .workspace import create_worktree  # local import: heavy git work

        try:
            worktree_path = create_worktree(ctx.project.source_path, ctx.run_dir)
        except Exception as exc:  # noqa: BLE001 - surfaced as an infra failure
            raise StageError(f"worktree setup failed: {exc}", category="infra_build_error")
        ctx.worktree_path = worktree_path
        ctx.state.worktree_path = worktree_path
        ctx.state.add_step("worktree", "ok", path=worktree_path)

        docker = DockerRunner(ctx.project, worktree_path, ctx.run_dir, image_key=ctx.finding_id)
        wrapper_path = docker.write_wrapper()
        base_context = build_base_context(
            ctx.alert, ctx.project, ctx.finding_id, ctx.run_dir, worktree_path, docker
        )
        base_context["docker"]["wrapper_path"] = str(wrapper_path)
        write_json(ctx.run_dir / "context.json", base_context)
        ctx.docker = docker
        ctx.base_context = base_context
        ctx.persist()


class DockerBuildStage(Stage):
    name = "docker_build"
    requires = ("worktree",)
    produces = ("docker_image",)

    def run(self, ctx: StageContext) -> None:
        docker = ctx.docker
        assert docker is not None
        if ctx.options.skip_docker_build:
            ctx.state.add_step("docker_build", "skipped", image=docker.image_tag)
            ctx.persist()
            return
        result = docker.build_image(ctx.options.command_timeout_seconds)
        ctx.state.add_command(result)
        if not result.ok:
            raise StageError("Docker builder image failed to build", category="infra_build_error")
        ctx.state.add_step("docker_build", "ok", image=docker.image_tag)
        ctx.persist()


class ExploiterStage(Stage):
    """Build a POV that really reproduces the vulnerability — with retries.

    The POV-before check is objective: on unpatched code the POV command must
    exit 0. When it doesn't (or the output fails a gate), the failure is fed back
    to the exploiter and it tries again, up to
    ``options.max_exploit_attempts``. With a budget of 1 this is exactly the old
    one-shot gate. A crashed/refused agent is NOT retried — that is an infra or
    policy failure, not something the exploiter can fix by trying harder.
    """

    name = "exploiter"
    requires = ("worktree", "docker_image")
    produces = ("exploiter_output", "pov_command", "pov_before", "pov_hash_before")

    def run(self, ctx: StageContext) -> None:
        budget = max(1, ctx.options.max_exploit_attempts)
        feedback: Optional[Tuple[JsonDict, str, str, List[CommandResult]]] = None

        for attempt in range(1, budget + 1):
            run_label = "exploiter" if attempt == 1 else f"exploiter_retry_a{attempt}"
            task = (
                render_exploiter_input(ctx.base_context)
                if feedback is None
                else render_exploiter_retry_input(ctx.base_context, *feedback, attempt)
            )
            ctx.baseline_sources()
            exploiter = ctx.agent_runner.run(
                "exploiter", task, ctx.run_dir, ctx.worktree_path, run_label=run_label
            )
            ctx.state.add_agent(exploiter)
            ctx.enforce_source_integrity(run_label)
            if not exploiter.ok:
                raise agent_stage_error(exploiter)

            failure: Optional[Tuple[str, str, List[CommandResult]]] = None
            try:
                pov = validate_exploiter_output(exploiter.parsed_output, ctx.worktree_path)
            except GateError as exc:
                failure = ("pov_output_invalid", str(exc), [])
            else:
                # Retried runs get their own command name so each attempt keeps its
                # own docker log instead of overwriting the previous attempt's.
                command_name = (
                    "pov_before_patch" if attempt == 1 else f"pov_before_patch_a{attempt}"
                )
                pov_before = ctx.docker.run_project_command(
                    pov["pov_command"], command_name, ctx.options.command_timeout_seconds,
                    env_overrides=POV_SANITIZER_ENV,
                )
                ctx.state.add_command(pov_before)
                if pov_before.ok:
                    ctx.baseline_pov()
                    write_diffs(ctx.run_dir, ctx.worktree_path)
                    ctx.exploiter_output = exploiter.parsed_output
                    ctx.pov_command = pov["pov_command"]
                    ctx.protected_pov_commands = [pov["pov_command"]]
                    ctx.pov_before = pov_before
                    ctx.state.add_step(
                        "pov_before_patch", "ok", command=pov["pov_command"], attempt=attempt
                    )
                    ctx.persist()
                    return
                detail = (
                    "POV command timed out on the unpatched code (inconclusive)."
                    if pov_before.timed_out
                    else (
                        f"POV command exited {pov_before.exit_code} on the unpatched code; "
                        "it must exit 0 while the vulnerability is present."
                    )
                )
                failure = ("pov_did_not_reproduce", detail, [pov_before])

            label, detail, evidence = failure
            if attempt == budget:
                raise StageError(
                    f"exploiter did not produce a reproducing POV within {budget} "
                    f"attempt(s): {detail}",
                    category="agent_failure",
                )
            ctx.state.add_step(
                "exploit_retry", "retry", attempt=attempt, failing=label, detail=detail
            )
            ctx.persist()
            feedback = (exploiter.parsed_output, label, detail, evidence)


class PatcherStage(Stage):
    name = "patcher"
    requires = ("worktree", "docker_image")
    produces = ("patcher_output", "regression_commands")

    def run(self, ctx: StageContext) -> None:
        show_evidence = ctx.experiment.patcher_evidence == "full"
        exploiter_output = ctx.exploiter_output if show_evidence else None
        pov_before = ctx.pov_before if show_evidence else None

        ctx.baseline_pov()
        patcher = ctx.agent_runner.run(
            "patcher",
            render_patcher_input(ctx.base_context, exploiter_output, pov_before),
            ctx.run_dir,
            ctx.worktree_path,
            on_retry_reset=ctx.patcher_retry_reset(),
        )
        ctx.state.add_agent(patcher)
        if not patcher.ok:
            raise agent_stage_error(patcher)

        try:
            regression_commands = validate_patcher_output(patcher.parsed_output)
        except GateError as exc:
            raise StageError(str(exc), category="agent_failure")

        # Both POV guards only apply when a POV exists (the exploiter ran); in the
        # alert-only baseline there is nothing to protect. The patcher may not pass
        # the POV off as a "regression test", and may not alter it — anything it
        # changed under the POV tree is rolled back to the pre-run snapshot.
        if ctx.pov_command:
            regression_commands = filter_duplicate_pov_commands(regression_commands, ctx.pov_command)
        ctx.enforce_pov_integrity("patcher")

        write_diffs(ctx.run_dir, ctx.worktree_path)
        if not collect_patch_only_diff(ctx.worktree_path).strip():
            raise StageError(
                "Patcher did not produce any non-POV code or test diff", category="agent_failure"
            )

        ctx.patcher_output = patcher.parsed_output
        ctx.regression_commands = regression_commands
        ctx.persist()


class PovAfterStage(Stage):
    """The POV-after gate, as a patcher self-correction fix-point.

    A POV that still reproduces is a patch defect, so the failure goes back to the
    patcher (up to ``options.max_correction_attempts``) instead of rejecting the
    run outright. With a budget of 1 this is exactly the old one-shot gate. Used
    by the `hardening` profile; `converge` covers the same gate plus regressions.
    """

    name = "pov_after"
    requires = ("worktree", "docker_image", "pov_command", "patcher_output")
    produces = ("pov_after",)

    def run(self, ctx: StageContext) -> None:
        PatchCorrectionLoop().converge(ctx, [pov_blocked_predicate()], stage="pov_after")


class HardeningLoopStage(Stage):
    """Iterative patcher <-> exploiter hardening.

    Runs after the baseline patch has already fixed the original POV. Each round
    the exploiter hunts for a *new* bypass variant of the same vulnerability; if
    it finds one that really reproduces, the patcher strengthens the fix until
    that variant (and the original POV) no longer reproduce. The loop stops early
    the moment the exploiter can no longer bypass the current patch, and never
    runs more than ``options.max_hardening_rounds`` rounds.

    It updates ``ctx.patcher_output`` / ``ctx.regression_commands`` in place, so
    the downstream regression and verifier stages judge the final hardened patch.
    """

    name = "harden"
    requires = ("worktree", "docker_image", "patcher_output", "pov_after")

    def run(self, ctx: StageContext) -> None:
        max_rounds = max(0, ctx.options.max_hardening_rounds)
        # (round, pov_command) for every variant that was a confirmed bypass, so
        # they can be replayed against the FINAL patch once the loop settles.
        confirmed_variants: List[Tuple[int, str]] = []
        exploit_budget = max(1, ctx.options.max_exploit_attempts)
        for round_num in range(1, max_rounds + 1):
            patch_diff = collect_patch_only_diff(ctx.worktree_path)

            # A malformed pov_path (e.g. echoing the in-container
            # /workspace/repo mount instead of a worktree-relative path) is the
            # same class of fixable mistake ExploiterStage retries on the first
            # pass; retry it here too rather than discarding an otherwise-good
            # hardening round outright.
            retry_feedback: Optional[Tuple[JsonDict, str, str, List[CommandResult]]] = None
            exploiter = None
            variant = None
            no_new_variant = False
            for exploit_attempt in range(1, exploit_budget + 1):
                run_label = (
                    f"exploiter_harden_r{round_num}"
                    if exploit_attempt == 1
                    else f"exploiter_harden_r{round_num}_retry_a{exploit_attempt}"
                )
                task = (
                    render_variant_exploiter_input(
                        ctx.base_context, ctx.exploiter_output, patch_diff, round_num
                    )
                    if retry_feedback is None
                    else render_exploiter_retry_input(ctx.base_context, *retry_feedback, exploit_attempt)
                )
                # The tree already carries the patch here, so an exploiter edit
                # to product code would silently weaken the fix being hardened.
                ctx.baseline_sources()
                exploiter = ctx.agent_runner.run(
                    "exploiter", task, ctx.run_dir, ctx.worktree_path, run_label=run_label,
                )
                ctx.state.add_agent(exploiter)
                ctx.enforce_source_integrity(run_label)
                if not exploiter.ok:
                    raise agent_stage_error(exploiter)

                # No new variant proposed -> the patch holds; stop retrying (this
                # is the intended "nothing left to harden" exit, not a defect).
                if str(exploiter.parsed_output.get("status")) != "pov_created":
                    no_new_variant = True
                    break

                try:
                    variant = validate_exploiter_output(exploiter.parsed_output, ctx.worktree_path)
                    break
                except GateError as exc:
                    if exploit_attempt == exploit_budget:
                        raise StageError(str(exc), category="agent_failure")
                    ctx.state.add_step(
                        "harden_exploit_retry", "retry",
                        round=round_num, attempt=exploit_attempt, detail=str(exc),
                    )
                    ctx.persist()
                    retry_feedback = (exploiter.parsed_output, "pov_output_invalid", str(exc), [])

            if no_new_variant:
                ctx.state.add_step(
                    "harden", "stable", round=round_num,
                    reason="exploiter found no new bypass variant",
                )
                ctx.persist()
                break

            variant_before = ctx.docker.run_project_command(
                variant["pov_command"],
                f"harden_variant_before_r{round_num}",
                ctx.options.command_timeout_seconds,
                env_overrides=POV_SANITIZER_ENV,
            )
            ctx.state.add_command(variant_before)
            # A proposed variant that doesn't actually reproduce is not a real
            # bypass -> treat the patch as holding and stop.
            if not variant_before.ok:
                ctx.state.add_step(
                    "harden", "stable", round=round_num,
                    reason="proposed variant did not bypass the current patch",
                )
                ctx.persist()
                break

            # Real bypass. Re-baseline the POV tree (it now includes the variant
            # file) so the patcher integrity guard below measures against it.
            confirmed_variants.append((round_num, variant["pov_command"]))
            if variant["pov_command"] not in ctx.protected_pov_commands:
                ctx.protected_pov_commands.append(variant["pov_command"])
            ctx.baseline_pov()
            write_diffs(ctx.run_dir, ctx.worktree_path)

            patcher = ctx.agent_runner.run(
                "patcher",
                render_hardening_patcher_input(
                    ctx.base_context, ctx.patcher_output, exploiter.parsed_output,
                    variant_before, patch_diff, round_num,
                ),
                ctx.run_dir,
                ctx.worktree_path,
                run_label=f"patcher_harden_r{round_num}",
                on_retry_reset=ctx.patcher_retry_reset(),
            )
            ctx.state.add_agent(patcher)
            if not patcher.ok:
                raise agent_stage_error(patcher)
            try:
                regression_commands = validate_patcher_output(patcher.parsed_output)
            except GateError as exc:
                raise StageError(str(exc), category="agent_failure")

            for protected in ctx.protected_pov_commands:
                regression_commands = filter_duplicate_pov_commands(regression_commands, protected)
            ctx.enforce_pov_integrity(f"patcher_harden_r{round_num}")
            write_diffs(ctx.run_dir, ctx.worktree_path)

            # Adopt the round's patch before checking it so a correction attempt
            # sends the patcher back its *current* fix, not the pre-round one.
            ctx.patcher_output = patcher.parsed_output
            ctx.regression_commands = regression_commands

            # The strengthened patch must block the new variant AND keep the
            # original POV blocked. A failure here is a patch defect, so it goes
            # back to the patcher (same self-correction budget as `converge`)
            # before the round is called a loss.
            PatchCorrectionLoop().converge(
                ctx,
                [
                    pov_blocked_predicate(
                        variant["pov_command"],
                        name=f"harden_variant_after_r{round_num}",
                        label=f"bypass_variant_blocked_r{round_num}",
                        description=f"bypass variant from hardening round {round_num}",
                    ),
                    pov_blocked_predicate(
                        ctx.pov_command,
                        name=f"harden_original_recheck_r{round_num}",
                        label="original_pov_blocked",
                        description="original POV",
                    ),
                ],
                stage=f"harden_r{round_num}",
            )
            ctx.state.add_step("harden", "hardened", round=round_num, command=variant["pov_command"])
            ctx.persist()
        else:
            # Loop ran the full budget without an early "stable" break.
            ctx.state.add_step("harden", "max_rounds_reached", rounds=max_rounds)
            ctx.persist()

        # Per-round variant checks were run against that round's patch; a later
        # round may have rewritten the fix and regressed an earlier variant. Replay
        # every confirmed variant against the FINAL patch so the accepted patch is
        # certified to block all of them, not just each one at its own round.
        for round_num, pov_command in confirmed_variants:
            replay = ctx.docker.run_project_command(
                pov_command,
                f"harden_final_replay_r{round_num}",
                ctx.options.command_timeout_seconds,
                env_overrides=POV_SANITIZER_ENV,
            )
            ctx.state.add_command(replay)
            if replay.exit_code == 0 or replay.timed_out:
                raise StageError(
                    f"Hardening: variant from round {round_num} reproduced again against the final patch",
                    category="agent_failure",
                )
        ctx.persist()


class RegressionStage(Stage):
    """The regression gate, as a patcher self-correction fix-point.

    A broken test is a patch defect, so it goes back to the patcher rather than
    rejecting the run (budget 1 == the old one-shot gate). When a POV exists it is
    re-checked *first* on every attempt, so a patch that fixes a test can never
    silently re-open the vulnerability.
    """

    name = "regression"
    requires = ("worktree", "docker_image", "patcher_output")
    produces = ("regression_results",)

    def run(self, ctx: StageContext) -> None:
        predicates: List[Predicate] = []
        if ctx.pov_command:
            predicates.append(pov_blocked_predicate())
        predicates.append(regressions_pass_predicate())
        PatchCorrectionLoop().converge(ctx, predicates, stage="regression")
        ctx.state.add_step(
            "patch_and_regression", "ok", regression_commands=list(ctx.regression_commands)
        )
        ctx.persist()


# --------------------------------------------------------------------------- #
# Self-correction: drive the patcher to a fix-point over a set of predicates.
# --------------------------------------------------------------------------- #


def _merge_regression_commands(pinned: List[str], proposed: List[str]) -> List[str]:
    """Union that preserves order and never drops a pinned command.

    A patcher correcting a regression failure must not shrink the very test set it
    is being judged by, so every previously-declared command survives.
    """
    merged = list(pinned)
    seen = {normalize_shell_command(command) for command in merged}
    for command in proposed:
        key = normalize_shell_command(command)
        if key not in seen:
            merged.append(command)
            seen.add(key)
    return merged


# The shell's own "found it but could not execute it" / "did not find it" codes.
# A PoV command that never ran is not evidence of anything, least of all that the
# patch works — see ``pov_blocked_predicate``. Deliberately only these two: they
# are the unambiguous ones. Exit 2 is reserved for a harness error in the
# fixPOV evaluator, but run PoVs were never written to that contract and a
# real crash can legitimately exit 2, so claiming it here would turn genuine
# blocks into errors and reject correct patches.
POV_HARNESS_ERROR_EXIT_CODES = frozenset({126, 127})


def pov_blocked_predicate(
    pov_command: Optional[str] = None,
    *,
    name: str = "pov_after_patch",
    label: str = "pov_no_longer_reproduces",
    description: str = "POV",
) -> Predicate:
    """A POV must no longer reproduce on the patched code.

    Defaults to the run's original POV (recorded as ``pov_after`` for the
    verifier). The hardening loop passes a bypass variant's command — with its own
    docker command name and label — so a variant that survives an improved patch
    reuses the same self-correction machinery.

    Three outcomes, not two. "Anything non-zero means blocked" is a dangerously
    forgiving default — it is the same mistake ``fix_pov_eval`` already
    corrects with its reserved exit 2, and here it pointed the wrong way: a PoV
    harness that could not run at all (deleted binary, broken rebuild) exits 127
    and used to *pass* the gate, accepting a run whose vulnerability was never
    re-tested. So an exec failure is now its own outcome — it fails the gate and
    goes back to the patcher, which is also the agent that can fix it, since
    rebuilding the harness against the patched tree is exactly what it was
    already trying to do.
    """

    def check(ctx: StageContext) -> PredicateResult:
        command = pov_command or ctx.pov_command
        result = ctx.docker.run_project_command(
            command, name, ctx.options.command_timeout_seconds,
            env_overrides=POV_SANITIZER_ENV,
        )
        if command == ctx.pov_command:
            ctx.pov_after = result  # expose the latest run to the verifier stage
        if result.timed_out:
            return PredicateResult(
                False, f"{description} re-run timed out after patching (inconclusive).", [result]
            )
        if result.exit_code == 0:
            return PredicateResult(
                False,
                f"{description} still reproduces the vulnerability after patching "
                "(command exited 0).",
                [result],
            )
        if result.exit_code in POV_HARNESS_ERROR_EXIT_CODES:
            ctx.state.add_step(
                "pov_harness_error",
                "errored",
                command=command,
                exit_code=result.exit_code,
            )
            return PredicateResult(
                False,
                f"{description} harness failed to execute (command exited "
                f"{result.exit_code}: not found / not executable). This is NOT "
                "evidence the patch works — the PoV never ran. If the PoV is a "
                "compiled harness, rebuild it against the patched tree; do not "
                "modify the PoV sources.",
                [result],
            )
        return PredicateResult(True, f"{description} no longer reproduces after patching.", [result])

    return Predicate(label, check)


def baseline_checkout(ctx: StageContext) -> Optional[Path]:
    """A pristine pre-patch checkout of the worktree, created once per run.

    ``HEAD`` in the run's isolated repo is the untouched source (every patch and
    the PoV tree are uncommitted or untracked), so exporting it gives exactly the
    tree the patch was applied to — with no PoV files in it, which is what makes
    an injected PoV test show up as "absent from the baseline" rather than as a
    regression. Returns None if the export fails; callers then fall back to
    treating a failing command as a genuine regression.
    """
    if ctx.baseline_checkout_path is not None:
        return ctx.baseline_checkout_path
    target = ctx.run_dir / "baseline_checkout"
    archive = ctx.run_dir / "baseline_source.tar"
    try:
        export = run_local_command(
            "git_archive_baseline",
            ["git", "-C", str(ctx.worktree_path), "archive", "--format=tar",
             "-o", str(archive), "HEAD"],
            cwd=ctx.worktree_path,
        )
        if export.exit_code != 0:
            return None
        target.mkdir(parents=True, exist_ok=True)
        extract = run_local_command(
            "tar_extract_baseline", ["tar", "-xf", str(archive), "-C", str(target)],
            cwd=ctx.run_dir,
        )
        if extract.exit_code != 0:
            return None
    finally:
        archive.unlink(missing_ok=True)
    ctx.baseline_checkout_path = target
    return target


def _triage_regression_failure(
    ctx: StageContext, index: int, command: str, started_at: float
) -> Tuple[str, str, List[CommandResult]]:
    """Decide whether a failed regression command is the patch's fault.

    Replays the same command against the pristine pre-patch checkout and compares
    JUnit reports, so the gate can tell an actual regression from the scaffold
    artifacts that dominate these failures: the injected PoV test (a *new* test
    whose vuln-present assertion fails precisely because the patch works), a test
    that only fails because the container runs as root, a pre-existing/flaky
    failure, or an unrunnable command the patcher picked. Every one of those
    failed on the baseline too, and none of them is a reason to send the patcher
    back — or to reject the run.

    Falls back to "genuine" whenever the comparison cannot be made, so a broken
    replay never launders a real regression into a pass.
    """
    checkout = baseline_checkout(ctx)
    if checkout is None:
        return "genuine", "no pristine baseline checkout available to compare against", []

    replay_started = time.time()
    baseline_docker = ctx.docker.for_checkout(checkout)
    baseline_result = baseline_docker.run_project_command(
        command, f"regression_{index}_baseline", ctx.options.command_timeout_seconds,
        env_overrides=POV_SANITIZER_ENV,
    )
    if baseline_result.timed_out:
        return (
            "genuine",
            "the baseline replay timed out, so the failure could not be attributed",
            [baseline_result],
        )

    verdict, regressed, explanation = classify_regression_failure(
        parse_junit_reports(ctx.worktree_path, newer_than=started_at - 1),
        parse_junit_reports(checkout, newer_than=replay_started - 1),
        baseline_result.ok,
    )
    ctx.state.add_step(
        "regression_triage",
        verdict,
        command=command,
        explanation=explanation,
        regressed_tests=regressed[:20],
        regressed_count=len(regressed),
        baseline_exit_code=baseline_result.exit_code,
    )
    return verdict, explanation, [baseline_result]


# A regression/exploiter/patcher command containing `clean` (`gradle ... clean
# build`, `mvn clean package`, ...) throws away incremental build state and can
# cost minutes on a large project (see "Run speed" in CLAUDE.md) — the whole
# reason `agent_guard.py` blocks agents from running one. `_ensure_build_checked`
# must never *itself* force one of those onto every correction attempt, so a
# project whose own default build command happens to include `clean` is left
# alone: the mandatory check below only ever adds a command that is safe to
# replay repeatedly.
_CLEAN_TOKEN_RE = re.compile(r"\bclean\b")


def _ensure_build_checked(commands: List[str], ctx: StageContext) -> List[str]:
    """Guarantee the project's own full build is part of the regression gate.

    Patcher-chosen ``regression_commands`` are scoped to whatever the agent
    thought to test — for a C/C++ project that is routinely a single module or
    object file, never a full top-level build. Nothing else in the gating path
    ever confirms the *whole* project still builds (``test_command`` defaults to
    a no-op ``"true"`` for most of these projects), so an agent that damages an
    unrelated part of the tree while patching or self-verifying (e.g. deleting a
    directory it assumed was disposable build output) sails through gating and
    is only ever caught later by the non-gating fixPOV eval — too late to
    feed back to the patcher, and after the run is already `accepted`.

    Appends ``ctx.project.build_command`` when it is missing from the command
    set and does not contain `clean`. It then goes through the exact same
    baseline-diff triage as every other regression command (see
    ``_triage_regression_failure``): if the pristine baseline also fails to
    build via this command, the failure is classified `scaffold` and does not
    block acceptance — so a project whose bare build command cannot be replayed
    outside the full docker/image setup is never newly broken by this check.
    """
    build_command = ctx.project.build_command
    if not build_command or _CLEAN_TOKEN_RE.search(build_command):
        return commands
    existing = {normalize_shell_command(command) for command in commands}
    if normalize_shell_command(build_command) in existing:
        return commands
    return commands + [build_command]


def regressions_pass_predicate() -> Predicate:
    """Every regression/test command must pass on the patched code.

    "Pass" means no test that passed before the patch fails after it — not "every
    command exits 0". The two differ constantly here, because the pipeline itself
    injects a PoV test into the tree the suite runs over, and because the agent
    picks the commands. A command that fails identically on the pristine baseline
    is telling us about the project, not about the patch.
    """

    def check(ctx: StageContext) -> PredicateResult:
        commands = list(ctx.regression_commands)
        if not commands and ctx.project.test_command:
            commands = [ctx.project.test_command]
        if not commands:
            raise StageError(
                "No regression command was provided and no default test command is available",
                category="pipeline",
            )
        commands = _ensure_build_checked(commands, ctx)
        # Record the effective (possibly defaulted) set so it is pinned against
        # any later correction attempt shrinking it.
        ctx.regression_commands = commands
        results: List[CommandResult] = []
        failed: List[Tuple[int, str, CommandResult, float]] = []
        for index, command in enumerate(commands, start=1):
            started_at = time.time()
            result = ctx.docker.run_project_command(
                command, f"regression_{index}", ctx.options.command_timeout_seconds,
                env_overrides=POV_SANITIZER_ENV,
            )
            results.append(result)
            if not result.ok:
                failed.append((index, command, result, started_at))
        ctx.regression_results = results
        if not failed:
            return PredicateResult(True, "All regression commands passed.", results)

        genuine: List[str] = []
        scaffold: List[str] = []
        for index, command, result, started_at in failed:
            verdict, explanation, extra = _triage_regression_failure(
                ctx, index, command, started_at
            )
            results.extend(extra)
            if verdict == "genuine":
                genuine.append(f"{' '.join(result.command)} — {explanation}")
            else:
                scaffold.append(f"{command} — {explanation}")

        if genuine:
            # Only the genuine failures are fed back; naming the scaffold ones too
            # would send the patcher chasing tests it cannot fix.
            return PredicateResult(False, "Regression command(s) failed: " + "; ".join(genuine), results)
        return PredicateResult(
            True,
            "All regression failures were pre-existing or scaffold-only: " + "; ".join(scaffold),
            results,
        )

    return Predicate("regressions_pass", check)


def assess_predicates(
    ctx: StageContext, predicates: List[Predicate]
) -> Optional[Tuple[Predicate, PredicateResult]]:
    """Check predicates in order once, recording each command; never re-patches.

    Returns the first predicate that fails together with its result, or None if
    every one passed. Stops at the first failure so a still-vulnerable patch never
    wastes time running the regression suite, and so security is always
    re-checked first.

    This is the read-only half of ``PatchCorrectionLoop.converge``, split out
    because the retrofit (``python -m security_pipeline retrofit``) *measures*
    whether an already-finished run's patch clears a gate. It must not send the
    patcher back: those runs have completed diffs that the fixPOV and
    residual scores were computed against, and rewriting the patch would silently
    invalidate every number already recorded for them.
    """
    for predicate in predicates:
        result = predicate.check(ctx)
        for command in result.commands:
            ctx.state.add_command(command)
        if not result.passed:
            return predicate, result
    return None


class PatchCorrectionLoop:
    """Drive the patcher toward a patch that satisfies every predicate.

    Each attempt re-checks the predicates in order (security first); on the first
    recoverable failure it sends the patcher back with that failure as feedback
    and tries again, up to ``options.max_correction_attempts`` attempts. Because
    every attempt re-checks the POV *before* the tests, a change the patcher makes
    to fix a regression can never silently re-open the vulnerability.

    With a budget of 1 there is no re-patching: the first failure is a terminal
    rejection — i.e. the old one-shot gates. Every objective patch gate in the
    pipeline runs through this loop (``converge``, the standalone ``pov_after``
    and ``regression`` stages, and each hardening round's post-patch checks), so a
    failing check always goes back to the patcher first.
    """

    def converge(
        self, ctx: StageContext, predicates: List[Predicate], stage: str = "converge"
    ) -> int:
        """Drive the patch to satisfy every predicate; returns attempts used.

        ``stage`` names the caller on each recorded correction step, so a run that
        self-corrects in several places (POV-after, a hardening round, the
        regression gate) stays attributable in the artifacts and the dashboard.
        """
        budget = max(1, ctx.options.max_correction_attempts)
        for attempt in range(1, budget + 1):
            failure = self._first_failure(ctx, predicates)
            if failure is None:
                self._finalize(ctx, stage, attempt, budget)
                return attempt
            predicate, result = failure
            if attempt == budget:
                raise StageError(
                    f"patch did not satisfy '{predicate.label}' within {budget} "
                    f"correction attempt(s): {result.summary}",
                    category="agent_failure",
                )
            ctx.state.add_step(
                "correction", "retry", stage=stage, attempt=attempt,
                failing=predicate.label, detail=result.summary,
            )
            ctx.persist()
            self._repatch(ctx, predicate, result, attempt + 1, stage)
        raise AssertionError("unreachable: the loop returns or raises")  # pragma: no cover

    def _first_failure(
        self, ctx: StageContext, predicates: List[Predicate]
    ) -> Optional[Tuple[Predicate, PredicateResult]]:
        return assess_predicates(ctx, predicates)

    def _finalize(self, ctx: StageContext, stage: str, attempt: int, budget: int) -> None:
        ctx.state.add_step(
            "correction", "converged", stage=stage, attempt=attempt, budget=budget
        )
        write_diffs(ctx.run_dir, ctx.worktree_path)
        ctx.persist()

    def _repatch(
        self,
        ctx: StageContext,
        predicate: Predicate,
        result: PredicateResult,
        attempt_num: int,
        stage: str = "converge",
    ) -> None:
        # Keep the historical label for the plain converge stage; other callers
        # (POV-after, a hardening round, regression) get their own artifact folder
        # so several correction loops in one run never clobber each other.
        run_label = (
            f"patcher_correction_a{attempt_num}"
            if stage == "converge"
            else f"patcher_correction_{stage}_a{attempt_num}"
        )
        ctx.baseline_pov()
        patcher = ctx.agent_runner.run(
            "patcher",
            render_correction_patcher_input(
                ctx.base_context,
                ctx.patcher_output,
                predicate.label,
                result.summary,
                result.commands,
                attempt_num,
            ),
            ctx.run_dir,
            ctx.worktree_path,
            run_label=run_label,
            on_retry_reset=ctx.patcher_retry_reset(),
        )
        ctx.state.add_agent(patcher)
        if not patcher.ok:
            raise agent_stage_error(patcher)
        try:
            proposed = validate_patcher_output(patcher.parsed_output)
        except GateError as exc:
            raise StageError(str(exc), category="agent_failure")
        # Guard 1: any change the patcher made to the POV is rolled back (same as
        # PatcherStage), and it may not pass off any POV (original or hardening
        # variant) as a test. Both only apply when a POV exists — an alert-only
        # arm has nothing to protect.
        for protected in ctx.protected_pov_commands or [ctx.pov_command or ""]:
            if protected:
                proposed = filter_duplicate_pov_commands(proposed, protected)
        ctx.enforce_pov_integrity(run_label)
        # Guard 2: the regression set may only grow, never shrink.
        ctx.regression_commands = _merge_regression_commands(ctx.regression_commands, proposed)
        write_diffs(ctx.run_dir, ctx.worktree_path)
        ctx.patcher_output = patcher.parsed_output
        ctx.persist()


class ConvergeStage(Stage):
    """Verify the patch and, when a budget is set, let the patcher self-correct.

    Runs the POV-after and regression gates as a fix-point: the POV must no longer
    reproduce AND the regression tests must pass. A failing check is sent back to
    the patcher as feedback and re-checked, up to ``--max-correction-attempts``
    (1 == the old one-shot ``pov_after`` + ``regression`` gates).
    """

    name = "converge"
    requires = ("worktree", "docker_image", "pov_command", "patcher_output")
    produces = ("pov_after", "regression_results")

    def run(self, ctx: StageContext) -> None:
        PatchCorrectionLoop().converge(
            ctx, [pov_blocked_predicate(), regressions_pass_predicate()], stage="converge"
        )
        # Keep the regression stage's terminal step name so dashboards / analysis
        # that key off "patch_and_regression" keep working unchanged.
        ctx.state.add_step(
            "patch_and_regression", "ok", regression_commands=list(ctx.regression_commands)
        )
        ctx.persist()


class VerifierStage(Stage):
    """The LLM review gate.

    ``pov_before``/``pov_after`` are deliberately NOT required. They are the
    verifier's strongest evidence but not its only one — the alert-only
    `baseline` has no exploiter, and reviewing its diff against the alert is
    exactly the gate that profile was missing. ``render_verifier_input`` switches
    evidence modes on what it is actually handed. Recipes that DO intend an
    exploit-backed review still get their dependency checked: ``patcher_evidence
    == "full"`` already forces the exploiter into the stage list
    (``resolve_experiment``), and the POV gates sit between them.
    """

    name = "verifier"
    requires = ("worktree", "patcher_output")
    produces = ("verifier_output",)

    def run(self, ctx: StageContext) -> None:
        verifier = ctx.agent_runner.run(
            "verifier",
            render_verifier_input(
                ctx.base_context,
                ctx.exploiter_output,
                ctx.patcher_output,
                ctx.pov_before,
                ctx.pov_after,
                ctx.regression_results,
            ),
            ctx.run_dir,
            ctx.worktree_path,
        )
        ctx.state.add_agent(verifier)
        if not verifier.ok:
            raise agent_stage_error(verifier)
        try:
            validate_verifier_output(verifier.parsed_output)
        except GateError as exc:
            raise StageError(str(exc), category="agent_failure")
        ctx.verifier_output = verifier.parsed_output
        ctx.persist()


def _evaluation_docker(docker):
    """The runner the fixPOV / residual evaluators should use.

    These stages run after every agent has exited, so their container is not
    agent-facing and keeps the network the agents were cut off from -- their
    curated staging builds legitimately fetch (`mvn dependency:build-classpath`
    and `mvn install` pull plugins the project's own `package` never used, and
    the coreutils harness clones gnulib). Under `--network none` that staging
    failed name resolution, which correctly records every POV as `errored` with
    a null score, wiping out the run's evaluation entirely.

    ``getattr`` because a test may pass a docker stub with no ``for_evaluation``;
    same reason ``fix_pov.evaluate_manifest`` probes for ``session``.
    """
    factory = getattr(docker, "for_evaluation", None)
    return factory() if callable(factory) else docker


class FixPovEvalStage(Stage):
    """Replay the project's curated fixPOVs against the patched code.

    A pure **evaluation** step: it measures how many of the CVE's real,
    advisory-derived exploit paths the pipeline's patch actually blocked, and
    NEVER rejects the run. A POV that still reproduces, a broken manifest, or a
    container error are all recorded, not raised — so this stage cannot turn an
    otherwise-accepted patch into a rejection.

    It is deliberately the LAST stage in every profile so no agent (exploiter,
    patcher, verifier) ever sees the fixPOV files or the official fix,
    which would leak the real CVE. Staged files live under
    ``.security-pipeline/gtpov`` (the staging path is frozen at its legacy name — see ``FIX_POV_STAGE_PARTS``) and are removed before returning, and this stage
    never calls ``write_diffs``, so fixPOV never enters a persisted diff.
    """

    name = "fix_pov_eval"
    requires = ("worktree", "docker_image", "patcher_output")
    produces = ("fix_pov_results",)

    def run(self, ctx: StageContext) -> None:
        from . import fix_pov as gt

        workspace_root = ctx.options.workspace_root
        slug = ctx.project.project_slug

        try:
            manifest = gt.load_manifest(workspace_root, slug)
        except gt.FixPovError as exc:
            ctx.state.add_step("fix_pov_eval", "errored", reason=str(exc))
            ctx.persist()
            return

        if manifest is None:
            ctx.state.add_step(
                "fix_pov_eval", "skipped",
                reason="no fixPOV manifest for this project",
            )
            ctx.persist()
            return

        try:
            summary = gt.evaluate_manifest(
                manifest=manifest,
                project_gt_dir=gt.project_dir(workspace_root, slug),
                docker=_evaluation_docker(ctx.docker),
                checkout_path=ctx.worktree_path,
                timeout_seconds=ctx.options.command_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - evaluation must never gate the run
            ctx.state.add_step("fix_pov_eval", "errored", reason=str(exc))
            ctx.persist()
            return

        # Record each POV's docker run for observability (already redacted by the
        # DockerRunner). Keep results.json itself as the authoritative artifact.
        # A POV can have no command_result at all — an uncertified or stale POV is
        # never executed, and nothing runs after a failed staging build.
        for record in summary.get("setup_results", []):
            ctx.state.commands.append(record)
        for pov in summary["povs"]:
            if pov.get("command_result"):
                ctx.state.commands.append(pov["command_result"])

        results_path = ensure_dir(ctx.run_dir / "fix_pov") / "results.json"
        write_json(results_path, gt.redact_for_run_artifact(summary))
        ctx.fix_pov_results = summary
        ctx.state.add_step(
            "fix_pov_eval", "ok",
            total=summary["total"],
            blocked=summary["blocked"],
            reproduced=summary["reproduced"],
            errored=summary["errored"],
            score=summary["score"],
            all_blocked=summary["all_blocked"],
            results_path=str(results_path),
        )
        ctx.persist()


class ResidualEvalStage(Stage):
    """Replay the project's residual-gap POVs — did the patch *beat* upstream?

    A residual POV exploits a path the CVE's **official fix does not close** (see
    ``security_pipeline/residual.py``). Blocking one means the pipeline's patch is
    strictly better than the upstream fix; failing to block one is the expected,
    neutral outcome (the patch merely matched upstream) and is **not** a defect —
    which is exactly why this is scored separately from ``fix_pov_eval``
    rather than folded into it.

    Like ``fix_pov_eval`` this is a pure **evaluation** step that NEVER
    rejects a run, and it runs after it (dead last) so no agent ever sees these
    files or the official fix. Staged under ``.security-pipeline/respov`` — a
    sibling of the fixPOV stage dir, so evaluating both in one run cannot
    make them collide — and removed before returning, so nothing leaks into a
    persisted diff.
    """

    name = "residual_eval"
    requires = ("worktree", "docker_image", "patcher_output")
    produces = ("residual_results",)

    def run(self, ctx: StageContext) -> None:
        from . import residual as res

        workspace_root = ctx.options.workspace_root
        slug = ctx.project.project_slug

        try:
            manifest = res.load_manifest(workspace_root, slug)
        except res.ResidualError as exc:
            ctx.state.add_step("residual_eval", "errored", reason=str(exc))
            ctx.persist()
            return

        if manifest is None:
            ctx.state.add_step(
                "residual_eval", "skipped",
                reason="no residual-gap POV manifest for this project",
            )
            ctx.persist()
            return

        try:
            summary = res.evaluate_manifest(
                manifest=manifest,
                project_res_dir=res.project_dir(workspace_root, slug),
                docker=_evaluation_docker(ctx.docker),
                checkout_path=ctx.worktree_path,
                timeout_seconds=ctx.options.command_timeout_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - evaluation must never gate the run
            ctx.state.add_step("residual_eval", "errored", reason=str(exc))
            ctx.persist()
            return

        for record in summary.get("setup_results", []):
            ctx.state.commands.append(record)
        for pov in summary["povs"]:
            if pov.get("command_result"):
                ctx.state.commands.append(pov["command_result"])

        results_path = ensure_dir(ctx.run_dir / "residual") / "results.json"
        write_json(results_path, res.redact_for_run_artifact(summary))
        ctx.residual_results = summary
        ctx.state.add_step(
            "residual_eval", "ok",
            total=summary["total"],
            hardened_beyond_fix=summary["hardened_beyond_fix"],
            matches_official_fix=summary["matches_official_fix"],
            errored=summary["errored"],
            score=summary["score"],
            all_hardened=summary["all_hardened"],
            results_path=str(results_path),
        )
        ctx.persist()


# --------------------------------------------------------------------------- #
# Registry, profiles, and recipe resolution
# --------------------------------------------------------------------------- #

STAGE_REGISTRY: Dict[str, Type[Stage]] = {
    "worktree": WorktreeStage,
    "docker_build": DockerBuildStage,
    "exploiter": ExploiterStage,
    "patcher": PatcherStage,
    "pov_after": PovAfterStage,
    "converge": ConvergeStage,
    "harden": HardeningLoopStage,
    "regression": RegressionStage,
    "verifier": VerifierStage,
    "fix_pov_eval": FixPovEvalStage,
    "residual_eval": ResidualEvalStage,
}

# Named experiment arms. Add a row here to define a new ablation — no changes to
# the orchestrator are needed.
# Every profile ends in `fix_pov_eval` then `residual_eval`: two non-gating
# measurement steps replayed against the final patched code. The first asks "did
# the patch match the official fix?" (real-exploit coverage); the second asks
# "did it BEAT the official fix?" by replaying exploits for paths upstream's own
# fix leaves open. Both run LAST (after the verifier) so no agent ever sees their
# files or the official fix, and neither can reject a run — see
# FixPovEvalStage / ResidualEvalStage.
PROFILES: Dict[str, Tuple[str, ...]] = {
    # Full hypothesis arm: exploiter builds the POV and the patcher sees it.
    # `converge` runs the POV-after + regression gates as a self-correction
    # fix-point (see --max-correction-attempts).
    "full": (
        "worktree", "docker_build", "exploiter", "patcher", "converge", "verifier",
        "fix_pov_eval", "residual_eval",
    ),
    # Alert-only baseline: the patcher never sees exploit evidence (no exploiter,
    # no POV), but the patch it produces is still reviewed by the verifier. Being
    # judged by nothing at all was confounding the comparison — a `full` patch had
    # to survive a reviewer and a `baseline` patch did not — so the arms differed
    # in gating as well as in evidence. Now only the evidence differs, which is
    # the study's actual variable.
    #
    # Deliberately NOT the `regression` stage: that gate exists to feed a broken
    # test back to the patcher, and this arm has no self-correction loop to feed.
    # The verifier runs the project's tests itself and weighs the result as part
    # of its review, which is the same information without a second container pass
    # or a redundant gate — see `render_verifier_input`'s alert-only mode.
    "baseline": (
        "worktree", "docker_build", "patcher", "verifier",
        "fix_pov_eval", "residual_eval",
    ),
    # Evaluated baseline: exploiter still runs to build the *scorer*, but its
    # output is withheld from the patcher (patcher_evidence == "alert_only").
    # Identical objective gates to `full` — the controlled comparison.
    "baseline_eval": (
        "worktree", "docker_build", "exploiter", "patcher", "converge", "verifier",
        "fix_pov_eval", "residual_eval",
    ),
    # Ablation: everything except the LLM verifier.
    "no_verifier": (
        "worktree", "docker_build", "exploiter", "patcher", "converge",
        "fix_pov_eval", "residual_eval",
    ),
    # Iterative hardening: after the baseline patch fixes the original POV, loop
    # the exploiter (hunt a new bypass variant) and patcher (strengthen the fix)
    # up to --max-rounds times, stopping early when no new bypass is found.
    "hardening": (
        "worktree", "docker_build", "exploiter", "patcher", "pov_after", "harden",
        "regression", "verifier", "fix_pov_eval", "residual_eval",
    ),
}

# Whether the patcher is shown the exploit evidence, per profile.
PROFILE_PATCHER_EVIDENCE: Dict[str, str] = {
    "full": "full",
    "baseline": "alert_only",
    "baseline_eval": "alert_only",
    "no_verifier": "full",
    "hardening": "full",
}

# Non-gating stages that pure-baseline offline scoring can drop without changing
# the study's independent variable. Exposed so a caller can strip evaluation-only
# stages (e.g. the --no-fix-pov-eval flag) without hardcoding the name.
EVALUATION_ONLY_STAGES = ("fix_pov_eval", "residual_eval")

DEFAULT_PROFILE = "full"
PATCHER_EVIDENCE_CHOICES = ("full", "alert_only")


def _validate_stage_dependencies(stage_names: Tuple[str, ...]) -> None:
    produced: set = set()
    for name in stage_names:
        stage_cls = STAGE_REGISTRY.get(name)
        if stage_cls is None:
            raise ExperimentConfigError(
                f"unknown stage: {name!r} (known: {', '.join(sorted(STAGE_REGISTRY))})"
            )
        missing = set(stage_cls.requires) - produced
        if missing:
            raise ExperimentConfigError(
                f"stage {name!r} requires {sorted(missing)} which no earlier stage produces"
            )
        produced |= set(stage_cls.produces)


def resolve_experiment(
    profile: Optional[str] = None,
    stages: Optional[List[str]] = None,
    patcher_evidence: Optional[str] = None,
) -> ExperimentConfig:
    """Build (and validate) an ExperimentConfig from a profile name and/or an ad
    hoc stage override. Raises ExperimentConfigError on an unrunnable recipe."""
    profile = profile or DEFAULT_PROFILE

    if stages is not None:
        stage_names = tuple(s.strip() for s in stages if s and s.strip())
        if not stage_names:
            raise ExperimentConfigError("--stages was empty")
    else:
        if profile not in PROFILES:
            raise ExperimentConfigError(
                f"unknown profile: {profile!r} (known: {', '.join(sorted(PROFILES))})"
            )
        stage_names = PROFILES[profile]

    evidence = patcher_evidence or PROFILE_PATCHER_EVIDENCE.get(profile, "full")
    if evidence not in PATCHER_EVIDENCE_CHOICES:
        raise ExperimentConfigError(
            f"patcher_evidence must be one of {PATCHER_EVIDENCE_CHOICES}, got {evidence!r}"
        )

    _validate_stage_dependencies(stage_names)

    if evidence == "full" and "patcher" in stage_names and "exploiter" not in stage_names:
        raise ExperimentConfigError(
            "patcher_evidence='full' needs the exploiter stage to produce the POV; "
            "use patcher_evidence='alert_only' or add the exploiter stage"
        )

    return ExperimentConfig(profile=profile, stages=stage_names, patcher_evidence=evidence)


def build_stages(experiment: ExperimentConfig) -> List[Stage]:
    return [STAGE_REGISTRY[name]() for name in experiment.stages]
