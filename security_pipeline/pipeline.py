from __future__ import annotations

import hashlib
import re
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from .claude_agents import DEFAULT_AGENT_MODEL, ClaudeAgentRunner
from .logging_io import ensure_dir, write_json
from .metadata import load_alert, resolve_project_metadata
from .models import ExperimentConfig, PipelineState, RunOptions
from .openrouter import is_openrouter_model, reconcile_openrouter_run_costs
from .stages import (
    StageContext,
    StageError,
    build_base_context,
    build_stages,
    resolve_experiment,
    write_diffs,
)


def sanitize_run_component(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value)
    return safe.strip(".-_") or "run"


def finding_id_from_parts(alert_name: str, project_slug: str, cve_id: str) -> str:
    digest = hashlib.sha256(
        f"{alert_name}:{project_slug}:{cve_id}".encode("utf-8")
    ).hexdigest()[:12]
    return f"finding-{digest}"


def make_finding_id(alert_path: Path, project: Any) -> str:
    return finding_id_from_parts(alert_path.name, project.project_slug, project.cve_id)


def make_run_id(finding_id: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{timestamp}_{sanitize_run_component(finding_id)}"


# `unique_run_dir` picks a name by probing the filesystem, so two threads running
# alerts concurrently (`run --jobs N`) could hand out the same directory before
# either creates it. Allocation is claimed under this lock — pick AND mkdir as
# one step — so concurrent runs can never share a run directory. It guards only
# that claim; everything else in run_alert is thread-local.
_RUN_DIR_LOCK = threading.Lock()


def claim_run_dir(runs_dir: Path, run_id: str) -> Path:
    with _RUN_DIR_LOCK:
        run_dir = unique_run_dir(runs_dir, run_id)
        ensure_dir(run_dir)
    return run_dir


def unique_run_dir(runs_dir: Path, run_id: str) -> Path:
    candidate = runs_dir / run_id
    if not candidate.exists():
        return candidate
    index = 2
    while True:
        candidate = runs_dir / f"{run_id}_{index}"
        if not candidate.exists():
            return candidate
        index += 1


# Printed once, on stderr, as soon as a run owns its directory. The finding id in
# the directory name is profile-independent, so anything watching a run from the
# outside (the dashboard's live monitor) cannot tell two runs of the same alert
# apart by name — it has to be told which one is which, and only the run itself
# knows. stderr, not stdout: stdout stays a stream of pure JSON summaries.
RUN_DIR_ANNOUNCEMENT = "security-pipeline: run dir "


def announce_run_dir(run_dir: Path) -> None:
    print(f"{RUN_DIR_ANNOUNCEMENT}{run_dir}", file=sys.stderr, flush=True)


def existing_run_dirs(runs_dir: Path, finding_id: str) -> List[Path]:
    """Return every run directory under runs_dir that belongs to finding_id.

    Run directories are named ``{timestamp}_{finding_id}`` with an optional
    ``_{index}`` suffix appended by unique_run_dir on collisions.
    """
    if not runs_dir.exists():
        return []
    component = sanitize_run_component(finding_id)
    pattern = re.compile(rf".+_{re.escape(component)}(?:_\d+)?$")
    matches = [
        child
        for child in runs_dir.iterdir()
        if child.is_dir() and pattern.match(child.name)
    ]
    return sorted(matches)


class SecurityPipeline:
    def __init__(self, options: RunOptions, experiment: Optional[ExperimentConfig] = None) -> None:
        self.options = options
        # Default to the full exploit → patch → verify pipeline so existing
        # callers (and the dashboard's CLI launcher) keep their behavior.
        self.experiment = experiment or resolve_experiment(profile="full")
        self.package_root = Path(__file__).resolve().parent
        self.agent_runner = ClaudeAgentRunner(options, self.package_root)

    def run_alert(self, alert_path: Path) -> PipelineState:
        alert_path = alert_path.resolve()
        alert = load_alert(alert_path)
        project = resolve_project_metadata(alert_path, self.options.workspace_root)
        finding_id = make_finding_id(alert_path, project)
        run_id = make_run_id(finding_id)
        run_dir = claim_run_dir(self.options.runs_dir, run_id)
        announce_run_dir(run_dir)

        state = PipelineState(
            run_id=run_dir.name,
            alert_path=alert_path,
            project=project,
            run_dir=run_dir,
            profile=self.experiment.profile,
            label=self.options.label,
            model=self.options.model or DEFAULT_AGENT_MODEL,
            stages=list(self.experiment.stages),
            max_hardening_rounds=self.options.max_hardening_rounds,
            max_correction_attempts=self.options.max_correction_attempts,
            max_exploit_attempts=self.options.max_exploit_attempts,
            max_api_error_attempts=self.options.max_api_error_attempts,
        )
        worktree_path = run_dir / "worktree"
        state.worktree_path = worktree_path

        state.add_step("metadata", "ok", finding_id=finding_id, cwe_id=project.cwe_id)
        self._write_state(state)

        if self.options.dry_run:
            context = build_base_context(alert, project, finding_id, run_dir, worktree_path, docker=None)
            context["dry_run"] = True
            context["profile"] = self.experiment.profile
            context["stages"] = list(self.experiment.stages)
            write_json(run_dir / "context.json", context)
            state.status = "dry_run"
            state.reason = "Context generated without creating a worktree, Docker image, or Claude agent run."
            state.add_step("dry_run", "ok")
            self._write_state(state)
            self._write_verdict(state)
            return state

        ctx = StageContext(
            options=self.options,
            experiment=self.experiment,
            agent_runner=self.agent_runner,
            alert=alert,
            project=project,
            finding_id=finding_id,
            run_dir=run_dir,
            worktree_path=worktree_path,
            state=state,
            persist=lambda: self._write_state(state),
        )

        try:
            for stage in build_stages(self.experiment):
                try:
                    stage.run(ctx)
                except StageError as exc:
                    return self._fail(state, exc.reason, category=exc.category)
                except Exception as exc:  # noqa: BLE001 - a crash must still produce a verdict
                    # An unexpected exception used to escape run_alert entirely: no
                    # verdict.json, state.json frozen mid-stage, and the run left at
                    # `created` forever (the dashboard shows it as still live). One
                    # UnicodeDecodeError on a Latin-1 .properties file in a git diff
                    # was enough to strand a run that had already built a POV and a
                    # patch. Record it as an infra failure instead.
                    state.add_step(
                        "stage_crashed",
                        "failed",
                        stage=stage.name,
                        error=f"{type(exc).__name__}: {exc}",
                        traceback=traceback.format_exc()[-4000:],
                    )
                    return self._fail(
                        state,
                        f"{stage.name} stage crashed: {type(exc).__name__}: {exc}",
                        category="pipeline",
                    )

            return self._accept(state, ctx)
        finally:
            # Whatever happened above, hand any root-owned build output the
            # project's containers left in the worktree back to this (unprivileged)
            # host user — see DockerRunner.reclaim_ownership. Runs before the
            # worktree stage set ctx.docker have nothing to reclaim.
            if ctx.docker is not None:
                ctx.docker.reclaim_ownership()
            # Revisit any incomplete per-agent OpenRouter accounting after the
            # whole run. Earlier agents have had time to become queryable, and
            # the final agent gets a second chance after its immediate lookup.
            # Billing observability must never change the pipeline verdict.
            self._reconcile_provider_costs(run_dir)

    def _reconcile_provider_costs(self, run_dir: Path) -> None:
        model = getattr(self.options, "model", None)
        if self.options.dry_run or not is_openrouter_model(model):
            return
        try:
            reconcile_openrouter_run_costs(run_dir, str(model))
        except Exception as exc:  # accounting must never fail the run
            print(
                f"security-pipeline: OpenRouter cost reconciliation incomplete: {exc}",
                file=sys.stderr,
            )

    def _accept(self, state: PipelineState, ctx: StageContext) -> PipelineState:
        """Terminal success. The wording reflects which gates the profile ran so
        an `accepted` verdict is not misread as objectively verified when it was
        the alert-only baseline (see verdict.json `profile`)."""
        # The wording is assembled from the gates that actually ran, not from the
        # profile name. `baseline` now runs the regression gate and the verifier
        # but still has no POV, so keying the sentence off `verifier_output` alone
        # would have it claim an exploit was reproduced and blocked when none was
        # ever built.
        has_pov = ctx.pov_after is not None
        verified = ctx.verifier_output is not None
        state.add_step("verifier" if verified else "completed", "accepted")
        if has_pov:
            clauses = [
                "POV reproduced before patching, no longer reproduced after patching",
                "regressions passed",
            ]
        else:
            clauses = ["Patcher produced a patch from the alert (baseline: no exploit evidence or POV)"]
            if ctx.regression_results:
                clauses.append("regressions passed")
        if verified:
            clauses.append("verifier accepted")
        state.reason = ", ".join(clauses) + "."
        state.status = "accepted"
        self._write_state(state)
        self._write_verdict(state)
        if ctx.worktree_path and ctx.worktree_path.exists():
            write_diffs(state.run_dir, ctx.worktree_path)
        return state

    def _fail(self, state: PipelineState, reason: str, category: str = "pipeline") -> PipelineState:
        state.status = "rejected"
        state.reason = reason
        state.category = category
        state.add_step("failed", "rejected", reason=reason, category=category)
        if state.run_dir and state.worktree_path and state.worktree_path.exists():
            try:
                write_diffs(state.run_dir, state.worktree_path)
            except Exception as exc:
                state.add_step("write_diffs", "failed", reason=str(exc))
        self._write_state(state)
        self._write_verdict(state)
        return state

    def _write_state(self, state: PipelineState) -> None:
        if state.run_dir:
            write_json(state.run_dir / "state.json", state.to_json_dict())

    def _write_verdict(self, state: PipelineState) -> None:
        if not state.run_dir:
            return
        verdict = {
            "run_id": state.run_id,
            "profile": state.profile,
            "label": state.label,
            "model": state.model,
            "stages": list(state.stages),
            "max_hardening_rounds": state.max_hardening_rounds,
            "max_correction_attempts": state.max_correction_attempts,
            "max_exploit_attempts": state.max_exploit_attempts,
            "status": state.status,
            "reason": state.reason,
            "category": state.category,
            "alert_path": "[redacted]",
            "project": state.project.to_agent_json_dict(state.run_id) if state.project else {},
            "run_dir": str(state.run_dir),
            "worktree_path": str(state.worktree_path) if state.worktree_path else "",
        }
        write_json(state.run_dir / "verdict.json", verdict)
