from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


JsonDict = Dict[str, Any]


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class ProjectMetadata:
    project_slug: str
    cve_id: str
    cwe_id: str
    cwe_name: str
    github_url: str
    github_tag: str
    buggy_commit_id: str
    fix_commit_ids: str
    source_path: Path
    dockerfile_path: Path
    build_system: str
    build_command: str
    test_command: str
    jdk_version: str = ""
    mvn_version: str = ""
    gradle_version: str = ""
    use_gradlew: str = ""
    # Per-project Docker platform override (e.g. "linux/amd64"), empty = host-
    # native default (docker_runner.DEFAULT_DOCKER_PLATFORM). Exists for old
    # C/C++ autotools projects whose bundled config.guess/config.sub predate
    # aarch64 Linux and fail to identify a native arm64 host ("configure:
    # error: cannot guess build type") -- the JVM-bytecode rationale for
    # defaulting to host-native (see docker_runner.py) does not hold for
    # native-compiled projects.
    docker_platform: str = ""

    def to_json_dict(self) -> JsonDict:
        return _json_value(asdict(self))

    def to_agent_json_dict(self, finding_id: str) -> JsonDict:
        return {
            "finding_id": finding_id,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "build_system": self.build_system,
            "build_command": self.build_command,
            "test_command": self.test_command,
            "jdk_version": self.jdk_version,
            "mvn_version": self.mvn_version,
            "gradle_version": self.gradle_version,
            "use_gradlew": self.use_gradlew,
        }


@dataclass(frozen=True)
class CommandResult:
    name: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    log_path: Optional[Path] = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def to_json_dict(self) -> JsonDict:
        return _json_value(asdict(self))


@dataclass(frozen=True)
class AgentResult:
    agent_name: str
    parsed_output: JsonDict
    raw_stdout: str
    raw_stderr: str
    exit_code: int
    input_path: Path
    output_path: Path
    stdout_path: Path
    stderr_path: Path
    parse_error: Optional[str] = None
    # Set when the Claude API declined the request for cyber-safety policy reasons
    # (stop_reason == "refusal"). Distinct from a crash/parse failure so the
    # pipeline can emit an `api_refusal` verdict instead of a generic failure.
    refused: bool = False
    refusal_reason: Optional[str] = None
    # One entry per transient-API-error re-roll this invocation performed (the
    # blocked attempt's message, e.g. a content-filter false positive or a dropped
    # connection). Empty on the common path. Serialized into state.json's agent
    # entry so the dashboard can surface the retry without a separate step.
    api_error_attempts: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.parse_error is None

    def to_json_dict(self) -> JsonDict:
        return _json_value(asdict(self))


@dataclass(frozen=True)
class RunOptions:
    workspace_root: Path
    alerts_dir: Path
    runs_dir: Path
    model: Optional[str] = None
    effort: str = "high"
    claude_bin: str = "claude"
    permission_mode: str = "bypassPermissions"
    agent_timeout_seconds: int = 3600
    command_timeout_seconds: int = 1800
    dry_run: bool = False
    skip_docker_build: bool = False
    # Free-form experiment tag (e.g. "v1", "new-prompt") recorded on the run so a
    # batch of runs can be grouped/filtered later in the dashboard. "" == unlabelled.
    label: str = ""
    # When true, agents run with --output-format stream-json and tee each event to
    # agent_io/<name>/stream.jsonl so a watcher can follow the agent token-by-token.
    # Off by default for direct Anthropic/Z.ai runs. OpenRouter runs retain the
    # stream regardless, because its generation IDs are required to reconcile
    # provider-billed cost instead of trusting Claude Code's fallback estimate.
    stream: bool = False
    # Maximum patcher<->exploiter hardening rounds for the "hardening" profile.
    # Each round the exploiter hunts a new bypass variant and the patcher
    # strengthens the fix; the loop stops early when no new variant is found.
    max_hardening_rounds: int = 4
    # Maximum patcher attempts at every objective patch gate (`converge`, and the
    # standalone `pov_after` / `regression` / hardening-round checks). 1 = the old
    # one-shot gates: a failing check rejects the run. >1 turns them into a
    # self-correction loop — the failing check is fed back to the patcher and
    # re-checked, up to this many attempts. Keep it equal across experiment arms
    # so a baseline-vs-full A/B is not confounded.
    max_correction_attempts: int = 3
    # Maximum exploiter attempts at producing a POV that really reproduces on the
    # unpatched code. 1 = the old one-shot gate (a non-reproducing POV rejects the
    # run); >1 feeds the failure back to the exploiter and lets it try again.
    max_exploit_attempts: int = 3
    # Maximum attempts per agent invocation when the Claude CLI dies on a
    # transient, non-refusal API failure — an output content-filter false positive
    # on defensive code, or a dropped connection. These exit non-zero like a crash
    # but usually clear on a re-roll of the SAME pinned model, so >1 retries them
    # instead of failing the run. 1 = the old behaviour (one such error kills the
    # run). Unrelated to the content-retry budgets above and not swapped per arm:
    # it only rescues infra/filter noise, so it need not be held equal in an A/B.
    max_api_error_attempts: int = 2


@dataclass(frozen=True)
class ExperimentConfig:
    """Selects which pipeline stages run and how the patcher is fed.

    ``profile`` is a human-readable label recorded in state/verdict so downstream
    analysis can separate experimental arms. ``stages`` is the ordered list of
    stage names to execute (resolved from the profile, or overridden ad hoc).
    ``patcher_evidence`` is the independent variable for the baseline study:
    "full" hands the patcher the exploiter output + validated POV; "alert_only"
    withholds them so the patcher sees only the finder alert.
    """

    profile: str = "full"
    stages: Tuple[str, ...] = ()
    patcher_evidence: str = "full"  # "full" | "alert_only"

    def to_json_dict(self) -> JsonDict:
        return {
            "profile": self.profile,
            "stages": list(self.stages),
            "patcher_evidence": self.patcher_evidence,
        }


@dataclass
class PipelineState:
    run_id: str
    alert_path: Path
    project: Optional[ProjectMetadata] = None
    run_dir: Optional[Path] = None
    worktree_path: Optional[Path] = None
    # Experiment arm this run belongs to (mirrors ExperimentConfig.profile).
    profile: str = "full"
    # Free-form user tag for grouping/filtering a batch of runs (mirrors
    # RunOptions.label). "" == unlabelled; carried into state.json + verdict.json.
    label: str = ""
    # The ordered stage names this run actually executes (ExperimentConfig.stages).
    # Recorded so consumers (e.g. the dashboard rail) reflect the real pipeline
    # shape instead of assuming the full exploit->patch->verify sequence.
    stages: List[str] = field(default_factory=list)
    # The model the run was launched with, already resolved through
    # ``DEFAULT_AGENT_MODEL`` so it names a real model rather than "unset".
    # Recorded because the only other trace of it is what the Claude CLI reports
    # back per agent: a run that is still queued, still building its image, or
    # whose agents all crashed has no such report, and the dashboard rendered
    # those as the literal word "default" whatever model was actually selected.
    model: str = ""
    # Persist the configured hardening budget with the run.  This lets artifact
    # consumers (notably the dashboard) distinguish an early stable exit from a
    # loop that exhausted its configured budget.
    max_hardening_rounds: int = 4
    # Configured patcher self-correction budget for the objective patch gates
    # (mirrors RunOptions.max_correction_attempts). 1 == one-shot gates.
    max_correction_attempts: int = 3
    # Configured exploiter retry budget for the POV-before gate (mirrors
    # RunOptions.max_exploit_attempts). 1 == one-shot gate.
    max_exploit_attempts: int = 3
    # Configured transient-API-error re-roll budget (mirrors
    # RunOptions.max_api_error_attempts). 1 == a single such error fails the run.
    max_api_error_attempts: int = 2
    status: str = "created"
    reason: str = ""
    # Machine-readable failure class for rejected runs, so infra/policy noise is
    # separable from genuine agent failures without log-spelunking. One of:
    # "" (not failed) | infra_build_error | api_refusal | agent_failure | pipeline.
    category: str = ""
    steps: List[JsonDict] = field(default_factory=list)
    commands: List[JsonDict] = field(default_factory=list)
    agents: List[JsonDict] = field(default_factory=list)

    def add_step(self, name: str, status: str, **details: Any) -> None:
        entry = {"name": name, "status": status}
        entry.update(_json_value(details))
        self.steps.append(entry)

    def add_command(self, result: CommandResult) -> None:
        self.commands.append(result.to_json_dict())

    def add_agent(self, result: AgentResult) -> None:
        self.agents.append(result.to_json_dict())

    def to_json_dict(self) -> JsonDict:
        return {
            "run_id": self.run_id,
            "alert_path": "[redacted]",
            "project": self.project.to_agent_json_dict(self.run_id) if self.project else None,
            "run_dir": str(self.run_dir) if self.run_dir else None,
            "worktree_path": str(self.worktree_path) if self.worktree_path else None,
            "profile": self.profile,
            "label": self.label,
            "model": self.model,
            "stages": list(self.stages),
            "max_hardening_rounds": self.max_hardening_rounds,
            "max_correction_attempts": self.max_correction_attempts,
            "max_exploit_attempts": self.max_exploit_attempts,
            "max_api_error_attempts": self.max_api_error_attempts,
            "status": self.status,
            "reason": self.reason,
            "category": self.category,
            "steps": _json_value(self.steps),
            "commands": _json_value(self.commands),
            "agents": _json_value(self.agents),
        }
