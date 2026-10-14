from __future__ import annotations

import json
import re
import subprocess
import threading
from dataclasses import replace
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .logging_io import ensure_dir, read_text, write_json, write_text
from .models import AgentResult, JsonDict, RunOptions
from .openrouter import (
    OPENROUTER_COST_FILENAME,
    is_openrouter_model,
    openrouter_process_env,
    openrouter_settings_env,
    reconcile_openrouter_agent_dir,
)
from .zai import is_zai_model, zai_process_env, zai_settings_env


class ClaudeAgentError(RuntimeError):
    pass


AGENT_DESCRIPTIONS = {
    "exploiter": "Creates a real proof-of-vulnerability test for a finder alert.",
    "patcher": "Patches the vulnerability using the alert and validated POV.",
    "verifier": "Reviews the patch, reruns checks, and accepts or rejects the fix.",
}

# Tools an exploit/patch/verify agent has no business using, denied at the CLI.
#
# Two reasons, one of them serious. **Blinding:** the pipeline redacts the CVE
# from every agent (``ProjectMetadata.to_agent_json_dict``) so the experiment
# measures repair from a finder alert, not recall of a public advisory — but an
# exploiter simply web-searched its way to the CVE *and its official fix commit*
# ("CVE-2022-29577 antisamy fix commit github"), which also contaminates that
# run's fixPOV score. **Wall time:** the rest are background-task and
# scheduling tools that cannot do anything useful inside a one-shot `-p` agent,
# yet were called 20+ times (ScheduleWakeup, Monitor, TaskOutput polls averaging
# 231s). ToolSearch is denied too, so nothing here can be loaded back on demand.
DISALLOWED_TOOLS = (
    # blinding
    "WebSearch",
    "WebFetch",
    # sub-agents and orchestration
    "Task",
    "Workflow",
    "Skill",
    "Agent",
    "ToolSearch",
    # background work / scheduling / notification
    "ScheduleWakeup",
    "Monitor",
    "TaskCreate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "TaskUpdate",
    "CronCreate",
    "CronList",
    "CronDelete",
    "PushNotification",
    "RemoteTrigger",
    "SendMessage",
    "DesignSync",
    "EnterWorktree",
    "ExitWorktree",
    "Artifact",
)


# Model used when a run does not pass --model. Pinned here on purpose so a run is
# reproducible from the repo rather than from whoever's machine launched it.
# Change this one line to re-baseline the whole pipeline.
DEFAULT_AGENT_MODEL = "claude-sonnet-5"


def agent_settings(package_root: Path, model: Optional[str] = None) -> JsonDict:
    """Pipeline-owned settings: the Bash guard hook, plus provider routing.

    These are the only settings an agent gets, which holds *because*
    ``build_command`` passes an empty ``--setting-sources`` — see the note there.
    That is also why alternate-provider routing has to be merged in *here*
    rather than left in ``~/.claude/settings.json``, which agents never read.

    Credentials are deliberately absent: this file is persisted under
    ``agent_io/`` and served by the dashboard, so the token travels only in the
    subprocess env.  The provider modules expose matching ``*_settings_env``
    and ``*_process_env`` views so the persisted half never contains a key.
    """
    guard = str((package_root / "agent_guard.py").resolve())
    settings: JsonDict = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": f"python3 {guard}"}],
                }
            ]
        }
    }
    if is_zai_model(model):
        settings["env"] = zai_settings_env(model)
    elif is_openrouter_model(model):
        settings["env"] = openrouter_settings_env(model)
    return settings


def load_prompt(package_root: Path, agent_name: str) -> str:
    return read_text(package_root / "prompts" / f"{agent_name}.md")


def load_schema(package_root: Path, agent_name: str) -> str:
    return read_text(package_root / "schemas" / f"{agent_name}.json")


def _loads(text: str):
    """``json.loads`` tolerating literal control characters inside strings.

    Agents routinely embed a raw newline or tab in a summary/notes field, which
    strict JSON forbids. The object is otherwise perfectly well-formed, and
    rejecting it discards a completed agent turn over whitespace — observed on a
    patcher whose finished patch was thrown away for exactly this.
    """
    return json.loads(text, strict=False)


def extract_json_object(text: str) -> JsonDict:
    stripped = text.strip()
    if not stripped:
        raise ValueError("empty output")

    try:
        parsed = _loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL)
    if fenced:
        parsed = _loads(fenced.group(1))
        if isinstance(parsed, dict):
            return parsed

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = _loads(stripped[start : end + 1])
        if isinstance(parsed, dict):
            return parsed

    raise ValueError("no JSON object found")


def parse_claude_stdout(stdout: str) -> JsonDict:
    top = extract_json_object(stdout)
    if "result" in top and isinstance(top["result"], str):
        return extract_json_object(top["result"])
    return top


def recover_output_from_stream(stream_path: Path) -> Optional[JsonDict]:
    """Last structured object the agent emitted in *any* turn, or None.

    Only consulted when the final turn carries no JSON at all. That happens: an
    agent 35+ turns deep emits its structured output while self-verifying, then
    closes with a summary instead of repeating it -- one patcher ended a clean
    70-turn run with "I have already provided the structured output above" and
    the run was rejected for "no JSON object found" with a finished patch on
    disk. The object is genuinely the agent's own, just not in the turn the
    parser reads, so recovering it beats discarding the work.

    Scans backwards so the *latest* object wins, and prefers an explicitly
    delimited ``<StructuredOutput>`` block over a brace scan, which would
    otherwise start at the first ``{`` in surrounding prose.
    """
    try:
        lines = stream_path.read_text(errors="replace").splitlines()
    except OSError:
        return None

    texts: List[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or event.get("type") != "assistant":
            continue
        for block in event.get("message", {}).get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                texts.append(block["text"])

    for text in reversed(texts):
        tagged = re.search(r"<StructuredOutput>\s*(\{.*\})\s*</StructuredOutput>", text, re.DOTALL)
        for candidate in (tagged.group(1) if tagged else None, text):
            if not candidate:
                continue
            try:
                return extract_json_object(candidate)
            except ValueError:
                continue
    return None


def detect_refusal(stdout: str) -> Optional[str]:
    """Return the refusal message if Claude declined for cyber-safety policy.

    On a refusal the CLI exits non-zero, but its stdout still carries a valid
    top-level result object with ``stop_reason == "refusal"`` and a human-readable
    message in ``result`` (e.g. the Cyber Verification Program notice). We inspect
    the TOP-level object here — ``parse_claude_stdout`` would try to drill into
    ``result`` as JSON and fail, hiding the refusal behind a generic parse error.
    Returns None when the output is not a refusal (including unparseable output).
    """
    try:
        top = extract_json_object(stdout)
    except ValueError:
        return None
    message = top.get("result") if isinstance(top.get("result"), str) else ""
    if top.get("stop_reason") == "refusal":
        return message or "Claude refused the request (cyber-safety policy)."
    if top.get("is_error") and re.search(r"cyber|safety measures|verification program", message, re.IGNORECASE):
        return message
    return None


# Appended to the task on a *content-filter* re-roll only. A whole-file rewrite
# of a vulnerable file is what trips the output content filter — verified on
# dolphinscheduler CVE-2022-26884: the alert-only baseline made surgical edits
# and passed, while the hardening patcher streamed the entire request processor
# and was blocked at the same token on two separate days. Steering the SAME
# pinned model toward small edits removes the trigger, and changing the input at
# all feeds the deterministic filter different tokens. The model is never swapped
# (that would confound the profile experiment).
RETRY_MINIMAL_EDITS_NOTE = (
    "\n\n---\n"
    "RETRY NOTE: the previous attempt's output was blocked by an automated "
    "content filter while it was re-emitting an entire source file verbatim. "
    "Apply the fix as minimal, targeted edits to the smallest span necessary — "
    "do NOT rewrite or re-emit whole files; change only the lines that must "
    "change.\n"
)

_CONTENT_FILTER_RE = re.compile(r"content filter", re.IGNORECASE)
# Transient / false-positive API failures worth re-rolling the same model for,
# as opposed to a cyber-safety refusal (a policy verdict we never retry).
_TRANSIENT_API_ERROR_RE = re.compile(
    r"content filter"
    r"|connection (?:closed|error|reset)"
    r"|overloaded"
    r"|api error:\s*(?:internal|timeout|request timed out|5\d\d|429)",
    re.IGNORECASE,
)


def is_content_filter_error(message: str) -> bool:
    return bool(_CONTENT_FILTER_RE.search(message or ""))


def detect_transient_api_error(stdout: str) -> Optional[str]:
    """Return the error message if the CLI died on a transient API failure.

    The CLI exits non-zero and its top-level result object carries
    ``terminal_reason == "api_error"`` with a human message in ``result`` — e.g.
    an output content-filter false positive on defensive code, or a dropped
    connection. Re-rolling the SAME pinned model usually clears these, so unlike a
    genuine crash they are worth retrying. A cyber-safety refusal
    (``stop_reason == "refusal"``, handled by ``detect_refusal``) is a policy
    decision and is deliberately NOT in scope here. Returns None for anything
    else, including a real crash or unparseable output.
    """
    try:
        top = extract_json_object(stdout)
    except ValueError:
        return None
    if top.get("stop_reason") == "refusal":
        return None
    if top.get("terminal_reason") != "api_error":
        return None
    message = top.get("result") if isinstance(top.get("result"), str) else ""
    return message if _TRANSIENT_API_ERROR_RE.search(message or "") else None


class ClaudeAgentRunner:
    def __init__(self, options: RunOptions, package_root: Path) -> None:
        self.options = options
        self.package_root = package_root

    def _streaming_enabled(self) -> bool:
        """Whether this invocation must retain Claude's event stream.

        OpenRouter's Anthropic skin returns generation IDs in the stream but
        Claude Code drops the provider's billed cost from its terminal result.
        Retaining those IDs lets us reconcile the exact OpenRouter charge after
        the agent finishes, even for a CLI run that did not request live output.
        """
        return bool(
            getattr(self.options, "stream", False)
            or is_openrouter_model(getattr(self.options, "model", None))
        )

    def build_command(
        self,
        agent_name: str,
        run_dir: Path,
        settings_path: Path,
    ) -> List[str]:
        """The full `claude` argv for one agent invocation.

        The task prompt is deliberately NOT an argv element — it is piped over
        stdin by the runner (``_run_blocking``/``_run_streaming``). Linux caps a
        single argv string at ``MAX_ARG_STRLEN`` (128 KiB), well below what an
        unclipped alert can reach: a struts/cxf alert alone is ~150-165 KB, and
        the rendered task wraps more text around it. A run hit exactly this —
        ``OSError: [Errno 7] Argument list too long`` — with a 174 KB prompt.
        ``ARG_MAX`` (the ~2 MB total argv+envp budget) is not the binding limit
        here; the per-string cap is, and it does not scale with alert size.

        ORDERING MATTERS: ``--disallowed-tools`` is variadic, so every argv entry
        after it is swallowed as another tool name until the next flag. It must
        therefore never be the last flag. Same rule applies to any variadic flag
        added later.
        """
        agents = {
            agent_name: {
                "description": AGENT_DESCRIPTIONS.get(agent_name, agent_name),
                "prompt": load_prompt(self.package_root, agent_name),
            }
        }
        command = [
            self.options.claude_bin,
            "-p",
            "--disallowed-tools",
            ",".join(DISALLOWED_TOOLS),
            "--agent",
            agent_name,
            "--agents",
            json.dumps(agents),
            "--permission-mode",
            self.options.permission_mode,
        ]
        # In stream mode the runner assembles the final result from the event
        # stream; in blocking mode Claude emits one JSON object. Everything
        # downstream (raw_stdout.txt, parse, output.json) is identical.
        if self._streaming_enabled():
            command += ["--output-format", "stream-json", "--verbose", "--include-partial-messages"]
        else:
            command += ["--output-format", "json"]
        # Isolation. `--settings` only *adds* a source, it does not replace the
        # default set, and with `--setting-sources` omitted the CLI loads all
        # three (user, project, local). So dropping the old `--setting-sources
        # user` widened inheritance instead of removing it, and two things leaked
        # in: the launching machine's ~/.claude settings (results depending on
        # whose laptop started the run — the reason --model is pinned below), and
        # the *analyzed project's own* .claude/settings.json, since agents run
        # with the worktree as cwd. Verified against claude 2.1.220: a probe
        # settings file in the working tree reached the agent's Bash env before
        # this flag and does not after. An explicitly empty list is the only way
        # to load none of them; `--bare` would also drop hooks and OAuth, so it is
        # not usable here. --strict-mcp-config likewise pins MCP to what we pass
        # (nothing) rather than whatever the host has configured.
        command += [
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--json-schema",
            load_schema(self.package_root, agent_name),
            "--add-dir",
            str(run_dir),
            "--settings",
            str(settings_path),
            # Always pinned: with user settings gone there is no implicit default,
            # and the first 30 runs had already drifted across haiku-4-5 (43
            # agents) and sonnet-5 (26) — an uncontrolled variable in an
            # experiment whose whole point is comparing profiles.
            "--model",
            self.options.model or DEFAULT_AGENT_MODEL,
        ]
        if self.options.effort:
            command += ["--effort", self.options.effort]
        return command

    def run(
        self,
        agent_name: str,
        input_markdown: str,
        run_dir: Path,
        worktree_path: Path,
        run_label: Optional[str] = None,
        on_retry_reset: Optional[Callable[[], None]] = None,
    ) -> AgentResult:
        # ``agent_name`` picks the system prompt, schema, and Claude --agent to
        # use; ``run_label`` (when given) names the artifact folder and the
        # recorded result so the same agent can run several times in one run
        # (e.g. per hardening round) without clobbering earlier artifacts.
        #
        # A transient, non-refusal API failure (an output content-filter false
        # positive on defensive code, a dropped connection) exits non-zero just
        # like a crash, but re-rolling the SAME pinned model usually clears it —
        # so it is retried up to ``options.max_api_error_attempts`` instead of
        # killing the run. Each retry uses its own ``<label>_apierr_a<N>`` folder
        # (matching the exploiter-retry convention) so the blocked attempt stays
        # on disk for inspection. ``on_retry_reset`` is called before a re-roll to
        # undo any partial edits the blocked attempt left in the worktree — the
        # content-filter block landed *after* two file edits had been written, and
        # re-invoking on top of them would make the next Edit's old_string fail to
        # match. The model is never swapped (that would confound the experiment);
        # a content-filter retry only appends a minimal-edits note to the task.
        io_name = run_label or agent_name
        budget = max(1, self.options.max_api_error_attempts)
        task = input_markdown
        retries: List[str] = []
        result = self._invoke(agent_name, task, run_dir, worktree_path, io_name)
        for attempt in range(2, budget + 1):
            if result.exit_code == 0 or result.refused:
                break
            transient = detect_transient_api_error(result.raw_stdout)
            if transient is None:
                break
            retries.append(transient)
            if on_retry_reset is not None:
                on_retry_reset()
            if is_content_filter_error(transient):
                task = input_markdown + RETRY_MINIMAL_EDITS_NOTE
            result = self._invoke(
                agent_name, task, run_dir, worktree_path, f"{io_name}_apierr_a{attempt}"
            )
        # Record the retry history on the returned result (empty on the common
        # path) so ``state.json``'s agent entry — and the dashboard — can show it.
        if retries:
            result = replace(result, api_error_attempts=tuple(retries))
        return result

    def _invoke(
        self,
        agent_name: str,
        input_markdown: str,
        run_dir: Path,
        worktree_path: Path,
        io_name: str,
    ) -> AgentResult:
        """One agent invocation: launch the CLI, persist artifacts, parse output."""
        agent_dir = ensure_dir(run_dir / "agent_io" / io_name)
        input_path = write_text(agent_dir / "input.md", input_markdown)
        stdout_path = agent_dir / "raw_stdout.txt"
        stderr_path = agent_dir / "raw_stderr.txt"
        output_path = agent_dir / "output.json"

        settings_path = write_json(
            agent_dir / "settings.json",
            agent_settings(self.package_root, self.options.model),
        )
        command = self.build_command(agent_name, run_dir, settings_path)
        env = self._agent_env()

        if self._streaming_enabled():
            raw_stdout, raw_stderr, exit_code = self._run_streaming(
                command, worktree_path, agent_dir, input_markdown, env
            )
        else:
            raw_stdout, raw_stderr, exit_code = self._run_blocking(command, worktree_path, input_markdown, env)

        write_text(stdout_path, raw_stdout)
        write_text(stderr_path, raw_stderr)

        parsed: JsonDict = {}
        parse_error: Optional[str] = None
        refusal_reason: Optional[str] = None
        recovered_from_stream = False
        if exit_code == 0:
            try:
                parsed = parse_claude_stdout(raw_stdout)
            except ValueError as exc:
                # The final turn had no JSON. Before writing the run off, look
                # for an object the agent emitted earlier (see
                # recover_output_from_stream) — a clean, completed run whose
                # last message happened to be prose is not a failed run.
                recovered = recover_output_from_stream(agent_dir / "stream.jsonl")
                if recovered is None:
                    parse_error = str(exc)
                else:
                    parsed = recovered
                    recovered_from_stream = True
        else:
            parse_error = f"claude exited with code {exit_code}"
            # A refusal also exits non-zero; surface it distinctly from a crash.
            refusal_reason = detect_refusal(raw_stdout)

        output_payload: JsonDict = parsed if parse_error is None else {"parse_error": parse_error}
        if recovered_from_stream:
            # Recorded, never silent: the object did not come from where the
            # contract says it should, and that is worth seeing in the artifact.
            output_payload["recovered_from_stream"] = True
        if refusal_reason is not None:
            output_payload["refused"] = True
            output_payload["refusal_reason"] = refusal_reason
        write_json(output_path, output_payload)
        self._reconcile_provider_cost(agent_dir, env)

        return AgentResult(
            agent_name=io_name,
            parsed_output=parsed,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            exit_code=exit_code,
            input_path=input_path,
            output_path=output_path,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            parse_error=parse_error,
            refused=refusal_reason is not None,
            refusal_reason=refusal_reason,
        )

    def _reconcile_provider_cost(self, agent_dir: Path, env: Optional[dict]) -> None:
        """Persist provider billing metadata without affecting the agent verdict.

        Cost accounting is observability, never a pipeline gate. A transient
        OpenRouter accounting failure therefore leaves an explicit incomplete
        artifact and lets the completed agent continue; the dashboard falls
        back to Claude's reported estimate until a backfill succeeds.
        """
        model = getattr(self.options, "model", None)
        if not is_openrouter_model(model):
            return
        try:
            reconcile_openrouter_agent_dir(
                agent_dir,
                str(model),
                auth_token=(env or {}).get("ANTHROPIC_AUTH_TOKEN"),
            )
        except Exception as exc:
            write_json(
                agent_dir / OPENROUTER_COST_FILENAME,
                {
                    "schema_version": 1,
                    "provider": "openrouter",
                    "model": str(model).strip().lower(),
                    "source": "openrouter_generation_api",
                    "complete": False,
                    "generation_count": 0,
                    "resolved_count": 0,
                    "cost_usd": None,
                    "errors": [{"error": str(exc)[:240]}],
                },
            )

    def _agent_env(self) -> Optional[dict]:
        """Environment for the ``claude`` subprocess.

        ``None`` (inherit) for a Claude model — the historical behaviour. For an
        alternate-provider model the endpoint and credential are injected here,
        and host ``ANTHROPIC_*`` variables are stripped so a machine configured
        for normal Claude use cannot half-authenticate the run.
        """
        if is_zai_model(self.options.model):
            return zai_process_env(self.options.model)
        if is_openrouter_model(self.options.model):
            return openrouter_process_env(self.options.model)
        return None

    def _run_blocking(
        self, command: list, worktree_path: Path, input_markdown: str, env: Optional[dict] = None
    ) -> Tuple[str, str, int]:
        """Original one-shot execution: capture stdout, parse the single JSON object."""
        try:
            completed = subprocess.run(
                command,
                cwd=str(worktree_path),
                env=env,
                input=input_markdown,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.options.agent_timeout_seconds,
                check=False,
            )
            return completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            return (exc.stdout or ""), (exc.stderr or "") + "\nClaude agent timed out.\n", 124

    def _run_streaming(
        self,
        command: list,
        worktree_path: Path,
        agent_dir: Path,
        input_markdown: str,
        env: Optional[dict] = None,
    ) -> Tuple[str, str, int]:
        """Stream stream-json events to stream.jsonl as they arrive; reconstruct
        the blocking-mode stdout from the terminal ``result`` event.

        The event stream carries per-token deltas, tool uses, and turn boundaries
        so a live monitor can follow the agent. The final ``result`` event is
        byte-identical to what ``--output-format json`` returns, so writing it as
        raw_stdout keeps every downstream parser (parse_claude_stdout, cost/token
        metadata) working unchanged. stderr is redirected straight to a file to
        avoid a pipe-buffer deadlock while we read stdout line by line.
        """
        stream_path = agent_dir / "stream.jsonl"
        stderr_path = agent_dir / "raw_stderr.txt"
        result_event: Optional[JsonDict] = None
        timed_out = {"value": False}

        with open(stderr_path, "w", encoding="utf-8") as stderr_fh, open(
            stream_path, "w", encoding="utf-8"
        ) as stream_fh:
            proc = subprocess.Popen(
                command,
                cwd=str(worktree_path),
                env=env,
                stdout=subprocess.PIPE,
                stderr=stderr_fh,
                stdin=subprocess.PIPE,
                text=True,
                errors="replace",
                bufsize=1,
            )

            def _feed_stdin() -> None:
                # Off the main thread: a prompt bigger than the pipe buffer would
                # otherwise deadlock against the stdout-reading loop below (write
                # blocks on a full pipe while the child blocks on a full stdout
                # pipe waiting for us to read).
                try:
                    assert proc.stdin is not None
                    proc.stdin.write(input_markdown)
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        assert proc.stdin is not None
                        proc.stdin.close()
                    except OSError:
                        pass

            feeder = threading.Thread(target=_feed_stdin, daemon=True)
            feeder.start()

            def _kill() -> None:
                timed_out["value"] = True
                proc.kill()

            timer = threading.Timer(self.options.agent_timeout_seconds, _kill)
            timer.start()
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    stream_fh.write(line + "\n")
                    stream_fh.flush()  # let the watcher see it immediately
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict) and event.get("type") == "result":
                        result_event = event
                proc.wait()
            finally:
                timer.cancel()
                feeder.join(timeout=5)

        exit_code = 124 if timed_out["value"] else (proc.returncode or 0)
        raw_stderr = read_text(stderr_path) if stderr_path.exists() else ""
        if timed_out["value"]:
            raw_stderr += "\nClaude agent timed out.\n"
        # Prefer the terminal result event; fall back to the raw stream on a crash
        # that never produced one (the file still holds whatever did arrive).
        raw_stdout = json.dumps(result_event) if result_event is not None else read_text(stream_path)
        return raw_stdout, raw_stderr, exit_code
