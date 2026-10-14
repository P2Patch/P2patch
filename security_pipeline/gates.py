from __future__ import annotations

from pathlib import Path
from typing import List, Mapping, Sequence

from .models import JsonDict
from .workspace import is_relative_to


class GateError(RuntimeError):
    pass


def normalize_path_text(candidate: str) -> str:
    cleaned = candidate.strip().strip("`'\"")
    if "\n" in cleaned:
        cleaned = cleaned.splitlines()[0].strip()
    for marker in (" (", "\t", "  "):
        if marker in cleaned:
            cleaned = cleaned.split(marker, 1)[0].strip()
    return cleaned.strip().strip("`'\"")


def normalize_shell_command(command: str) -> str:
    return " ".join(command.strip().split())


def filter_duplicate_pov_commands(commands: Sequence[str], pov_command: str) -> List[str]:
    pov = normalize_shell_command(pov_command)
    return [command for command in commands if normalize_shell_command(command) != pov]


# docker_runner.py mounts worktree_path at this path inside the project
# container. Agent prompts drill hard on using it for *commands* (which do run
# inside the container), and agents sometimes echo the same prefix back for a
# *file path* (which the orchestrator resolves on the host) instead of a
# worktree-relative path. Treat that one well-known prefix as worktree-relative
# rather than rejecting it as outside the worktree.
CONTAINER_WORKTREE_PREFIX = "/workspace/repo"


def resolve_worktree_path(worktree_path: Path, candidate: str) -> Path:
    candidate = normalize_path_text(candidate)
    if not candidate:
        raise GateError("Missing path")
    raw = Path(candidate)
    if raw.is_absolute():
        try:
            raw = raw.relative_to(CONTAINER_WORKTREE_PREFIX)
        except ValueError:
            pass
    resolved = raw if raw.is_absolute() else worktree_path / raw
    if not is_relative_to(resolved, worktree_path):
        raise GateError(f"Path is outside the worktree: {candidate}")
    return resolved


def validate_exploiter_output(output: Mapping[str, object], worktree_path: Path) -> JsonDict:
    status = str(output.get("status", ""))
    if status != "pov_created":
        raise GateError(f"Exploiter did not create a POV: status={status!r}")

    pov_command = str(output.get("pov_command", "")).strip()
    if not pov_command:
        raise GateError("Exploiter output is missing pov_command")

    pov_path_text = str(output.get("pov_path", "")).strip()
    pov_path = resolve_worktree_path(worktree_path, pov_path_text)
    pov_root = worktree_path / ".security-pipeline" / "pov"
    if not is_relative_to(pov_path, pov_root):
        raise GateError("POV must be under .security-pipeline/pov")
    if not pov_path.exists():
        raise GateError(f"POV path does not exist: {pov_path}")

    return {"pov_path": str(pov_path), "pov_command": pov_command}


def validate_patcher_output(output: Mapping[str, object]) -> List[str]:
    status = str(output.get("status", ""))
    if status != "patched":
        raise GateError(f"Patcher did not produce a patch: status={status!r}")
    commands = output.get("regression_commands", [])
    if commands is None:
        return []
    if not isinstance(commands, list) or not all(isinstance(item, str) for item in commands):
        raise GateError("regression_commands must be a list of strings")
    return [item.strip() for item in commands if item.strip()]


def validate_verifier_output(output: Mapping[str, object]) -> None:
    verdict = str(output.get("verdict", ""))
    if verdict != "accepted":
        raise GateError(f"Verifier rejected the patch: verdict={verdict!r}")


def all_commands_succeeded(exit_codes: Sequence[int]) -> bool:
    return all(code == 0 for code in exit_codes)
