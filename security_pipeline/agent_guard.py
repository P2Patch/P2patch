#!/usr/bin/env python3
"""PreToolUse hook: block the Bash habits that dominate agent wall time.

Prompt text alone did not hold. Across the first 30 runs the agents ran
``mvn clean`` 44 times (both prompts forbid it in bold), backgrounded builds
and then blocked on ``tail -f`` for 280s at a stretch (18.5 min of dead time),
and re-ran the full project test suite 103 times on top of the pipeline's own
regression gate. This hook enforces those rules mechanically.

Wired up by ``claude_agents.ClaudeAgentRunner`` via a generated ``--settings``
file, and invoked as ``python3 <this file>`` so it needs no package import.
Contract: hook JSON on stdin; exit 0 to allow, exit 2 to block with the reason
on stderr (which Claude reads and acts on).
"""

from __future__ import annotations

import json
import re
import sys

# (pattern, why, what to do instead) — the message is written for the agent.
RULES = [
    (
        re.compile(r"\b(?:mvn|mvnw|\./mvnw|gradle|gradlew|\./gradlew)\b[^|;&]*\bclean\b"),
        "`clean` is forbidden in this worktree.",
        "Build output persists between commands here, so every build after the first is "
        "incremental; `clean` throws that away and makes each one start from scratch "
        "(minutes per build on a multi-module project). Re-run the same command without "
        "`clean`. If you truly hit a stale-artifact problem, delete just the one stale "
        "path instead.",
    ),
    (
        re.compile(r"\btail\s+-[a-zA-Z]*f\b"),
        "`tail -f` is forbidden.",
        "You are a single-shot agent; following a log just blocks you until the timeout. "
        "Run the command in the foreground and read its output when it finishes.",
    ),
    (
        re.compile(r"\bwhile\s+(?:true|:)\b|\buntil\s+\["),
        "Polling loops are forbidden.",
        "Run the command in the foreground and read its output when it finishes.",
    ),
]

SLEEP_RE = re.compile(r"\bsleep\s+(\d+)")
# `sleep N` under this many seconds is ordinary (waiting for a server to bind).
SLEEP_ALLOWANCE_SECONDS = 15

# --- Network egress -------------------------------------------------------
#
# Agents must not reach the internet: the CVE is redacted from them and the
# WebSearch/WebFetch tools are banned precisely so an exploiter cannot read its
# way to the advisory and the official fix commit (which also contaminates the
# fixPOV / residual POV scores derived from that advisory). But agents
# route around the tool ban with `curl`/`git fetch`/`urllib` in Bash. The
# containers are cut off from the network (see docker_runner.AGENT_NETWORK_ENV);
# this rule is the readable second layer, giving the agent a reason instead of
# an opaque "network unreachable" — and it also covers a command the agent runs
# on the host rather than inside the container. Loopback is allowed: an
# HTTP-server POV legitimately drives itself with `curl localhost:8080/...`.

# A host token that is local — never blocked.
_LOCAL_HOST_RE = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|\[::1\]|host\.docker\.internal)$",
    re.IGNORECASE,
)
# http(s) URLs and scp/ssh-style `user@host` targets.
_URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)", re.IGNORECASE)
_SSH_HOST_RE = re.compile(r"\b[A-Za-z0-9._\-]+@([A-Za-z0-9.\-]+)")
# Fetch verbs that reference an explicit host in a URL / user@host form
# (blocked only for a remote host).
_HOST_FETCH_RE = re.compile(r"\b(curl|wget|scp|ssh)\b")
# Raw-socket tools take a bare `HOST PORT`; capture the host so loopback and
# listen mode (`nc -l PORT`, which has no host) stay allowed.
_SOCKET_HOST_RE = re.compile(
    r"\b(?:nc|ncat|netcat|telnet)\s+(?:-\S+\s+)*([A-Za-z0-9][A-Za-z0-9.\-]*)\s+\d+"
)
# Verbs that are remote by nature — blocked regardless of any parsed host.
_ALWAYS_REMOTE_RE = re.compile(
    r"git\s+(clone|fetch|pull|ls-remote)\b"
    r"|\b(pip|pip3)\s+install\b"
    r"|\bnpm\s+(install|i|ci|add)\b"
    r"|\byarn\s+add\b"
    r"|\bgo\s+get\b"
    r"|\bcargo\s+(add|install)\b"
    r"|urllib\.request|urlopen|requests\.(get|post|put|head|request)"
    r"|http\.client|httpx\.|urllib3|socket\.create_connection"
)

_EGRESS_GUIDANCE = (
    "Network egress is forbidden for pipeline agents. Work only from the source "
    "in this worktree; do not fetch advisories, upstream repositories, package "
    "registries, or the fix commit. (Loopback like localhost:PORT is allowed for "
    "driving a POV against a locally-run server.)"
)


def _remote_hosts(command: str) -> list:
    """Non-local hosts an explicit-host verb references in ``command``."""
    hosts = (
        _URL_HOST_RE.findall(command)
        + _SSH_HOST_RE.findall(command)
        + _SOCKET_HOST_RE.findall(command)
    )
    return [h for h in hosts if not _LOCAL_HOST_RE.match(h)]


def egress_reason(command: str) -> str:
    """Block reason if the command reaches the network, else ""."""
    if _ALWAYS_REMOTE_RE.search(command):
        return _EGRESS_GUIDANCE
    if (_HOST_FETCH_RE.search(command) or _SOCKET_HOST_RE.search(command)) and _remote_hosts(command):
        return _EGRESS_GUIDANCE
    return ""


def check(tool_name: str, tool_input: dict) -> str:
    """The reason this call must be blocked, or "" to allow it."""
    if tool_name != "Bash":
        return ""

    if tool_input.get("run_in_background"):
        return (
            "Background Bash is forbidden. You are a single-shot agent with nothing else "
            "to do while a build runs, and backgrounding it only leads to polling the log. "
            "Run the command in the foreground with an adequate `timeout` instead."
        )

    command = str(tool_input.get("command") or "")
    for pattern, headline, guidance in RULES:
        if pattern.search(command):
            return f"{headline} {guidance}"

    egress = egress_reason(command)
    if egress:
        return egress

    longest_sleep = max(
        (int(seconds) for seconds in SLEEP_RE.findall(command)), default=0
    )
    if longest_sleep > SLEEP_ALLOWANCE_SECONDS:
        return (
            f"`sleep {longest_sleep}` is forbidden. Nothing will change while you wait. "
            "Run the command in the foreground instead."
        )
    return ""


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # never break the agent over a malformed hook payload

    reason = check(str(payload.get("tool_name") or ""), payload.get("tool_input") or {})
    if not reason:
        return 0
    print(f"Blocked by the security-pipeline agent guard: {reason}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
