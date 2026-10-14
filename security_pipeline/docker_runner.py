from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Iterator, List, Mapping, Optional, Sequence

from .env import get_env
from .logging_io import ensure_dir, write_text
from .models import CommandResult, ProjectMetadata

# Build for the HOST's native architecture by default (arm64 host -> linux/arm64,
# amd64 host -> linux/amd64), which avoids Docker emulation entirely.
#
# Why not pin linux/amd64 (the dataset's capture arch)? The CWE-Bench Dockerfiles
# are architecture-agnostic (JDK + Maven/Gradle; the build artifact is JVM
# bytecode, identical across arches), so a native-arch build reproduces the same
# repo without editing any Dockerfile. Meanwhile, emulating amd64 on Apple Silicon
# is slow AND unreliable: amd64 `docker build` steps fall back to QEMU (Rosetta
# only accelerates `docker run`), and QEMU mishandles syscalls GNU tar issues on a
# real tarball, breaking extraction ("tar: ... Cannot ...: Function not
# implemented"). Native-arch sidesteps that, and on an amd64 machine this still
# builds native amd64 exactly as the dataset intends — so teammates on amd64 are
# unaffected and it generalizes to any future alert with no per-project config.
#
# The exception is a project needing native amd64 binaries with no aarch64 build
# (e.g. Eclipse SWT / durian-swt): force amd64 for it by exporting
# DOCKER_DEFAULT_PLATFORM=linux/amd64 (an explicit env override always wins, here
# and in the generated wrapper) or run it on an amd64 host/CI.
def host_docker_platform() -> str:
    machine = platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "linux/arm64"
    if machine in ("x86_64", "amd64", "x64"):
        return "linux/amd64"
    return ""  # unknown arch: let the docker daemon pick its native default


DEFAULT_DOCKER_PLATFORM = host_docker_platform()

# Build steps commonly fetch over the network (171/189 dataset Dockerfiles wget
# Maven from archive.apache.org; all git clone). Those fetches fail transiently
# (connection refused/reset, DNS, TLS timeout) — antisamy was rejected once this
# way then passed on a plain re-run. Retry the build a bounded number of times,
# but ONLY when the log shows a network signature: a deterministic failure
# (compile error, arch mismatch) must fail fast, not loop.
BUILD_MAX_ATTEMPTS = 3
BUILD_RETRY_BACKOFF_SECONDS = 5

_NETWORK_ERROR_PATTERN = re.compile(
    r"connection refused|connection reset|could not resolve|"
    r"temporary failure in name resolution|network is unreachable|"
    r"tls handshake timeout|failed to fetch|error downloading|"
    r"could not connect|unable to access|early eof|i/o timeout|"
    r"failed to do request|503 service unavailable|dial tcp",
    re.IGNORECASE,
)


def looks_like_network_error(text: str) -> bool:
    return bool(_NETWORK_ERROR_PATTERN.search(text or ""))


_UNSAFE_LOG_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def _env_args(env_overrides: Optional[Mapping[str, str]]) -> List[str]:
    """``-e K=V`` pairs for a docker run/exec argv (empty when nothing is set)."""
    if not env_overrides:
        return []
    args: List[str] = []
    for key, value in sorted(env_overrides.items()):
        args += ["-e", f"{key}={value}"]
    return args


# Agents run their own Bash inside these containers (POV commands the exploiter
# authors, the tree the patcher edits, and the `run_in_docker.sh` wrapper the
# agent drives directly). By default that container had full internet, and
# agents used it to `curl` the GitHub advisory / official fix commit — which is
# exactly what the CVE redaction and the WebSearch/WebFetch tool bans exist to
# prevent, and it contaminates the fixPOV / residual POV scores derived
# from the same advisory. So agent-facing containers are cut off from the
# network by default. The image is built (deps fetched) at `docker build` time,
# which is untouched, so incremental agent builds run offline against the
# cached ~/.m2 etc.; a build that genuinely must fetch at agent-time can opt a
# Docker image names the pipeline builds, one per project+Dockerfile hash. The
# prefix was ``simpleautosec-`` before the project was renamed to P2Patch;
# images built under the old prefix are still recognised where the pipeline
# *reads* images back (see LEGACY_IMAGE_PREFIX), because the docker layer cache
# and any leftover images on a run host are named with whatever prefix was in
# effect when they were built.
IMAGE_PREFIX = "p2patch-"
LEGACY_IMAGE_PREFIX = "simpleautosec-"

# project back in with P2PATCH_AGENT_NETWORK (a docker network name, or
# "bridge"/"default"/"host"; empty or "none" == isolated).
AGENT_NETWORK_ENV = "P2PATCH_AGENT_NETWORK"


def agent_network_policy() -> str:
    """The docker network for agent-facing containers ("none" == isolated)."""
    value = (get_env(AGENT_NETWORK_ENV) or "").strip()
    # "default" is not a real docker network name; treat it (and "bridge") as
    # "let docker use its default network" == opt back into full connectivity.
    if value.lower() in ("bridge", "default"):
        return "bridge"
    return value or "none"


# The isolation above is about *agents*, and only agents: it exists so an agent
# cannot Bash its way to the advisory and the official fix. Containers that run
# no agent must not inherit it. The evaluation families (fixPOV, residual)
# stage a curated POV tree and build it with commands from a checked-in
# manifest, and their staging legitimately fetches -- `mvn
# dependency:build-classpath` and `mvn install` pull plugins the project's own
# `package` never used (so they are absent from the image's ~/.m2), and the
# coreutils harness clones gnulib. Under `--network none` all of that failed
# name resolution, and because a staging failure records every POV as `errored`
# with a null score (correctly -- a POV exiting non-zero because nothing built
# is not a blocked exploit), four hardening runs lost their fixPOV and
# residual scores entirely. Nothing is leaked by giving these containers the
# network: the agents are finished and gone, the commands are ours, and the
# stage already had the official fix on disk.
EVAL_NETWORK_ENV = "P2PATCH_EVAL_NETWORK"

# Sentinel for "this runner is not agent-facing"; see DockerRunner(network=...).
EVALUATION_NETWORK = "__evaluation__"


def evaluation_network_policy() -> str:
    """The docker network for evaluation containers (unrestricted by default)."""
    value = (get_env(EVAL_NETWORK_ENV) or "").strip()
    if value.lower() in ("bridge", "default"):
        return "bridge"
    return value or "bridge"


def _network_args(policy: str) -> List[str]:
    """``--network`` argv for a `docker run` (may be empty)."""
    if policy == EVALUATION_NETWORK:
        policy = evaluation_network_policy()
    if policy == "bridge":
        # Docker's out-of-the-box default; passing it is a no-op but explicit.
        return ["--network", "bridge"]
    return ["--network", policy]


# Applied to the run's own PoV and regression commands, and to nothing else.
#
# LeakSanitizer runs at exit under ASan and reports a leak by exiting non-zero,
# which a PoV harness cannot distinguish from the crash it is actually testing
# for. A memory leak is essentially never the CWE under test, but it is enough
# to keep a PoV "reproducing" forever: one binutils dwarf1 run had its real
# CWE-125 fixed on the first attempt, then burned its whole correction budget on
# an unrelated 28-byte leak in the same harness and was rejected.
#
# Deliberately NOT applied to the fixPOV or residual evaluators: those
# PoVs are certified against a recorded content hash and exit-code contract, and
# silently changing the sanitizer environment underneath them would move scores
# without invalidating the certification that vouches for them.
POV_SANITIZER_ENV = {"ASAN_OPTIONS": "detect_leaks=0"}


class DockerError(RuntimeError):
    pass


def sanitize_docker_component(value: str) -> str:
    safe = re.sub(r"[^a-z0-9_.-]+", "-", value.lower())
    safe = safe.strip(".-_")
    return safe or "project"


def dockerfile_hash(dockerfile_path: Path) -> str:
    return hashlib.sha256(dockerfile_path.read_bytes()).hexdigest()[:12]


class DockerRunner:
    def __init__(
        self,
        project: ProjectMetadata,
        worktree_path: Path,
        run_dir: Path,
        image_key: Optional[str] = None,
        network: Optional[str] = None,
    ) -> None:
        # None == agent-facing: read the isolation policy from the environment.
        # EVALUATION_NETWORK marks a container no agent ever touches (the
        # fixPOV / residual evaluators, and the offline drivers that only
        # run curated POVs: fixpov/respov validate and replay, reverify), which
        # stays connected so POV staging can still fetch. `retrofit` is NOT one
        # of those -- it drives the verifier agent and replays agent-authored
        # regression commands -- so it keeps the agent policy. Resolved lazily
        # in _network_args so the env is read at `docker run` time, as before.
        self.network_policy = network
        self.project = project
        self.worktree_path = worktree_path
        self.run_dir = run_dir
        self.docker_log_dir = ensure_dir(run_dir / "docker")
        # Per-project override (build_info.csv's docker_platform column) wins
        # over the host-native default -- see ProjectMetadata.docker_platform.
        self.platform = project.docker_platform or DEFAULT_DOCKER_PLATFORM
        self.image_tag = (
            f"{IMAGE_PREFIX}{sanitize_docker_component(image_key or project.project_slug)}:"
            f"{dockerfile_hash(project.dockerfile_path)}"
        )
        self.redactions = [
            project.cve_id,
            project.project_slug,
            str(project.source_path),
            str(project.dockerfile_path),
            str(project.dockerfile_path.parent),
            project.buggy_commit_id,
            project.fix_commit_ids,
        ]
        # When inside a `session()`, project commands run via `docker exec` on this
        # kept-alive container instead of a fresh `docker run --rm` each time. This
        # amortizes container startup and keeps the container's ~/.m2 (plugin
        # downloads) and the mounted target/ warm across every POV in the checkout.
        # None means "no session" → the original per-command `docker run --rm`.
        self._session_container: Optional[str] = None
        # Lazily probed from the image; see image_build_outputs().
        self._build_outputs: Optional[frozenset] = None

    def for_checkout(self, checkout_path: Path) -> "DockerRunner":
        """A runner for the same image and run, mounted on a different checkout.

        Used by the regression gate to replay a failing test command against a
        pristine pre-patch export of the tree. The image tag is copied rather than
        recomputed so the replay cannot accidentally target a different (or
        unbuilt) image than the run itself.
        """
        clone = DockerRunner(
            self.project, checkout_path, self.run_dir, network=self.network_policy
        )
        clone.image_tag = self.image_tag
        return clone

    def for_evaluation(self, checkout_path: Optional[Path] = None) -> "DockerRunner":
        """A runner for the same image whose container is not agent-facing.

        Used by the fixPOV and residual eval stages, which run curated
        POVs after every agent has exited. They keep the network the agents were
        cut off from, because their staging builds fetch (see EVAL_NETWORK_ENV).
        """
        clone = DockerRunner(
            self.project,
            checkout_path or self.worktree_path,
            self.run_dir,
            network=EVALUATION_NETWORK,
        )
        clone.image_tag = self.image_tag
        return clone

    def _network_args(self) -> List[str]:
        return _network_args(
            self.network_policy
            if self.network_policy is not None
            else agent_network_policy()
        )

    def build_args(self) -> List[str]:
        return [
            "docker",
            "build",
            "--target",
            "builder",
            "-f",
            str(self.project.dockerfile_path),
            "-t",
            self.image_tag,
            str(self.project.dockerfile_path.parent),
        ]

    def command_args(
        self, shell_command: str, env_overrides: Optional[Mapping[str, str]] = None
    ) -> List[str]:
        return [
            "docker",
            "run",
            "--rm",
            *self._network_args(),
            "-v",
            f"{self.worktree_path}:/workspace/repo",
            *_env_args(env_overrides),
            "-w",
            "/workspace/repo",
            self.image_tag,
            "bash",
            "-lc",
            shell_command,
        ]

    def log_path_for(self, name: str) -> Path:
        """Log file for a command, kept inside ``docker/`` whatever the name is.

        Most command names are literals from this package, but the fixPOV
        evaluator builds them from manifest POV ids (``fixpov_<id>``), and nothing
        stopped an id containing ``../`` from landing the log outside the run's
        docker directory. Names are sanitized here rather than at each call site
        so the containment holds for any future caller too.
        """
        safe = _UNSAFE_LOG_CHARS.sub("_", name).strip("._-") or "command"
        return self.docker_log_dir / f"{safe}.log"

    def _run(self, name: str, command: Sequence[str], timeout_seconds: Optional[int]) -> CommandResult:
        log_path = self.log_path_for(name)
        env = os.environ.copy()
        # Project override (self.platform) or host-native platform; an explicit
        # process env override always wins over both. Skip entirely on an
        # unknown arch so we never pin an empty platform.
        if self.platform:
            env.setdefault("DOCKER_DEFAULT_PLATFORM", self.platform)
        try:
            completed = subprocess.run(
                list(command),
                cwd=str(self.run_dir),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout_seconds,
                check=False,
                env=env,
            )
            result = CommandResult(
                name=name,
                command=[self._redact(item) for item in command],
                exit_code=completed.returncode,
                stdout=self._redact(completed.stdout),
                stderr=self._redact(completed.stderr),
                log_path=log_path,
            )
        except subprocess.TimeoutExpired as exc:
            # CPython quirk: TimeoutExpired.stdout/.stderr can be raw bytes even
            # when the command was run with text=True — communicate() populates
            # them from its internal buffer before the text-decoding wrapper
            # applies, on the timeout path specifically. _redact() (below) assumes
            # str, so an undecoded bytes value here used to raise "a bytes-like
            # object is required, not 'str'" and crash the whole gate instead of
            # recording an honest timeout.
            def _as_text(value: object) -> str:
                if isinstance(value, bytes):
                    return value.decode("utf-8", errors="replace")
                return value or ""

            result = CommandResult(
                name=name,
                command=[self._redact(item) for item in command],
                exit_code=124,
                stdout=self._redact(_as_text(exc.stdout)),
                stderr=self._redact(_as_text(exc.stderr)),
                log_path=log_path,
                timed_out=True,
            )
        write_text(log_path, format_command_log(result))
        return result

    def _redact(self, value: str) -> str:
        redacted = value
        for sensitive in self.redactions:
            if sensitive:
                redacted = redacted.replace(sensitive, "[redacted]")
        return redacted

    def reclaim_ownership(self) -> None:
        """Hand worktree files a build container wrote as root back to the
        invoking host user.

        Every project container runs as root (Dockerfiles have no ``USER``;
        Maven/Gradle need root's ``~/.m2``/``~/.gradle``), so build output the
        container writes into the bind-mounted worktree (``target/``,
        ``build/``, ``.gradle/``) lands root-owned on the host. The dashboard
        backend runs unprivileged (``p2patch-dashboard.service``, formerly
        ``autosec-dashboard.service``), so those
        files silently block it from ever deleting the run directory later —
        ``shutil.rmtree(..., ignore_errors=True)`` swallows the permission
        error and the run just can't be removed. Reclaiming ownership once,
        after the run's containers are done with the worktree, means nothing
        root-owned survives into the artifact the dashboard manages. Best
        effort: a project whose image was never built has nothing to reclaim,
        and a chown that fails leaves the pre-existing (broken) delete path
        as a fallback rather than failing the run over a cleanup step.
        """
        if not self.worktree_path.exists():
            return
        uid, gid = os.getuid(), os.getgid()
        with contextlib.suppress(subprocess.SubprocessError, OSError):
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{self.worktree_path}:/workspace/repo",
                    self.image_tag,
                    "chown",
                    "-R",
                    f"{uid}:{gid}",
                    "/workspace/repo",
                ],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=120,
                check=False,
            )

    def image_build_outputs(self) -> frozenset:
        """Paths this project's own image build leaves untracked in the repo.

        The product-source guard has to tell "the build made this" from "the
        exploiter authored this", and its only signal was git: a path git does
        not ignore and does not track is treated as the agent's work and
        deleted. That holds for Maven (``target/`` is always ignored) and breaks
        completely for the old autotools C projects, which ship no ``.gitignore``
        at all -- every object file, ``Makefile``, ``config.status`` and built
        tool reads as agent-authored. On libtiff it deleted 184 of them,
        including the ``tools/tiffcrop`` the exploiter had *just* used to prove
        the CVE reproduces, so the harness re-ran a binary that no longer existed
        and the run was rejected for "not reproducing" three attempts running.

        The image is the answer to the question git cannot answer: it is built
        by running this project's own build, so whatever git calls untracked
        inside it is by definition build output. Derived once per DockerRunner
        and cached; a failure yields the empty set, which is exactly the old
        behaviour.
        """
        if self._build_outputs is None:
            self._build_outputs = self._probe_build_outputs()
        return self._build_outputs

    def _probe_build_outputs(self) -> frozenset:
        probe = self._run(
            "build_output_probe",
            [
                "docker", "run", "--rm", "--entrypoint", "bash", self.image_tag,
                "-lc", "cd /workspace/repo && git status --porcelain",
            ],
            120,
        )
        if not probe.ok:
            return frozenset()
        # Same porcelain shape the worktree guard parses, so the two agree on
        # granularity: a wholly-untracked directory collapses to one `dir/`
        # entry, a partly-tracked one lists its files.
        return frozenset(
            line[3:].strip()
            for line in probe.stdout.splitlines()
            if line.startswith("?? ") and line[3:].strip()
        )

    def build_image(
        self, timeout_seconds: Optional[int], attempts: int = BUILD_MAX_ATTEMPTS
    ) -> CommandResult:
        result = self._run("docker_build", self.build_args(), timeout_seconds)
        attempt = 1
        # Retry only transient network failures; a timeout or a deterministic
        # build error (compile/config) is not worth re-running. docker_build.log
        # is overwritten each attempt, so it always reflects the final outcome.
        while (
            not result.ok
            and not result.timed_out
            and attempt < attempts
            and looks_like_network_error(f"{result.stdout}\n{result.stderr}")
        ):
            time.sleep(BUILD_RETRY_BACKOFF_SECONDS * attempt)
            attempt += 1
            result = self._run("docker_build", self.build_args(), timeout_seconds)
        return result

    def run_project_command(
        self,
        shell_command: str,
        name: str,
        timeout_seconds: Optional[int],
        env_overrides: Optional[Mapping[str, str]] = None,
    ) -> CommandResult:
        if self._session_container:
            return self._run(name, self.exec_args(shell_command, env_overrides), timeout_seconds)
        return self._run(name, self.command_args(shell_command, env_overrides), timeout_seconds)

    def exec_args(
        self, shell_command: str, env_overrides: Optional[Mapping[str, str]] = None
    ) -> List[str]:
        """`docker exec` argv for the current session container (mirrors
        ``command_args``' ``bash -lc`` shape so a command behaves identically
        whether it runs via `docker run` or `docker exec`)."""
        return [
            "docker",
            "exec",
            *_env_args(env_overrides),
            "-w",
            "/workspace/repo",
            str(self._session_container),
            "bash",
            "-lc",
            shell_command,
        ]

    @contextlib.contextmanager
    def session(self) -> Iterator[bool]:
        """Keep one container alive for the duration of the block so every
        ``run_project_command`` runs via `docker exec` instead of a fresh
        `docker run --rm`. Yields True when a persistent container is active,
        False when startup failed and we transparently fell back to per-command
        `docker run --rm` (so the caller never has to special-case failure).

        The container is always removed on exit, including on exceptions.
        """
        container = self._start_session()
        if container is None:
            # Transparent fallback: behave exactly like the old per-command path.
            yield False
            return
        self._session_container = container
        try:
            yield True
        finally:
            self._session_container = None
            self._stop_session(container)

    def _start_session(self) -> Optional[str]:
        argv = [
            "docker",
            "run",
            "-d",
            "--rm",
            *self._network_args(),
            "-v",
            f"{self.worktree_path}:/workspace/repo",
            "-w",
            "/workspace/repo",
            self.image_tag,
            "sleep",
            "infinity",
        ]
        env = os.environ.copy()
        if self.platform:
            env.setdefault("DOCKER_DEFAULT_PLATFORM", self.platform)
        try:
            completed = subprocess.run(
                argv, cwd=str(self.run_dir), capture_output=True, text=True,
                errors="replace", timeout=120, check=False, env=env,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if completed.returncode != 0:
            return None
        container = (completed.stdout or "").strip().splitlines()
        return container[-1].strip() if container and container[-1].strip() else None

    def _stop_session(self, container: str) -> None:
        with contextlib.suppress(subprocess.SubprocessError, OSError):
            subprocess.run(
                ["docker", "rm", "-f", container],
                capture_output=True, text=True, errors="replace", timeout=60, check=False,
            )

    def write_wrapper(self) -> Path:
        path = self.run_dir / "run_in_docker.sh"
        # Inherit the project override or host-native default but let an
        # external env override win. On an unknown arch (empty default) and no
        # project override, don't export a platform at all.
        platform_line = (
            f'export DOCKER_DEFAULT_PLATFORM="${{DOCKER_DEFAULT_PLATFORM:-{self.platform}}}"'
            if self.platform
            else "# host-native platform (no DOCKER_DEFAULT_PLATFORM pin)"
        )
        # Agents drive this wrapper directly, so it carries the same network
        # isolation as command_args()/_start_session(). Resolved at generation
        # time from the same helper (env is stable for a run), and emitted only
        # when a policy applies so the flag order matches the argv builders.
        network_args = self._network_args()
        network_line = (
            f"  {network_args[0]} {network_args[1]} \\\n" if network_args else ""
        )
        content = f"""#!/usr/bin/env bash
set -euo pipefail
{platform_line}
if [ "$#" -lt 1 ]; then
  echo "usage: $0 '<command to run inside /workspace/repo>'" >&2
  exit 2
fi
docker run --rm \\
{network_line}  -v "{self.worktree_path}:/workspace/repo" \\
  -w /workspace/repo \\
  "{self.image_tag}" \\
  bash -lc "$*"
"""
        write_text(path, content)
        path.chmod(0o755)
        return path


def format_command_log(result: CommandResult) -> str:
    command = " ".join(result.command)
    return (
        f"$ {command}\n"
        f"exit_code={result.exit_code}\n"
        f"timed_out={str(result.timed_out).lower()}\n\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}\n"
    )
