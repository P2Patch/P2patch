from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .models import CommandResult

# Regenerated build output under a PoV tree, as opposed to hand-authored PoV
# source. The PoV integrity guard must ignore all of it: running the PoV is how
# the patcher self-verifies its fix, and every run recompiles, so these files
# legitimately change byte-for-byte while the PoV itself is untouched.
#
# Two shapes occur in practice and both must be covered:
#   - output in a dedicated directory (`run_pov.sh` does `rm -rf classes && javac
#     -d classes ...`)                                     -> POV_ARTIFACT_DIRS
#   - output dropped beside the source, because `javac Pov.java` with no `-d`
#     writes `Pov.class` into the PoV root and `javac -d . pkg/Pov.java` writes
#     it into a package subdirectory                   -> POV_ARTIFACT_SUFFIXES
# Only the directory case was excluded originally, so a patcher that merely
# re-ran the PoV to check its own fix was reported as having tampered with it.
POV_ARTIFACT_DIRS = frozenset(
    {"classes", "work", "target", "build", "out", "bin", ".gradle", "__pycache__", "node_modules"}
)
POV_ARTIFACT_SUFFIXES = frozenset(
    {
        ".class", ".jar", ".war", ".ear", ".o", ".obj", ".a", ".so", ".dylib", ".dll", ".exe",
        ".pyc", ".pyo", ".log",
    }
)

# ...and a third shape the suffix list cannot express: a compiled C/C++ PoV
# harness. `.exe` is in the list, but that is the *Windows* convention — the
# Linux one is no extension at all (`gcc -o pov pov.c`, `pov`, `test_dwarf`),
# so those binaries were snapshotted as if they were hand-authored PoV source
# and force-restored after every patcher run. The patcher recompiles the
# harness against its fix to self-verify, the guard reverts it to the build
# linked against *unpatched* product code, and the gate then re-runs that
# stale binary and reports the vulnerability still reproducing — no patch,
# however correct, could ever pass. Cost two runs their verdicts
# (libjpeg-turbo CWE-476, binutils dwarf2 CWE-369), both with a correct fix.
#
# Detected by leading magic bytes rather than by name, so a hand-written
# `run_pov` script with no extension stays protected (it starts with `#!` or
# text, not a magic number).
#
# The executable bit is required as well, and that is the load-bearing half:
# a *crafted ELF input* is exactly what several PoVs feed to the target
# (binutils' malformed object files), it also starts with \x7fELF, and it must
# stay protected — a patcher that edits the exploit input into something benign
# would otherwise walk the gate. Exploit inputs are written 0644; a compiled
# harness is 0755. Note this is strictly more conservative than the suffix list
# above, which already exempts `.so`/`.exe` unconditionally regardless of mode.
_ELF_MAGIC = b"\x7fELF"
_PE_MAGIC = b"MZ"
_MACH_O_MAGICS = frozenset(
    {
        b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
        b"\xce\xfa\xed\xfe",  # 32-bit little-endian
        b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
        b"\xfe\xed\xfa\xce",  # 32-bit big-endian
        b"\xca\xfe\xba\xbe",  # universal ("fat") archive
    }
)

# Snapshot entry kinds. A symlink is recorded by its *target*, never by the bytes
# it points at: dereferencing here let a link planted inside the PoV tree
# (`pov/alias.java -> ../../src/Main.java`) be snapshotted as the product file
# and then written back over it, silently reverting the patcher's own fix and
# leaving the run stuck failing the PoV-after gate it could no longer pass.
ENTRY_FILE = "file"
ENTRY_LINK = "link"

# rel path -> (kind, permission bits, payload) for every hand-authored PoV entry.
# payload is the file contents for ENTRY_FILE and the raw link target for
# ENTRY_LINK.
TreeEntry = Tuple[str, int, bytes]
TreeSnapshot = Dict[str, TreeEntry]


class WorkspaceError(RuntimeError):
    pass


def run_local_command(
    name: str,
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: Optional[int] = None,
    preserve_newlines: bool = False,
) -> CommandResult:
    """Run a local command and capture its output as text.

    ``preserve_newlines`` decodes the raw bytes instead of letting
    ``subprocess`` do it. ``text=True`` implies **universal newlines**, which
    silently rewrites every CRLF in the output to LF — for a diff that is
    destructive, not cosmetic: zip4j's sources are CRLF, so its recorded
    ``patch_only.diff`` came out with LF context lines that no longer matched
    the file, and ``git apply`` rejected the whole patch (measured: 131 CRs
    dropped from a single file's diff). Every caller that captures a diff must
    pass it; the rest read git porcelain, where the translation is harmless.
    """
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            capture_output=True,
            text=not preserve_newlines,
            errors=None if preserve_newlines else "replace",
            timeout=timeout_seconds,
            check=False,
        )
        stdout, stderr = completed.stdout, completed.stderr
        if preserve_newlines:
            # errors="replace" is still applied — the Latin-1 i18n bundles that
            # motivated it (antisamy) must not raise here — but the decode is
            # ours, so CR survives.
            stdout = stdout.decode("utf-8", errors="replace")
            stderr = stderr.decode("utf-8", errors="replace")
        return CommandResult(
            name=name,
            command=list(command),
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
        )
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = exc.stdout or "", exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return CommandResult(
            name=name,
            command=list(command),
            exit_code=124,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )


def create_worktree(
    source_repo: Path,
    run_dir: Path,
    revision: str = "HEAD",
    dirname: str = "worktree",
) -> Path:
    """Export ``revision`` of ``source_repo`` into ``run_dir/dirname`` as its own repo.

    ``revision``/``dirname`` are non-default only for fixPOV replay, which
    reconstructs a run's patched tree from an explicit base commit instead of
    whatever the shared source checkout points at today.
    """
    worktree_path = run_dir / dirname
    run_dir.mkdir(parents=True, exist_ok=True)
    worktree_path.mkdir(parents=True, exist_ok=False)

    archive_path = run_dir / f"{dirname}-source.tar"
    archive = run_local_command(
        "git_archive",
        [
            "git", "-C", str(source_repo), "archive", "--format=tar",
            "-o", str(archive_path), revision,
        ],
        cwd=source_repo,
    )
    if archive.exit_code != 0:
        raise WorkspaceError(f"Failed to export source tree: {archive.stderr or archive.stdout}")

    extract = run_local_command("tar_extract", ["tar", "-xf", str(archive_path), "-C", str(worktree_path)], cwd=run_dir)
    archive_path.unlink(missing_ok=True)
    if extract.exit_code != 0:
        raise WorkspaceError(f"Failed to extract source tree: {extract.stderr or extract.stdout}")

    init = run_local_command("git_init", ["git", "init", "-q"], cwd=worktree_path)
    if init.exit_code != 0:
        raise WorkspaceError(f"Failed to initialize isolated git repo: {init.stderr or init.stdout}")
    add = run_local_command("git_add", ["git", "add", "-A"], cwd=worktree_path)
    if add.exit_code != 0:
        raise WorkspaceError(f"Failed to stage baseline source tree: {add.stderr or add.stdout}")
    commit = run_local_command(
        "git_commit",
        [
            "git",
            "-c",
            "user.name=security-pipeline",
            "-c",
            "user.email=security-pipeline@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "baseline",
        ],
        cwd=worktree_path,
    )
    if commit.exit_code != 0:
        raise WorkspaceError(f"Failed to commit baseline source tree: {commit.stderr or commit.stdout}")
    return worktree_path


def remove_worktree(source_repo: Path, worktree_path: Path) -> None:
    shutil.rmtree(worktree_path, ignore_errors=True)


def has_revision(repo: Path, revision: str) -> bool:
    """Whether ``revision`` is a commit this clone actually has locally.

    The project checkouts are shallow (``fetch_source`` clones ``--depth 1``),
    so a commit named in ``project_info.csv`` is not guaranteed to be present.
    """
    if not revision:
        return False
    result = run_local_command(
        "git_cat_file", ["git", "cat-file", "-e", f"{revision}^{{commit}}"], cwd=repo
    )
    return result.exit_code == 0


def reset_checkout(repo: Path) -> None:
    """Return a reconstruction checkout to its baseline commit.

    Tracked edits are reverted and untracked files removed, but **ignored** files
    are deliberately kept: build output (``target/``) lives there, and throwing it
    away would make every replay in a batch a cold build. That is the same reason
    the agent prompts and ``agent_guard`` forbid ``mvn clean``.
    """
    revert = run_local_command("git_checkout_all", ["git", "checkout", "--", "."], cwd=repo)
    if revert.exit_code != 0:
        raise WorkspaceError(f"Failed to revert checkout: {revert.stderr or revert.stdout}")
    clean = run_local_command("git_clean", ["git", "clean", "-fdq"], cwd=repo)
    if clean.exit_code != 0:
        raise WorkspaceError(f"Failed to clean checkout: {clean.stderr or clean.stdout}")


def apply_patch_file(repo: Path, patch_path: Path) -> CommandResult:
    """Apply a run's recorded diff to a checkout. Returns the result unraised.

    The caller decides what a failure means — for replay it means "this run cannot
    be reconstructed", which is a fallback, not an error.
    """
    return run_local_command(
        "git_apply", ["git", "apply", "--whitespace=nowarn", str(patch_path)], cwd=repo
    )


def git_output(repo: Path, args: Sequence[str], preserve_newlines: bool = False) -> str:
    result = run_local_command(
        "git", ["git", *args], cwd=repo, preserve_newlines=preserve_newlines
    )
    if result.exit_code != 0:
        raise WorkspaceError(result.stderr or result.stdout)
    return result.stdout


def git_status_short(repo: Path) -> str:
    return git_output(repo, ["status", "--short"])


def _matches_prefix(path: str, prefixes: Sequence[str]) -> bool:
    cleaned = path.replace(os.sep, "/")
    return any(cleaned == prefix.rstrip("/") or cleaned.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)


def list_untracked(repo: Path) -> List[str]:
    output = git_output(repo, ["ls-files", "--others", "--exclude-standard"])
    return [line for line in output.splitlines() if line.strip()]


def _diff_pathspecs(
    include_prefixes: Optional[Sequence[str]],
    exclude_prefixes: Sequence[str],
) -> List[str]:
    pathspecs = list(include_prefixes) if include_prefixes else ["."]
    pathspecs.extend(f":(exclude){prefix.rstrip('/')}" for prefix in exclude_prefixes)
    return pathspecs


def collect_git_diff(
    repo: Path,
    include_prefixes: Optional[Sequence[str]] = None,
    exclude_prefixes: Sequence[str] = (),
) -> str:
    # preserve_newlines throughout: a diff of a CRLF project (zip4j) is only
    # appliable if its context lines keep their CR. See run_local_command.
    pathspecs = _diff_pathspecs(include_prefixes, exclude_prefixes)
    diff = git_output(repo, ["diff", "--binary", "--", *pathspecs], preserve_newlines=True)
    diff += git_output(
        repo, ["diff", "--cached", "--binary", "--", *pathspecs], preserve_newlines=True
    )

    for rel_path in list_untracked(repo):
        if include_prefixes and not _matches_prefix(rel_path, include_prefixes):
            continue
        if exclude_prefixes and _matches_prefix(rel_path, exclude_prefixes):
            continue
        result = run_local_command(
            "git_diff_untracked",
            # --binary --full-index so the hunk carries the file's actual bytes and
            # an applicable index line. Without them a binary untracked file (the
            # `Pov.class` a patcher's self-verification drops in the repo root)
            # became a contentless "Binary files ... differ" stanza, and the diff
            # stopped being appliable: `git apply` rejects the whole patch with
            # "cannot apply binary patch ... without full index line". That killed
            # reconstruction-based replay for the entire run, not just that file.
            ["git", "diff", "--binary", "--full-index", "--no-index", "--", "/dev/null", rel_path],
            cwd=repo,
            preserve_newlines=True,
        )
        if result.stdout:
            diff += result.stdout
        elif result.stderr:
            diff += result.stderr
    return diff


def collect_patch_only_diff(repo: Path) -> str:
    return collect_git_diff(repo, exclude_prefixes=(".security-pipeline/pov",))


# --------------------------------------------------------------------------- #
# Product-source guard.
#
# The exploiter is told "do not patch product code or normal tests" — it owns
# only its PoV tree. Nothing enforced that, and in a hardening round the
# exploiter runs *in the already-patched worktree*: an edit it leaves behind
# (debug logging, a temporary accessor, a weakened check) survives into the
# final diff that the verifier and the offline judges score, and the
# `status != pov_created` early exit declares the patch "stable" without ever
# looking. This snapshots the product tree around an exploiter run the same way
# the PoV guard brackets a patcher run, and restores rather than rejects.
#
# Only what git already reports as changed is captured, so the cost is the size
# of the patch surface (a handful of files), not the size of the repo.
# --------------------------------------------------------------------------- #

# Everything the exploiter legitimately owns; excluded from the guard.
SOURCE_GUARD_EXCLUDE = (".security-pipeline",)

# None means "this path did not exist when the snapshot was taken". Otherwise a
# TreeEntry: ENTRY_FILE carries the bytes to restore, ENTRY_OTHER marks something
# that is not a regular file (a symlink, a fifo) — recorded so the restore leaves
# it alone rather than mistaking it for a path the exploiter created.
ENTRY_OTHER = "other"
SourceSnapshot = Dict[str, Optional[TreeEntry]]


def _porcelain_paths(repo: Path) -> List[str]:
    """Every path `git status` reports as changed, NUL-separated so no quoting.

    Ignored files (build output) are not listed, which is what keeps the guard
    from touching ``target/``.
    """
    output = git_output(repo, ["status", "--porcelain", "-z"])
    fields = output.split("\x00")
    paths: List[str] = []
    index = 0
    while index < len(fields):
        entry = fields[index]
        index += 1
        if len(entry) < 4:
            continue
        status, path = entry[:2], entry[3:]
        paths.append(path)
        if "R" in status or "C" in status:
            # A rename/copy record is followed by its source path.
            if index < len(fields):
                paths.append(fields[index])
                index += 1
    return paths


def _guarded_paths(
    repo: Path, exclude_prefixes: Sequence[str], build_outputs: Sequence[str] = ()
) -> List[str]:
    """Paths the product-source guard is responsible for.

    ``build_outputs`` is the project's own image build answering the question
    git cannot (see ``DockerRunner.image_build_outputs``): an autotools tree
    ships no ``.gitignore``, so its scattered ``Makefile``/``config.status``/
    ``tools/tiffcrop`` are untracked and were being treated as agent-authored
    product code -- restored to stale bytes, or deleted outright.
    """
    return [
        path
        for path in _porcelain_paths(repo)
        if path
        and not _matches_prefix(path, exclude_prefixes)
        and not _matches_prefix(path, build_outputs)
    ]


def _tracked_in_head(repo: Path, rel: str) -> bool:
    result = run_local_command("git_cat_file", ["git", "cat-file", "-e", f"HEAD:{rel}"], cwd=repo)
    return result.exit_code == 0


def snapshot_worktree_sources(
    repo: Path,
    exclude_prefixes: Sequence[str] = SOURCE_GUARD_EXCLUDE,
    build_outputs: Sequence[str] = (),
) -> SourceSnapshot:
    """Record the contents of every product file that already differs from HEAD."""
    snapshot: SourceSnapshot = {}
    for rel in _guarded_paths(repo, exclude_prefixes, build_outputs):
        target = repo / rel
        if target.is_symlink() or (target.exists() and not target.is_file()):
            snapshot[rel] = (ENTRY_OTHER, 0, b"")
            continue
        if not target.exists():
            snapshot[rel] = None
            continue
        try:
            snapshot[rel] = (ENTRY_FILE, target.stat().st_mode & 0o777, target.read_bytes())
        except OSError:
            snapshot[rel] = (ENTRY_OTHER, 0, b"")
    return snapshot


def _remove_path(target: Path) -> None:
    """Delete ``target``, recursing if it turned out to be a directory.

    A path `git status` reports as changed is not necessarily a file: an
    untracked git submodule (e.g. a project's `gnulib` checkout, populated by
    its own bootstrap step) or a build-output directory reports as one
    directory entry, not one line per file inside it. ``Path.unlink()`` raises
    ``IsADirectoryError`` on those.
    """
    if target.is_dir() and not target.is_symlink():
        shutil.rmtree(target, ignore_errors=True)
    else:
        target.unlink()


def restore_worktree_sources(
    repo: Path,
    snapshot: SourceSnapshot,
    exclude_prefixes: Sequence[str] = SOURCE_GUARD_EXCLUDE,
    build_outputs: Sequence[str] = (),
) -> List[str]:
    """Undo every product-tree change made since ``snapshot``; return the paths.

    Three cases, and the third is why this cannot be a plain content diff:
      * recorded in the snapshot -> rewrite those exact bytes (or delete it again
        if it was absent);
      * changed now but pristine then -> ``git checkout`` it back to HEAD;
      * changed now, pristine then, and absent from HEAD -> the run created it,
        so delete it. Untracked files under a build-output directory are left
        alone: a project without a ``target/`` ignore rule would otherwise have
        its whole incremental build thrown away here.
    """
    changed: List[str] = []
    candidates = set(snapshot) | set(_guarded_paths(repo, exclude_prefixes, build_outputs))
    for rel in sorted(candidates):
        if _matches_prefix(rel, exclude_prefixes) or _matches_prefix(rel, build_outputs):
            continue
        target = repo / rel
        if rel in snapshot:
            recorded = snapshot[rel]
            if recorded is None:
                if target.is_symlink() or target.exists():
                    _remove_path(target)
                    changed.append(rel)
                continue
            kind, mode, data = recorded
            if kind == ENTRY_OTHER:
                continue  # not ours to reconstruct; it was already like this
            readable = not target.is_symlink() and target.is_file()
            if readable and target.read_bytes() == data and target.stat().st_mode & 0o777 == mode:
                continue
            _write_entry(target, (ENTRY_FILE, mode, data))
            changed.append(rel)
            continue
        if _tracked_in_head(repo, rel):
            restored = run_local_command(
                "git_checkout_head", ["git", "checkout", "HEAD", "--", rel], cwd=repo
            )
            if restored.exit_code == 0:
                changed.append(rel)
            continue
        # Every part, not just the parents: `git status` reports a wholly-untracked
        # directory as `target/`, whose only part IS the build-output name. A
        # project shipping no `target/` ignore rule would otherwise have its build
        # deleted here on the first exploiter run.
        if POV_ARTIFACT_DIRS & set(Path(rel).parts):
            continue
        if target.is_symlink() or target.exists():
            _remove_path(target)
            changed.append(rel)
    return sorted(changed)


def _tree_entries(path: Path) -> List[Tuple[str, Path, str]]:
    """Every hand-authored entry under ``path`` as ``(rel, path, kind)``, sorted.

    Build output is excluded (see ``POV_ARTIFACT_DIRS``/``_SUFFIXES``) but
    symlinks never are: a link is not something a compiler emits, and it has to
    be tracked so the guard can restore it *as a link* instead of following it.
    ``rglob`` does not descend through a symlinked directory, so a directory
    replaced by a link surfaces here as a single link entry and the files it
    shadows are simply recreated from the snapshot.
    """
    if not path.exists():
        return []
    entries: List[Tuple[str, Path, str]] = []
    for item in sorted(path.rglob("*")):
        rel = item.relative_to(path)
        if POV_ARTIFACT_DIRS & set(rel.parts[:-1]):
            continue
        if item.is_symlink():
            entries.append((rel.as_posix(), item, ENTRY_LINK))
            continue
        if not item.is_file():
            continue
        if item.suffix.lower() in POV_ARTIFACT_SUFFIXES:
            continue
        if is_compiled_binary(item):
            continue
        entries.append((rel.as_posix(), item, ENTRY_FILE))
    return entries


def is_compiled_binary(item: Path) -> bool:
    """True when ``item`` is an *executable* compiled image (see the magic tables).

    Both halves matter: the magic bytes say "a compiler produced this", and the
    executable bit says "this is the harness, not an exploit input". See the
    comment on ``_MACH_O_MAGICS`` for why exploit inputs must not match.
    """
    try:
        if not item.stat().st_mode & 0o111:
            return False
        with open(item, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head.startswith(_ELF_MAGIC) or head.startswith(_PE_MAGIC) or head in _MACH_O_MAGICS


def _read_entry(item: Path, kind: str) -> TreeEntry:
    if kind == ENTRY_LINK:
        return (ENTRY_LINK, 0, os.readlink(str(item)).encode("utf-8", "surrogateescape"))
    return (ENTRY_FILE, item.stat().st_mode & 0o777, item.read_bytes())


def _write_entry(target: Path, entry: TreeEntry) -> None:
    """(Re)create ``target`` from ``entry``, never writing *through* a symlink."""
    kind, mode, payload = entry
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or target.exists():
        target.unlink()
    if kind == ENTRY_LINK:
        target.symlink_to(payload.decode("utf-8", "surrogateescape"))
        return
    target.write_bytes(payload)
    target.chmod(mode)


def snapshot_path_tree(path: Path) -> TreeSnapshot:
    """Capture the tree's hand-authored entries so they can be compared/restored."""
    return {rel: _read_entry(item, kind) for rel, item, kind in _tree_entries(path)}


def hash_path_tree(path: Path) -> str:
    digest = hashlib.sha256()
    if not path.exists():
        digest.update(b"<missing>")
        return digest.hexdigest()

    for rel, (kind, mode, payload) in sorted(snapshot_path_tree(path).items()):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(f"{mode:o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def restore_path_tree(path: Path, snapshot: Mapping[str, TreeEntry]) -> List[str]:
    """Put ``path`` back exactly as ``snapshot`` recorded it.

    Returns the paths that had to be changed — added, removed, or rewritten —
    which is precisely what happened to the tree since the snapshot was taken.
    An empty list means the tree was untouched.
    """
    current = {rel: (item, kind) for rel, item, kind in _tree_entries(path)}
    changed: List[str] = []

    for rel, (item, kind) in current.items():
        entry = snapshot.get(rel)
        if entry is None:
            item.unlink(missing_ok=True)
            changed.append(rel)
            continue
        if kind != entry[0] or _read_entry(item, kind)[2] != entry[2]:
            # Type flipped (a file swapped for a link, or the reverse) or the
            # payload differs. Either way the entry is rebuilt from scratch.
            _write_entry(item, entry)
            changed.append(rel)
            continue
        if kind == ENTRY_FILE and item.stat().st_mode & 0o777 != entry[1]:
            item.chmod(entry[1])
            changed.append(rel)

    # Second pass, after the loop above has cleared any link standing where a
    # real file or directory belongs.
    for rel, entry in snapshot.items():
        if rel in current:
            continue
        _write_entry(path / rel, entry)
        changed.append(rel)

    return sorted(changed)


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
