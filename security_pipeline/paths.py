"""Where the benchmark data lives.

The CVE corpus, the per-project Dockerfiles and both curated POV families were
split out into their own repository (VulnRepairBench) so the data can be used
and cited independently of this pipeline. It is mounted here as a git submodule
at ``benchmark/``:

    benchmark/dataset/          project_info.csv, build_info.csv, fix_info.csv,
                                Dockerfiles/, project-sources/ (gitignored)
    benchmark/fix_povs/         "did the patch close the CVE?" suites
    benchmark/residual_povs/    "did the patch beat upstream?" suites

Every path into that tree is resolved through this module rather than spelled
out at the call site, for two reasons. Moving the mount point is then one edit
instead of forty, and — the practical one — a checkout whose submodule has not
been initialised looks *exactly* like a checkout whose data is simply missing,
so :func:`require_benchmark` can give one accurate error naming
``git submodule update --init`` instead of each caller reporting its own file
as absent.

``P2PATCH_BENCHMARK`` points at a checkout somewhere else entirely, which is
what a run host with the corpus on a separate volume needs — the project
sources alone are tens of GB, and a machine that already has them should not
have to keep a second copy under the pipeline checkout.
"""
from __future__ import annotations

from pathlib import Path

from .env import get_env

BENCHMARK_DIRNAME = "benchmark"
BENCHMARK_ENV = "P2PATCH_BENCHMARK"

DATASET_SUBDIR = "dataset"
FIX_POVS_SUBDIR = "fix_povs"
RESIDUAL_POVS_SUBDIR = "residual_povs"


class BenchmarkMissing(RuntimeError):
    """The benchmark checkout is absent (usually an uninitialised submodule)."""


def benchmark_root(workspace_root: Path) -> Path:
    """The VulnRepairBench checkout backing this workspace."""
    override = get_env(BENCHMARK_ENV)
    if override:
        return Path(override).expanduser()
    return Path(workspace_root) / BENCHMARK_DIRNAME


def require_benchmark(workspace_root: Path) -> Path:
    """:func:`benchmark_root`, but fail with an actionable message if empty.

    A submodule that was never initialised is an empty *directory*, not a
    missing one, so testing for existence is not enough.
    """
    root = benchmark_root(workspace_root)
    if (root / DATASET_SUBDIR / "project_info.csv").is_file():
        return root
    raise BenchmarkMissing(
        f"benchmark data not found at {root}. It lives in the VulnRepairBench "
        f"submodule — run `git submodule update --init` in the repository root, "
        f"or set {BENCHMARK_ENV} to an existing checkout."
    )


def dataset_dir(workspace_root: Path) -> Path:
    return benchmark_root(workspace_root) / DATASET_SUBDIR


def project_info_csv(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "project_info.csv"


def build_info_csv(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "build_info.csv"


def fix_info_csv(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "fix_info.csv"


def dockerfiles_dir(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "Dockerfiles"


def project_sources_dir(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "project-sources"


def project_source(workspace_root: Path, project_slug: str) -> Path:
    return project_sources_dir(workspace_root) / project_slug


def patches_dir(workspace_root: Path) -> Path:
    return dataset_dir(workspace_root) / "patches"


def fix_povs_dir(workspace_root: Path) -> Path:
    return benchmark_root(workspace_root) / FIX_POVS_SUBDIR


def residual_povs_dir(workspace_root: Path) -> Path:
    return benchmark_root(workspace_root) / RESIDUAL_POVS_SUBDIR
