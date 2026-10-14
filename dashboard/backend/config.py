"""Path configuration for the P2Patch Lab backend.

The backend reads the security pipeline's on-disk artifacts directly and reuses
the ``security_pipeline`` package for finding-id / metadata logic, so it stays in
lockstep with however the pipeline actually names and stores runs.
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
DASHBOARD_DIR = BACKEND_DIR.parent
REPO_ROOT = DASHBOARD_DIR.parent

# Make the pipeline package importable (finding-id hashing, metadata helpers).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

RUNS_DIR = REPO_ROOT / "security_pipeline_runs"
ALERTS_DIR = REPO_ROOT / "finder_results_filtered"
# The CVE corpus and both POV families live under benchmark/
# (P2PATCH_BENCHMARK relocates it). Resolved through the
# pipeline's own helper so the backend and the CLI can never disagree about
# where the data is.
from security_pipeline import paths as _paths  # noqa: E402

BENCHMARK_DIR = _paths.benchmark_root(REPO_ROOT)
DATASET_DIR = _paths.dataset_dir(REPO_ROOT)
PROJECT_INFO_CSV = _paths.project_info_csv(REPO_ROOT)
FIX_INFO_CSV = _paths.fix_info_csv(REPO_ROOT)


# Resolved per call against the *current* REPO_ROOT rather than frozen at
# import. Tests relocate the whole tree by patching config.REPO_ROOT, and a
# module-level constant silently ignores that — it would keep pointing at the
# real checkout while the test wrote its fixtures into a tmpdir, so a lookup
# could pass by reading the developer's own data.
def fix_povs_dir() -> Path:
    return _paths.fix_povs_dir(REPO_ROOT)


def residual_povs_dir() -> Path:
    return _paths.residual_povs_dir(REPO_ROOT)


def dataset_dir() -> Path:
    return _paths.dataset_dir(REPO_ROOT)

# LoopRepair baseline-tool benchmark results (produced out-of-band by
# run_looprepair_standalone.sh, merged from however many hosts ran it — see
# baselines/runs/loop_repair/merged/summary.csv). Read-only, like everything
# else this backend serves.
LOOP_REPAIR_DIR = REPO_ROOT / "baselines" / "runs" / "loop_repair" / "merged"

CACHE_DIR = BACKEND_DIR / ".cache"
FRONTEND_DIST = DASHBOARD_DIR / "frontend" / "dist"

# Vite dev server origins allowed to call the API during development.
DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
