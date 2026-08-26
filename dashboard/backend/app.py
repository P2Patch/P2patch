"""P2Patch Lab API — read-only observability over the security pipeline runs.

Run (from dashboard/backend):
    uvicorn app:app --reload --port 8000
"""
from __future__ import annotations

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config
import groundtruth
import fix_pov_replay
import loop_repair
import loop_repair_fixpov
import patchagent
import san2patch
import san2patch_fixpov
import patchagent_fixpov
import residual_replay
import residual_triage
import retrofit_job
import verifier_rerun_job
import live
import runs
import sources
from analysis import base as analysis_base
from analysis import cve_research, exploit_eval, patch_eval, reference_patch

app = FastAPI(title="P2Patch Lab API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.DEV_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _recover_live_state() -> None:
    """Rebuild launch/queue state from disk on every (re)start: reattach live
    runs, reconcile dead ones, and hold any recovered queue paused. This is what
    makes a backend restart non-destructive — nothing in memory is load-bearing."""
    try:
        result = live.recover()
        print(f"[live] recovered: {result}", flush=True)
    except Exception as exc:  # noqa: BLE001 - never let recovery abort startup
        print(f"[live] recovery failed: {exc}", flush=True)

api = FastAPI(title="P2Patch Lab API")
api.add_middleware(
    CORSMiddleware,
    allow_origins=config.DEV_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@api.get("/health")
def health() -> dict:
    return {"ok": True, "runs_dir": str(config.RUNS_DIR), "runs_dir_exists": config.RUNS_DIR.is_dir()}


@api.get("/stats")
def get_stats() -> dict:
    return runs.stats()


@api.get("/runs")
def get_runs() -> list:
    return runs.list_runs()


class RunExportRequest(BaseModel):
    """The run directories to include in one portable archive."""

    run_ids: list[str]


def _run_export_response(run_ids: list[str]) -> FileResponse:
    try:
        archive_path, filename = runs.export_runs(run_ids)
    except runs.RunExportError as exc:
        status = 404 if str(exc).startswith("run not found:") else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc

    cleanup = BackgroundTasks()
    cleanup.add_task(runs.remove_export, archive_path)
    return FileResponse(
        archive_path,
        media_type="application/zip",
        filename=filename,
        background=cleanup,
    )


@api.post("/runs/export")
def export_selected_runs(req: RunExportRequest) -> FileResponse:
    """Download selected run directories as a ZIP that extracts into RUNS_DIR."""
    return _run_export_response(req.run_ids)


@api.get("/runs/{run_id}/export")
def export_run(run_id: str) -> FileResponse:
    """Download one run directory as a portable ZIP."""
    return _run_export_response([run_id])


@api.get("/runs/{run_id}")
def get_run(run_id: str) -> dict:
    detail = runs.get_run(run_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    return detail


@api.delete("/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    """Permanently delete a run directory. Refuses while the run is still active."""
    if live.is_run_active(run_id):
        raise HTTPException(status_code=409, detail="run is currently active — stop it first")
    # A fixPOV replay is a second kind of active user of the directory: it
    # writes into fix_pov/ from a background worker, so deleting underneath
    # it leaves a partial run behind when that worker reports its result.
    if fix_pov_replay.is_replay_active(run_id):
        raise HTTPException(
            status_code=409,
            detail="a fixPOV replay is running for this run — wait for it to finish",
        )
    if residual_replay.is_replay_active(run_id):
        raise HTTPException(
            status_code=409,
            detail="a residual replay is running for this run — wait for it to finish",
        )
    # A retrofit is the same kind of active user: it writes into gates/ and
    # agent_io/verifier/ from a background worker, so deleting underneath it
    # leaves a partial run behind when that worker reports its result.
    if retrofit_job.is_retrofit_active(run_id):
        raise HTTPException(
            status_code=409,
            detail="a retrofit is running for this run — wait for it to finish",
        )
    # A verifier re-run writes into agent_io/verifier/, state.json and verdict.json
    # from a background worker, so deleting underneath it corrupts the run.
    if verifier_rerun_job.is_active(run_id):
        raise HTTPException(
            status_code=409,
            detail="a verifier re-run is running for this run — wait for it to finish",
        )
    try:
        deleted = runs.delete_run(run_id)
    except runs.RunDeleteError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if not deleted:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    return {"deleted": True, "run_id": run_id}


@api.post("/runs/{run_id}/stop")
def stop_run(run_id: str) -> dict:
    """Stop the live run that produced this run directory."""
    try:
        return live.stop_run(run_id)
    except live.LaunchError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.get("/runs/{run_id}/agents/{agent_name}")
def get_agent(run_id: str, agent_name: str) -> dict:
    io = runs.get_agent_io(run_id, agent_name)
    if io is None:
        raise HTTPException(status_code=404, detail=f"agent io not found: {run_id}/{agent_name}")
    return io


@api.get("/runs/{run_id}/diff/{kind}")
def get_diff(run_id: str, kind: str) -> Response:
    diff = runs.get_diff(run_id, kind)
    if diff is None:
        raise HTTPException(status_code=404, detail=f"diff not found: {run_id}/{kind}")
    return Response(content=diff, media_type="text/plain; charset=utf-8")


@api.get("/runs/{run_id}/log/{name}")
def get_log(run_id: str, name: str) -> Response:
    log = runs.get_log(run_id, name)
    if log is None:
        raise HTTPException(status_code=404, detail=f"log not found: {run_id}/{name}")
    return Response(content=log, media_type="text/plain; charset=utf-8")


@api.get("/runs/{run_id}/ground-truth")
def get_ground_truth(run_id: str, diffs: bool = False) -> dict:
    gt = groundtruth.ground_truth_for_run(run_id)
    if gt is None:
        raise HTTPException(status_code=404, detail=f"no ground truth mapping for run: {run_id}")
    if diffs and gt.get("github_url"):
        gt = dict(gt)
        gt["official_fix_diffs"] = [
            groundtruth.fetch_fix_diff(gt["github_url"], sha) for sha in gt.get("fix_commit_ids", [])
        ]
    return gt


@api.get("/runs/{run_id}/fix-pov-replay")
def get_fix_pov_replay(run_id: str) -> dict:
    """Replay availability and background-job status for one run."""
    try:
        return fix_pov_replay.status(run_id)
    except fix_pov_replay.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/runs/{run_id}/fix-pov-replay")
def start_fix_pov_replay(run_id: str) -> dict:
    """Replay current curated POVs without rerunning the pipeline agents."""
    if live.is_run_active(run_id):
        raise HTTPException(status_code=409, detail="run is currently active")
    try:
        return fix_pov_replay.start(run_id)
    except fix_pov_replay.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/runs/{run_id}/residual-replay")
def get_residual_replay(run_id: str) -> dict:
    """Residual-POV replay availability and background-job status."""
    try:
        return residual_replay.status(run_id)
    except residual_replay.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/runs/{run_id}/residual-replay")
def start_residual_replay(run_id: str) -> dict:
    """Replay current residual POVs without rerunning the pipeline agents."""
    if live.is_run_active(run_id):
        raise HTTPException(status_code=409, detail="run is currently active")
    try:
        return residual_replay.start(run_id)
    except residual_replay.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/runs/{run_id}/retrofit")
def get_retrofit(run_id: str) -> dict:
    """Retrofit availability and background-job status for one run."""
    try:
        return retrofit_job.status(run_id)
    except retrofit_job.RetrofitError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/runs/{run_id}/retrofit")
def start_retrofit(run_id: str) -> dict:
    """Replay the verifier against this run's existing patch.

    Assess-only: the patch is never rewritten and the run's verdict never
    changes — only the recorded gate outcome does.
    """
    if live.is_run_active(run_id):
        raise HTTPException(status_code=409, detail="run is currently active")
    try:
        return retrofit_job.start(run_id)
    except retrofit_job.RetrofitError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/runs/{run_id}/rerun-verifier")
def get_rerun_verifier(run_id: str) -> dict:
    """Re-run-verifier availability and background-job status for one run."""
    try:
        return verifier_rerun_job.status(run_id)
    except verifier_rerun_job.VerifierRerunError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/runs/{run_id}/rerun-verifier")
def start_rerun_verifier(run_id: str) -> dict:
    """Re-run the verifier for a run whose verifier crashed; flip to accepted if it passes.

    For a run rejected only because the verifier AGENT crashed (expired OAuth,
    structured-output-retry exhaustion, a transient API error) while every
    objective gate passed. Only a genuine ``accepted`` verdict flips the run.
    """
    if live.is_run_active(run_id):
        raise HTTPException(status_code=409, detail="run is currently active")
    try:
        return verifier_rerun_job.start(run_id)
    except verifier_rerun_job.VerifierRerunError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _run_dir_and_gt(run_id: str):
    run_dir = runs.resolve_run_dir(run_id)
    if run_dir is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    gt = groundtruth.ground_truth_for_run(run_id)
    if gt is None:
        raise HTTPException(status_code=404, detail=f"no CVE mapping for run: {run_id}")
    return run_dir, gt


@api.get("/runs/{run_id}/reference-patch")
def reference_patch_ep(run_id: str, force: bool = False) -> dict:
    """Deterministic reference-patch bundle (official fix hunks + localization)."""
    run_dir, gt = _run_dir_and_gt(run_id)
    return reference_patch.get_or_build(run_id, run_dir, gt, force=force)


@api.post("/runs/{run_id}/analysis/patch-eval")
def start_patch_eval(run_id: str, force: bool = False, samples: int = 1) -> dict:
    """Kick off (or return the running/cached) patch-quality evaluation.

    ``samples`` > 1 runs the judge that many times and stabilizes the score into
    a median + confidence band (ensemble judging). Clamped to 1..5.
    """
    run_dir, gt = _run_dir_and_gt(run_id)
    return patch_eval.start(run_id, run_dir, gt, samples=max(1, min(samples, 5)), force=force)


@api.get("/runs/{run_id}/analysis/patch-eval")
def get_patch_eval(run_id: str) -> dict:
    return _analysis_status(run_id, patch_eval.AGENT)


@api.post("/runs/{run_id}/analysis/exploit-eval")
def start_exploit_eval(run_id: str, force: bool = False, samples: int = 1) -> dict:
    """Kick off (or return the running/cached) POV-quality evaluation.

    ``samples`` > 1 runs the judge that many times and stabilizes the score into
    a median + confidence band (ensemble judging). Clamped to 1..5.
    """
    run_dir, gt = _run_dir_and_gt(run_id)
    return exploit_eval.start(run_id, run_dir, gt, samples=max(1, min(samples, 5)), force=force)


@api.get("/runs/{run_id}/analysis/exploit-eval")
def get_exploit_eval(run_id: str) -> dict:
    return _analysis_status(run_id, exploit_eval.AGENT)


@api.post("/runs/{run_id}/analysis/cve-research")
def start_cve_research(run_id: str, force: bool = False) -> dict:
    """Fetch canonical CVE metadata + locate a public exploit."""
    run_dir, gt = _run_dir_and_gt(run_id)
    return cve_research.start(run_id, run_dir, gt, force=force)


@api.get("/runs/{run_id}/analysis/cve-research")
def get_cve_research(run_id: str) -> dict:
    return _analysis_status(run_id, cve_research.AGENT)


def _analysis_status(run_id: str, agent: str) -> dict:
    run_dir = runs.resolve_run_dir(run_id)
    if run_dir is None:
        raise HTTPException(status_code=404, detail=f"run not found: {run_id}")
    return {
        "status": analysis_base.get_status(run_dir, agent),
        "result": analysis_base.get_result(run_dir, agent),
    }


# --- Live run monitor (Phase 3) -------------------------------------------
class LaunchRequest(BaseModel):
    alert_file: str
    effort: str = "high"
    model: str | None = None
    profile: str = "full"
    label: str = ""
    dry_run: bool = False
    skip_docker_build: bool = False
    rerun: bool = False
    max_rounds: int = live.HARDENING_ROUNDS_DEFAULT
    max_correction_attempts: int = live.CORRECTION_ATTEMPTS_DEFAULT
    max_exploit_attempts: int = live.EXPLOIT_ATTEMPTS_DEFAULT


class BatchRequest(BaseModel):
    alert_files: list[str]
    effort: str = "high"
    model: str | None = None
    profile: str = "full"
    label: str = ""
    dry_run: bool = False
    skip_docker_build: bool = False
    rerun: bool = False
    max_rounds: int = live.HARDENING_ROUNDS_DEFAULT
    max_correction_attempts: int = live.CORRECTION_ATTEMPTS_DEFAULT
    max_exploit_attempts: int = live.EXPLOIT_ATTEMPTS_DEFAULT
    concurrency: int = 1
    # Matrix axes: queue one run per (alert × effort × profile × model). Each
    # falls back to its singular field above when omitted.
    efforts: list[str] | None = None
    profiles: list[str] | None = None
    models: list[str | None] | None = None


@api.get("/residual-triage")
def get_residual_triage() -> dict:
    """Every certified residual POV with its upstream triage and execution state."""
    return residual_triage.overview()


@api.get("/residual-triage/{project_slug}")
def get_residual_triage_suite(project_slug: str) -> dict:
    data = residual_triage.suite(project_slug)
    if not data.get("available"):
        raise HTTPException(status_code=404, detail=data.get("reason", "not found"))
    return data


@api.get("/live/options")
def live_options() -> dict:
    """Selectable experiment profiles, efforts, and models for the launcher."""
    return live.launch_options()


@api.get("/live/targets")
def live_targets() -> list:
    """Alerts that can be launched, with CVE/CWE, source availability, prior runs."""
    return live.list_targets()


@api.get("/live/launches")
def live_launches(limit: int = 0) -> list:
    """Every launch, newest first. `limit` of 0 (the default) means no cap."""
    return live.list_launches(limit)


@api.get("/live/scheduler")
def live_scheduler() -> dict:
    """Queue scheduler state: concurrency, running/queued counts, pause flag.
    (Registered before /live/{launch_id} so the literal path is not shadowed.)"""
    return live.scheduler_status()


@api.post("/live/stop-all")
def live_stop_all() -> dict:
    """Stop every running launch and cancel the whole queue, then pause."""
    return live.stop_all()


@api.post("/live/pause")
def live_pause() -> dict:
    """Hold the queue — running launches finish, no new ones start."""
    return live.pause()


@api.post("/live/resume")
def live_resume() -> dict:
    """Release a paused/recovered queue and resume starting runs."""
    return live.resume()


@api.post("/live/launch")
def live_launch(req: LaunchRequest) -> dict:
    """Spawn a pipeline run for one alert and return its launch handle."""
    try:
        return live.launch(
            req.alert_file,
            effort=req.effort,
            model=req.model,
            profile=req.profile,
            label=req.label,
            dry_run=req.dry_run,
            skip_docker_build=req.skip_docker_build,
            rerun=req.rerun,
            max_rounds=req.max_rounds,
            max_correction_attempts=req.max_correction_attempts,
            max_exploit_attempts=req.max_exploit_attempts,
        )
    except live.LaunchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.post("/live/batch")
def live_batch(req: BatchRequest) -> dict:
    """Queue one run per (alert × effort × profile × model); the scheduler starts
    them up to `concurrency`."""
    if not req.alert_files:
        raise HTTPException(status_code=400, detail="no alerts selected")
    for axis, values in (("efforts", req.efforts), ("profiles", req.profiles), ("models", req.models)):
        if values is not None and not values:
            raise HTTPException(status_code=400, detail=f"{axis} cannot be empty")
    return live.launch_batch(
        req.alert_files,
        concurrency=req.concurrency,
        effort=req.effort,
        model=req.model,
        profile=req.profile,
        label=req.label,
        dry_run=req.dry_run,
        skip_docker_build=req.skip_docker_build,
        rerun=req.rerun,
        max_rounds=req.max_rounds,
        max_correction_attempts=req.max_correction_attempts,
        max_exploit_attempts=req.max_exploit_attempts,
        efforts=req.efforts,
        profiles=req.profiles,
        models=req.models,
    )


@api.get("/live/{launch_id}")
def live_get(launch_id: str) -> dict:
    ln = live.get(launch_id)
    if ln is None:
        raise HTTPException(status_code=404, detail=f"unknown launch: {launch_id}")
    return live.snapshot(ln)


@api.get("/live/{launch_id}/stream")
def live_stream(launch_id: str) -> StreamingResponse:
    ln = live.get(launch_id)
    if ln is None:
        raise HTTPException(status_code=404, detail=f"unknown launch: {launch_id}")
    return StreamingResponse(
        live.stream(ln),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@api.post("/live/{launch_id}/stop")
def live_stop(launch_id: str) -> dict:
    try:
        return live.stop(launch_id)
    except live.LaunchError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.get("/baselines/san2patch")
def san2patch_list() -> dict:
    """San2Patch benchmark results: summary stats, our POV re-scoring headline, and
    every case row."""
    return {"stats": san2patch.stats(), "pov": san2patch.pov_summary(),
            "results": san2patch.list_results()}


@api.get("/baselines/san2patch/{key}")
def san2patch_detail(key: str) -> dict:
    result = san2patch.get_result(key)
    if result is None:
        raise HTTPException(status_code=404, detail=f"san2patch result not found: {key}")
    return result


@api.get("/baselines/san2patch/{key}/diff")
def san2patch_diff(key: str) -> Response:
    diff = san2patch.get_diff(key)
    if diff is None:
        raise HTTPException(status_code=404, detail=f"no patch for san2patch case: {key}")
    return Response(content=diff, media_type="text/plain; charset=utf-8")


@api.get("/baselines/san2patch/{key}/log")
def san2patch_log(key: str) -> Response:
    log = san2patch.get_log(key)
    if log is None:
        raise HTTPException(status_code=404, detail=f"no log for san2patch case: {key}")
    return Response(content=log, media_type="text/plain; charset=utf-8")


@api.get("/baselines/san2patch/{key}/trace/{stage}/{name}")
def san2patch_trace(key: str, stage: str, name: str) -> Response:
    """One attempt's full Tree-of-Thought state (stage reasoning + candidate patches)."""
    trace = san2patch.get_trace(key, f"{stage}/{name}")
    if trace is None:
        raise HTTPException(status_code=404, detail=f"no trace {stage}/{name} for {key}")
    return Response(content=trace, media_type="application/json")


@api.get("/baselines/san2patch/{key}/fixpov-replay")
def get_san2patch_fixpov_replay(key: str) -> dict:
    try:
        return san2patch_fixpov.fixpov_status(key)
    except san2patch_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/san2patch/{key}/fixpov-replay")
def start_san2patch_fixpov_replay(key: str) -> dict:
    try:
        return san2patch_fixpov.fixpov_start(key)
    except san2patch_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/baselines/san2patch/{key}/respov-replay")
def get_san2patch_respov_replay(key: str) -> dict:
    try:
        return san2patch_fixpov.respov_status(key)
    except san2patch_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/san2patch/{key}/respov-replay")
def start_san2patch_respov_replay(key: str) -> dict:
    try:
        return san2patch_fixpov.respov_start(key)
    except san2patch_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/baselines/patchagent")
def patchagent_list() -> dict:
    """PatchAgent benchmark results: summary stats, both POV re-scoring headlines, and
    every case row. Two POV headlines rather than one because fixPOV and residual
    scores read in OPPOSITE directions and must not collapse into a single number."""
    return {"stats": patchagent.stats(),
            "pov": patchagent.pov_summary("fixpov"),
            "pov_residual": patchagent.pov_summary("respov"),
            "results": patchagent.list_results()}


@api.get("/baselines/patchagent/{key}")
def patchagent_detail(key: str) -> dict:
    result = patchagent.get_result(key)
    if result is None:
        raise HTTPException(status_code=404, detail=f"patchagent result not found: {key}")
    return result


@api.get("/baselines/patchagent/{key}/diff")
def patchagent_diff(key: str) -> Response:
    diff = patchagent.get_diff(key)
    if diff is None:
        raise HTTPException(status_code=404, detail=f"no patch for patchagent case: {key}")
    return Response(content=diff, media_type="text/plain; charset=utf-8")


@api.get("/baselines/patchagent/{key}/log/{name}")
def patchagent_log(key: str, name: str) -> Response:
    log = patchagent.get_log(key, name)
    if log is None:
        raise HTTPException(status_code=404, detail=f"no log {name} for patchagent case: {key}")
    return Response(content=log, media_type="text/plain; charset=utf-8")


@api.get("/baselines/patchagent/{key}/trace/{name}")
def patchagent_trace(key: str, name: str) -> Response:
    """One agent attempt's full context (every viewcode/locate/validate call)."""
    trace = patchagent.get_trace(key, name)
    if trace is None:
        raise HTTPException(status_code=404, detail=f"no trace {name} for {key}")
    return Response(content=trace, media_type="application/json")

@api.get("/baselines/patchagent/{key}/fixpov-replay")
def get_patchagent_fixpov_replay(key: str) -> dict:
    try:
        return patchagent_fixpov.fixpov_status(key)
    except patchagent_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/patchagent/{key}/fixpov-replay")
def start_patchagent_fixpov_replay(key: str) -> dict:
    try:
        return patchagent_fixpov.fixpov_start(key)
    except patchagent_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/baselines/patchagent/{key}/respov-replay")
def get_patchagent_respov_replay(key: str) -> dict:
    try:
        return patchagent_fixpov.respov_status(key)
    except patchagent_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/patchagent/{key}/respov-replay")
def start_patchagent_respov_replay(key: str) -> dict:
    try:
        return patchagent_fixpov.respov_start(key)
    except patchagent_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))



@api.get("/baselines/loop-repair")
def loop_repair_list() -> dict:
    """LoopRepair benchmark results: summary stats + every CVE row."""
    return {"stats": loop_repair.stats(), "results": loop_repair.list_results()}


@api.get("/baselines/loop-repair/{key}")
def loop_repair_detail(key: str) -> dict:
    result = loop_repair.get_result(key)
    if result is None:
        raise HTTPException(status_code=404, detail=f"loop_repair result not found: {key}")
    return result


@api.get("/baselines/loop-repair/{key}/diff/{kind}")
def loop_repair_diff(key: str, kind: str) -> Response:
    diff = loop_repair.get_diff(key, kind)
    if diff is None:
        raise HTTPException(status_code=404, detail=f"diff not found: {key}/{kind}")
    return Response(content=diff, media_type="text/plain; charset=utf-8")


@api.get("/baselines/loop-repair/{key}/log/{name}")
def loop_repair_log(key: str, name: str) -> Response:
    log = loop_repair.get_log(key, name)
    if log is None:
        raise HTTPException(status_code=404, detail=f"log not found: {key}/{name}")
    return Response(content=log, media_type="text/plain; charset=utf-8")


@api.get("/baselines/loop-repair/{key}/pov-input/{filename}")
def loop_repair_pov_input(key: str, filename: str) -> Response:
    data = loop_repair.get_pov_input(key, filename)
    if data is None:
        raise HTTPException(status_code=404, detail=f"pov input not found: {key}/{filename}")
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@api.get("/baselines/loop-repair/{key}/fixpov-replay")
def get_loop_repair_fixpov_replay(key: str) -> dict:
    """fixPOV replay availability and background-job status for one
    LoopRepair CVE — the same job shape as /runs/{run_id}/fix-pov-replay,
    keyed by the LoopRepair result instead of a pipeline run."""
    try:
        return loop_repair_fixpov.fixpov_status(key)
    except loop_repair_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/loop-repair/{key}/fixpov-replay")
def start_loop_repair_fixpov_replay(key: str) -> dict:
    """Score this CVE's LoopRepair patch against the curated fixPOVs."""
    try:
        return loop_repair_fixpov.fixpov_start(key)
    except loop_repair_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/baselines/loop-repair/{key}/respov-replay")
def get_loop_repair_respov_replay(key: str) -> dict:
    """Residual POV replay availability and background-job status for one
    LoopRepair CVE."""
    try:
        return loop_repair_fixpov.respov_status(key)
    except loop_repair_fixpov.ReplayError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@api.post("/baselines/loop-repair/{key}/respov-replay")
def start_loop_repair_respov_replay(key: str) -> dict:
    """Score this CVE's LoopRepair patch against the curated residual POVs."""
    try:
        return loop_repair_fixpov.respov_start(key)
    except loop_repair_fixpov.ReplayError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.get("/sources/{project_slug}")
def source_status(project_slug: str) -> dict:
    """Whether a project's source tree is present, plus any in-flight clone job."""
    try:
        return sources.status(project_slug)
    except sources.SourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@api.post("/sources/{project_slug}/clone")
def source_clone(project_slug: str) -> dict:
    """Fetch a missing project source on demand (background clone); returns its status."""
    try:
        return sources.start_clone(project_slug)
    except sources.SourceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


app.mount("/api", api)

# Serve the built frontend if present (single-command production deploy). The
# /api mount is registered first so it always wins; the catch-all returns
# index.html so client-side routes (e.g. /runs/<id>) survive a hard refresh.
if config.FRONTEND_DIST.is_dir():
    assets_dir = config.FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str) -> FileResponse:  # noqa: ARG001 - path captured by router
        return FileResponse(config.FRONTEND_DIST / "index.html")
