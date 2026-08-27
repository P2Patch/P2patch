import type {
  AgentIO,
  AnalysisResponse,
  AnalysisStatus,
  BatchResponse,
  San2PatchList,
  San2PatchResult,
  GroundTruth,
  FixPovReplayStatus,
  ResidualReplayStatus,
  RetrofitJobStatus,
  VerifierRerunJobStatus,
  LaunchOptionsMeta,
  LaunchRecord,
  LaunchResponse,
  LiveSnapshot,
  LiveTarget,
  LoopRepairList,
  LoopRepairResult,
  PatchAgentList,
  PatchAgentResult,
  PublishedMeta,
  ReferencePatch,
  RunDetail,
  RunSummary,
  SchedulerStatus,
  SourceStatus,
  Stats,
} from "./types";

/**
 * Published (static) mode. When the app is built with VITE_STATIC=1 there is no
 * backend: the read-only API has been frozen to a flat file tree by
 * `dashboard/export_static.py`. GETs are rewritten to those files
 * (`/api/<path>.json` / `.txt`, query strings dropped) and every mutation is
 * refused. See dashboard/README's "Publish" section.
 */
export const PUBLISHED = __PUBLISHED__;

const BASE = PUBLISHED ? `${import.meta.env.BASE_URL}api` : "/api";

/** Map an API path to its static file (or pass it through in server mode). */
function fileURL(path: string, ext: "json" | "txt"): string {
  if (!PUBLISHED) return `${BASE}${path}`;
  const clean = path.split("?")[0]; // e.g. ground-truth?diffs=true -> one file
  return `${BASE}${clean}.${ext}`;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(fileURL(path, "json"));
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${body ? ` — ${body}` : ""}`);
  }
  return res.json() as Promise<T>;
}

async function getText(path: string): Promise<string> {
  const res = await fetch(fileURL(path, "txt"));
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.text();
}

async function sendJSON<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (PUBLISHED) {
    throw new Error("This is a read-only published snapshot — that action needs the live backend.");
  }
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res
      .json()
      .then((j) => (j as { detail?: string }).detail)
      .catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`);
  }
  return res.json() as Promise<T>;
}

const postJSON = <T>(path: string, body?: unknown) => sendJSON<T>("POST", path, body);

/** Download a response body as a file, preserving the server's ZIP filename. */
async function downloadZip(path: string, body: unknown): Promise<void> {
  if (PUBLISHED) {
    throw new Error("This published snapshot cannot create archives — use the live dashboard.");
  }
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res
      .json()
      .then((j) => (j as { detail?: string }).detail)
      .catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`);
  }

  const contentDisposition = res.headers.get("content-disposition") ?? "";
  const filename = contentDisposition.match(/filename="?([^";]+)"?/i)?.[1] ?? "p2patch-runs.zip";
  const url = URL.createObjectURL(await res.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Give the browser a chance to begin reading the blob before releasing it.
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export const api = {
  meta: () => getJSON<PublishedMeta>("/meta"),
  stats: () => getJSON<Stats>("/stats"),
  runs: () => getJSON<RunSummary[]>("/runs"),
  run: (id: string) => getJSON<RunDetail>(`/runs/${id}`),
  runExportUrl: (id: string) => `${BASE}/runs/${encodeURIComponent(id)}/export`,
  exportRuns: (ids: string[]) => downloadZip("/runs/export", { run_ids: ids }),
  deleteRun: (id: string) => sendJSON<{ deleted: boolean }>("DELETE", `/runs/${id}`),
  stopRun: (id: string) => postJSON<{ stopped: boolean }>(`/runs/${id}/stop`),
  agent: (id: string, name: string) => getJSON<AgentIO>(`/runs/${id}/agents/${name}`),
  diff: (id: string, kind: string) => getText(`/runs/${id}/diff/${kind}`),
  log: (id: string, name: string) => getText(`/runs/${id}/log/${name}`),
  groundTruth: (id: string, diffs = false) =>
    getJSON<GroundTruth>(`/runs/${id}/ground-truth${diffs ? "?diffs=true" : ""}`),
  fixPovReplay: (id: string) =>
    getJSON<FixPovReplayStatus>(`/runs/${id}/fix-pov-replay`),
  startFixPovReplay: (id: string) =>
    postJSON<FixPovReplayStatus>(`/runs/${id}/fix-pov-replay`),
  residualReplay: (id: string) =>
    getJSON<ResidualReplayStatus>(`/runs/${id}/residual-replay`),
  startResidualReplay: (id: string) =>
    postJSON<ResidualReplayStatus>(`/runs/${id}/residual-replay`),
  retrofit: (id: string) => getJSON<RetrofitJobStatus>(`/runs/${id}/retrofit`),
  startRetrofit: (id: string) => postJSON<RetrofitJobStatus>(`/runs/${id}/retrofit`),
  rerunVerifier: (id: string) =>
    getJSON<VerifierRerunJobStatus>(`/runs/${id}/rerun-verifier`),
  startRerunVerifier: (id: string) =>
    postJSON<VerifierRerunJobStatus>(`/runs/${id}/rerun-verifier`),
  referencePatch: (id: string) => getJSON<ReferencePatch>(`/runs/${id}/reference-patch`),
  analysis: <T>(id: string, agent: string) =>
    getJSON<AnalysisResponse<T>>(`/runs/${id}/analysis/${agent}`),
  startAnalysis: (id: string, agent: string, force = false, samples?: number) => {
    const q = new URLSearchParams();
    if (force) q.set("force", "true");
    if (samples && samples > 1) q.set("samples", String(samples));
    const qs = q.toString();
    return postJSON<AnalysisStatus>(`/runs/${id}/analysis/${agent}${qs ? `?${qs}` : ""}`);
  },

  // Live run monitor
  liveOptions: () => getJSON<LaunchOptionsMeta>("/live/options"),
  liveTargets: () => getJSON<LiveTarget[]>("/live/targets"),
  liveLaunches: () => getJSON<LaunchRecord[]>("/live/launches"),
  launch: (body: {
    alert_file: string;
    effort: string;
    model?: string | null;
    profile: string;
    label?: string;
    dry_run: boolean;
    skip_docker_build: boolean;
    rerun: boolean;
    max_rounds: number;
    max_correction_attempts: number;
    max_exploit_attempts: number;
  }) => postJSON<LaunchResponse>("/live/launch", body),
  launchBatch: (body: {
    alert_files: string[];
    label?: string;
    dry_run: boolean;
    skip_docker_build: boolean;
    rerun: boolean;
    max_rounds: number;
    max_correction_attempts: number;
    max_exploit_attempts: number;
    concurrency: number;
    // Matrix axes — one run is queued per (alert × effort × profile × model).
    efforts: string[];
    profiles: string[];
    models: (string | null)[];
  }) => postJSON<BatchResponse>("/live/batch", body),
  liveSnapshot: (launchId: string) => getJSON<LiveSnapshot>(`/live/${launchId}`),
  liveStop: (launchId: string) => postJSON<{ stopped: boolean }>(`/live/${launchId}/stop`),
  liveStreamUrl: (launchId: string) => `${BASE}/live/${launchId}/stream`,

  // Queue scheduler controls (durable across restarts — state lives on disk)
  scheduler: () => getJSON<SchedulerStatus>("/live/scheduler"),
  stopAll: () => postJSON<{ stopped: number; paused: boolean }>("/live/stop-all"),
  pauseQueue: () => postJSON<SchedulerStatus>("/live/pause"),
  resumeQueue: () => postJSON<SchedulerStatus>("/live/resume"),

  // On-demand source cloning (for alerts that ship without a local source tree)
  sourceStatus: (slug: string) => getJSON<SourceStatus>(`/sources/${encodeURIComponent(slug)}`),
  cloneSource: (slug: string) => postJSON<SourceStatus>(`/sources/${encodeURIComponent(slug)}/clone`),

  // San2Patch baseline-tool benchmark (its own page; LoopRepair's is separate)
  san2patchList: () => getJSON<San2PatchList>("/baselines/san2patch"),
  san2patchResult: (key: string) => getJSON<San2PatchResult>(`/baselines/san2patch/${encodeURIComponent(key)}`),
  san2patchDiff: (key: string) => getText(`/baselines/san2patch/${encodeURIComponent(key)}/diff`),
  san2patchLog: (key: string) => getText(`/baselines/san2patch/${encodeURIComponent(key)}/log`),
  san2patchTrace: (key: string, rel: string) =>
    getText(`/baselines/san2patch/${encodeURIComponent(key)}/trace/${rel}`),
  san2patchFixpovReplay: (key: string) =>
    getJSON<FixPovReplayStatus>(`/baselines/san2patch/${encodeURIComponent(key)}/fixpov-replay`),
  startSan2patchFixpovReplay: (key: string) =>
    postJSON<FixPovReplayStatus>(`/baselines/san2patch/${encodeURIComponent(key)}/fixpov-replay`),
  san2patchRespovReplay: (key: string) =>
    getJSON<ResidualReplayStatus>(`/baselines/san2patch/${encodeURIComponent(key)}/respov-replay`),
  startSan2patchRespovReplay: (key: string) =>
    postJSON<ResidualReplayStatus>(`/baselines/san2patch/${encodeURIComponent(key)}/respov-replay`),

  // PatchAgent baseline-tool benchmark (its own page, like San2Patch's).
patchAgentList: () => getJSON<PatchAgentList>("/baselines/patchagent"),
  patchAgentResult: (key: string) =>
    getJSON<PatchAgentResult>(`/baselines/patchagent/${encodeURIComponent(key)}`),
  patchAgentDiff: (key: string) => getText(`/baselines/patchagent/${encodeURIComponent(key)}/diff`),
  patchAgentLog: (key: string, name: string) =>
    getText(`/baselines/patchagent/${encodeURIComponent(key)}/log/${encodeURIComponent(name)}`),
  patchAgentTrace: (key: string, name: string) =>
    getText(`/baselines/patchagent/${encodeURIComponent(key)}/trace/${encodeURIComponent(name)}`),
  // Re-score one case after a POV set is edited. Same `fixpov replay-patch` CLI, same
  // certified manifests and same oracle San2Patch and pipeline runs use.
  patchAgentFixpovReplay: (key: string) =>
    getJSON<FixPovReplayStatus>(`/baselines/patchagent/${encodeURIComponent(key)}/fixpov-replay`),
  startPatchAgentFixpovReplay: (key: string) =>
    postJSON<FixPovReplayStatus>(`/baselines/patchagent/${encodeURIComponent(key)}/fixpov-replay`),
  patchAgentRespovReplay: (key: string) =>
    getJSON<ResidualReplayStatus>(`/baselines/patchagent/${encodeURIComponent(key)}/respov-replay`),
  startPatchAgentRespovReplay: (key: string) =>
    postJSON<ResidualReplayStatus>(`/baselines/patchagent/${encodeURIComponent(key)}/respov-replay`),

  // LoopRepair baseline-tool benchmark ("Other projects")
  loopRepairList: () => getJSON<LoopRepairList>("/baselines/loop-repair"),
  loopRepairResult: (key: string) => getJSON<LoopRepairResult>(`/baselines/loop-repair/${encodeURIComponent(key)}`),
  loopRepairDiff: (key: string, kind: "patch" | "reference") =>
    getText(`/baselines/loop-repair/${encodeURIComponent(key)}/diff/${kind}`),
  loopRepairLog: (key: string, name: string) =>
    getText(`/baselines/loop-repair/${encodeURIComponent(key)}/log/${name}`),
  loopRepairPovInputUrl: (key: string, filename: string) =>
    `${BASE}/baselines/loop-repair/${encodeURIComponent(key)}/pov-input/${encodeURIComponent(filename)}`,
  loopRepairFixpovReplay: (key: string) =>
    getJSON<FixPovReplayStatus>(`/baselines/loop-repair/${encodeURIComponent(key)}/fixpov-replay`),
  startLoopRepairFixpovReplay: (key: string) =>
    postJSON<FixPovReplayStatus>(`/baselines/loop-repair/${encodeURIComponent(key)}/fixpov-replay`),
  loopRepairRespovReplay: (key: string) =>
    getJSON<ResidualReplayStatus>(`/baselines/loop-repair/${encodeURIComponent(key)}/respov-replay`),
  startLoopRepairRespovReplay: (key: string) =>
    postJSON<ResidualReplayStatus>(`/baselines/loop-repair/${encodeURIComponent(key)}/respov-replay`),
};
