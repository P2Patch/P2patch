// Shapes returned by the P2Patch Lab API (see dashboard/backend).

/** Snapshot metadata for the published (static) build; see export_static.py. */
export interface PublishedMeta {
  published: boolean;
  generated_at: string;
  run_count: number;
  profiles: string[];
  distinct_cves: number;
}

export interface AgentTokens {
  input: number | null;
  output: number | null;
  cache_read: number | null;
  cache_creation: number | null;
}

export interface AgentMeta {
  duration_ms?: number | null;
  duration_api_ms?: number | null;
  num_turns?: number | null;
  cost_usd?: number | null;
  cost_source?: string | null;
  /** Claude CLI fallback estimate retained when provider-billed cost is used. */
  estimated_cost_usd?: number | null;
  stop_reason?: string | null;
  is_error?: boolean | null;
  model?: string | null;
  tokens?: AgentTokens;
}

export interface RunTotals {
  cost_usd: number;
  cost_source?: string | null;
  num_turns: number;
  agent_duration_ms: number;
}

export interface PatchEvalSummary {
  score: number;
  band: string | null;
  gates_passed: boolean | null;
  samples: number | null;
}

export interface RunSummary {
  run_id: string;
  finding_id: string | null;
  timestamp: string | null;
  status: string;
  profile: string;
  label: string;
  model: string | null;
  reason: string;
  cve_id: string | null;
  cwe_id: string | null;
  cwe_name: string | null;
  project_slug: string | null;
  build_system: string | null;
  agents: { name: string; ok: boolean }[];
  totals: RunTotals;
  patch_eval: PatchEvalSummary | null;
  coverage_score: number | null;
  /** Beyond-upstream hardening score; null when no residual POVs ran. */
  residual_score: number | null;
  has_ground_truth: boolean;
  official_fix_commits: number;
  hardening?: HardeningSummary | null;
}

export interface Stage {
  key: string;
  label: string;
  kind: "step" | "agent" | "command";
  status: "pass" | "fail" | "skipped" | "pending" | "running";
  detail: string | null;
}

export interface CommandResult {
  name: string;
  command: string[];
  exit_code: number;
  timed_out: boolean;
  log: string | null;
  expected_failure?: boolean;
  // Set only for fixPOV runs, where the evaluator — not the raw exit
  // code — decides whether the exploit was blocked or the run was inconclusive.
  outcome?: "blocked" | "reproduced" | "errored" | null;
}

export interface HardeningCheck {
  name: string;
  exit_code: number | null;
  timed_out: boolean;
}

export interface HardeningRound {
  round: number;
  status: "pending" | "running" | "stable" | "hardened" | "failed" | string;
  reason: string | null;
  active_agent?: string | null;
  agents: Partial<Record<"exploiter" | "patcher", string>>;
  commands: Partial<Record<"variant_before" | "variant_after" | "original_recheck", HardeningCheck>>;
}

export interface HardeningSummary {
  max_rounds: number;
  status: string;
  reason: string | null;
  rounds_attempted: number;
  rounds_hardened: number;
  active_agent?: string | null;
  rounds: HardeningRound[];
}

/** One time the pipeline sent work back to an agent instead of rejecting. */
export interface PatchCorrection {
  /** Which gate failed: converge | pov_after | regression | harden_r<N>. */
  gate: string;
  attempt: number;
  failing: string | null;
  detail: string | null;
  /** agent_io folder of the patcher attempt that answered this failure. */
  agent: string;
}

export interface ExploitRetry {
  attempt: number;
  failing: string | null;
  detail: string | null;
  agent: string;
}

export interface ApiErrorRetry {
  /** agent_io folder of the attempt that ran after the re-roll(s). */
  agent: string | null;
  /** How many times this invocation re-rolled the same model. */
  attempts: number;
  /** "content_filter" (output filter false positive) or "connection" (dropped). */
  kind: "content_filter" | "connection";
  detail: string;
  /** True if the retry recovered and the run continued past this agent. */
  recovered: boolean;
}

export interface RetrySummary {
  max_correction_attempts: number;
  max_exploit_attempts: number;
  max_api_error_attempts: number;
  patch_corrections: PatchCorrection[];
  exploit_retries: ExploitRetry[];
  api_error_retries: ApiErrorRetry[];
  gates_converged: string[];
}

export interface AgentSummary {
  name: string;
  exit_code: number | null;
  parse_error: string | null;
  ok: boolean;
  status_field: string | null;
  meta: AgentMeta;
  parsed_output: Record<string, unknown> | null;
}

export interface FixLocalization {
  commit: string;
  file: string;
  class: string;
  class_start: string;
  class_end: string;
  method: string;
  method_start: string;
  method_end: string;
  signature: string;
  is_test: boolean;
}

export interface GroundTruth {
  finding_id: string;
  cve_id: string;
  cwe_id: string;
  cwe_name: string;
  project_slug: string;
  alert_file: string;
  github_url: string;
  repo: string | null;
  github_tag: string;
  advisory_id: string;
  buggy_commit_id: string;
  fix_commit_ids: string[];
  fix_localizations: FixLocalization[];
  fix_files: string[];
  links: Record<string, string | null>;
  official_fix_diffs?: { sha: string; url?: string; diff?: string; error?: string; cached?: boolean }[];
}

export interface TraceStep {
  uri: string;
  line: number;
  message: string;
}

export interface AlertTrace {
  cwe_id: string;
  vulnerabilities: { traces: TraceStep[][] }[];
}

export interface FixPov {
  id: string;
  description: string;
  exploit_path: string;
  outcome: "blocked" | "reproduced" | "errored";
  exit_code: number | null;
}

export interface FixPovEval {
  total: number;
  blocked: number;
  reproduced: number;
  errored: number;
  score: number | null;
  all_blocked: boolean;
  povs: FixPov[];
}

export interface ResidualPov {
  id: string;
  description: string;
  /** One line on what the official upstream fix fails to close. */
  gap_summary: string;
  exploit_path: string;
  outcome: "blocked" | "reproduced" | "errored";
  exit_code: number | null;
}

/**
 * Residual-gap evaluation — a BONUS metric, the inverse of FixPovEval.
 *
 * These POVs exploit paths the CVE's *official upstream fix* does not close.
 * `hardened_beyond_fix` counts the ones the pipeline's patch blocked anyway
 * (better than upstream); `matches_official_fix` counts the ones it left open
 * exactly as upstream does — the expected, neutral outcome, never a failure.
 */
export interface ResidualEval {
  total: number;
  hardened_beyond_fix: number;
  matches_official_fix: number;
  errored: number;
  score: number | null;
  all_hardened: boolean;
  residual_of: string;
  povs: ResidualPov[];
}

// Objective gates replayed against a finished run's patch by
// `security-pipeline retrofit`. Assess-only: the patch and the run's verdict are
// untouched, so `failed` being non-empty on an accepted run is expected — see
// RetrofitGatesPanel for why it is rendered as a warning rather than a failure.
export interface RetrofitGateDetail {
  status: "passed" | "failed" | "errored";
  detail?: string;
  verdict?: string;
  commands?: string[];
}

export interface RetrofitGates {
  gates: string[];
  passed: string[];
  failed: string[];
  errored: string[];
  all_passed: boolean | null;
  evaluation_mode: string;
  detail: Record<string, RetrofitGateDetail>;
}

export interface FixPovReplayStatus {
  run_id: string;
  project_slug: string;
  available: boolean;
  unavailable_reason: string | null;
  has_manifest: boolean;
  state: "absent" | "running" | "done" | "error";
  started_at: string | null;
  finished_at: string | null;
  returncode: number | null;
  error: string | null;
  log_tail: string[];
  result: FixPovEval | null;
}

export interface ResidualReplayStatus {
  run_id: string;
  project_slug: string;
  available: boolean;
  unavailable_reason: string | null;
  has_manifest: boolean;
  state: "absent" | "running" | "done" | "error";
  started_at: string | null;
  finished_at: string | null;
  returncode: number | null;
  error: string | null;
  log_tail: string[];
  result: ResidualEval | null;
}

// Background retrofit job: replays the verifier against a finished run's
// existing patch. Same job shape as a fixPOV replay (both run through
// dashboard/backend/run_jobs.py), with the retrofit's own result payload.
export interface RetrofitJobStatus {
  run_id: string;
  project_slug: string;
  available: boolean;
  unavailable_reason: string | null;
  gates: string[];
  state: "absent" | "running" | "done" | "error";
  started_at: string | null;
  finished_at: string | null;
  returncode: number | null;
  error: string | null;
  log_tail: string[];
  result: RetrofitGates | null;
}

// Background verifier re-run job: for a run rejected only because the verifier
// AGENT crashed (expired OAuth, structured-output-retry exhaustion, a transient
// API error) while every objective gate passed. Re-runs the verifier and, only
// if it accepts, flips the run to accepted. Unlike a retrofit this DOES change
// the run's status — but only on a genuine `accepted` verdict.
export interface VerifierRerunResult {
  status: "accepted" | "rejected" | "errored";
  flipped: boolean;
  verdict?: string;
  summary?: string;
  model?: string | null;
  ran_at?: string;
}

export interface VerifierRerunJobStatus {
  run_id: string;
  available: boolean;
  unavailable_reason: string | null;
  state: "absent" | "running" | "done" | "error";
  started_at: string | null;
  finished_at: string | null;
  returncode: number | null;
  error: string | null;
  log_tail: string[];
  result: VerifierRerunResult | null;
}

export interface RunDetail {
  run_id: string;
  finding_id: string | null;
  timestamp: string | null;
  status: string;
  profile: string;
  label: string;
  model: string | null;
  reason: string;
  project: Record<string, string> | null;
  ground_truth: GroundTruth | null;
  fix_pov_eval: FixPovEval | null;
  residual_eval: ResidualEval | null;
  retrofit_gates: RetrofitGates | null;
  alert_trace: AlertTrace | null;
  stages: Stage[];
  steps: Record<string, unknown>[];
  commands: CommandResult[];
  agents: AgentSummary[];
  totals: RunTotals;
  artifacts: { diffs: Record<string, boolean>; logs: string[] };
  hardening?: HardeningSummary | null;
  retries?: RetrySummary | null;
}

export interface AgentIO {
  run_id: string;
  agent: string;
  input_md: string | null;
  output_json: Record<string, unknown> | null;
  raw_stderr: string | null;
  meta: AgentMeta;
}

export interface CweBucket {
  cwe_id: string;
  cwe_name: string | null;
  total: number;
  accepted: number;
}

export interface EvalDimension {
  key: string;
  label?: string;
  score: number;
  rationale: string;
  evidence: string;
}

export interface EvalIssue {
  severity: "high" | "medium" | "low";
  description: string;
}

// Ensemble judging (Phase 4): the distribution of K judge samples over one run.
export interface EnsembleDim {
  key: string;
  label: string;
  median: number;
  min: number;
  max: number;
  stdev: number;
  agreement: number;
  samples: number[];
}

export interface EnsembleSample {
  score: number | null;
  band: string | null;
  gates_passed: boolean | null;
}

export interface Ensemble {
  samples: number;
  samples_attempted?: number;
  overall: {
    score_median: number;
    score_mean: number;
    score_min: number;
    score_max: number;
    score_stdev: number;
    mean_median: number;
    band_mode: string;
    band_agreement: number;
    mean_dim_stdev: number;
  };
  dimensions: EnsembleDim[];
  gate_agreement: Record<string, number>;
  per_sample: EnsembleSample[];
  confidence: "high" | "medium" | "low";
  medoid_index: number;
}

export interface StructuralOverlap {
  overlap_files: string[];
  ours_only: string[];
  official_only: string[];
  jaccard: number;
  covers_all_official?: boolean;
}

export interface PatchEval {
  summary: string;
  root_cause: string;
  dimensions: EvalDimension[];
  equivalence_verdict: string;
  gates: { vulnerability_eliminated: boolean; no_regressions: boolean };
  issues: EvalIssue[];
  overall: { mean: number; score: number; band: string; gates_passed: boolean };
  structural_overlap: StructuralOverlap;
  execution_signals: Record<string, unknown>;
  reference: { production_files: string[]; commits: string[] };
  ensemble?: Ensemble;
}

export interface ExploitEval {
  summary: string;
  dimensions: EvalDimension[];
  gates: { discriminative: boolean; reaches_sink: boolean };
  weaponization: "unproven" | "proof_of_concept" | "functional" | "high";
  official_comparison: { available: boolean; verdict: string; notes: string } | null;
  issues: EvalIssue[];
  overall: { mean: number; score: number; band: string; gates_passed: boolean };
  execution_signals: Record<string, unknown>;
  pov_files: string[];
  ensemble?: Ensemble;
}

export interface CveMetadata {
  nvd:
    | {
        description: string;
        cvss: { version: string; score: number; severity: string; vector: string } | null;
        published: string;
        references: { url: string; tags: string[] }[];
        exploit_refs: string[];
      }
    | null;
  osv: { aliases: string[]; fixed_versions: string[]; summary: string } | null;
  ghsa: { summary: string; severity: string; cvss: number; html_url: string } | null;
  kev: { known_exploited: boolean; date_added?: string; ransomware?: string; name?: string };
}

export interface ExploitCandidate {
  source: string;
  kind: string;
  name?: string;
  url?: string;
  confidence?: string;
  stars?: number;
  description?: string;
}

export interface BestExploit {
  source: string;
  kind: string;
  url: string | null;
  name: string | null;
  confidence: number;
  rationale: string;
}

export interface CveResearch {
  cve_id: string;
  advisory_id: string;
  repo: string | null;
  metadata: CveMetadata;
  kev: CveMetadata["kev"];
  curated_exploits: ExploitCandidate[];
  candidate_repos: ExploitCandidate[];
  judge: {
    known_exploitation_summary: string;
    best_exploit: BestExploit | null;
    candidates_reviewed: { url: string | null; genuine: boolean; reason: string }[];
  };
}

export interface AnalysisStatus {
  state: "absent" | "running" | "done" | "error";
  started_at?: string;
  finished_at?: string | null;
  error?: string | null;
}

export interface AnalysisResponse<T> {
  status: AnalysisStatus;
  result: T | null;
}

export type PatchEvalResponse = AnalysisResponse<PatchEval>;

export interface ReferencePatch {
  cve_id: string;
  cwe_id: string;
  repo: string | null;
  production_files: string[];
  localizations: FixLocalization[];
  reference_diff: string;
  commits: { sha: string; url?: string; error?: string; files?: unknown[] }[];
}

// --- LoopRepair baseline-tool benchmark (dashboard/backend/loop_repair.py) --
export interface LoopRepairStats {
  total: number;
  patched: number;
  failed: number;
  success_rate: number;
  total_cost_usd: number;
  total_tokens: number;
}

export interface LoopRepairResultSummary {
  key: string;
  project: string;
  cve: string;
  vul_id: string;
  status: string;
  elapsed_seconds: number | null;
  num_patches_evaluated: number | null;
  num_repairs_found: number | null;
  patch_found: boolean;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cost_usd: number | null;
  /** Human write-up of what happened — root cause for a failure, or a note on
   *  how a success was reached (e.g. required a retry or a scoped fix). */
  message: string;
  /** Score-only headline from a fixpov/respov replay against this CVE's LoopRepair
   *  patch, if one has been run — null until the "replay POVs" button is used. */
  fix_pov: LoopRepairPovHeadline | null;
  residual: LoopRepairPovHeadline | null;
}

export interface LoopRepairPovHeadline {
  score: number | null;
  total: number | null;
  all_blocked: boolean | null;
  all_hardened: boolean | null;
}

export interface LoopRepairList {
  stats: LoopRepairStats;
  /** fixPOVs: blocked is good. */
  pov: BaselineCoverage | null;
  /** Residual: a POV still reproducing is the expected neutral result, so this is
   *  kept SEPARATE from `pov` rather than averaged with it. */
  pov_residual: BaselineCoverage | null;
  results: LoopRepairResultSummary[];
}

export interface LoopRepairCrash {
  command?: string;
  input?: string;
  bad_output?: string;
  "expected-exit-code"?: number;
}

export interface LoopRepairBug {
  project?: { name?: string };
  name?: string;
  binary?: string;
  crash?: LoopRepairCrash;
  "source-directory"?: string;
  build?: Record<string, unknown>;
}

export interface LoopRepairTestCounts {
  executed?: number;
  passed?: number;
  failed?: number;
}

export interface LoopRepairVerification {
  status: string;
  elapsed_seconds: number | null;
  model?: string | null;
  num_patches_evaluated: number | null;
  num_repairs_found: number | null;
  num_compilation_failures?: number | null;
  patch_found: boolean;
  patch_location?: string | null;
  patch_compiles?: boolean | null;
  tests?: LoopRepairTestCounts | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cost_usd: number | null;
  /** Present only when a human corrected the tool's own self-reported verdict. */
  manual_override_note?: string;
}

export interface LoopRepairResult extends LoopRepairResultSummary {
  bug: LoopRepairBug | null;
  verification: LoopRepairVerification | null;
  has_patch: boolean;
  has_reference_fix: boolean;
  /** Full per-POV detail, same shape the Experiments run detail uses — see
   *  FixPovEvalPanel / ResidualEvalPanel. */
  fix_pov_eval: FixPovEval | null;
  residual_eval: ResidualEval | null;
  pov_input_files: string[];
  logs_available: string[];
}

export interface Stats {
  total_runs: number;
  accepted: number;
  rejected: number;
  accept_rate: number;
  by_status: Record<string, number>;
  by_cwe: CweBucket[];
  total_cost_usd: number;
  distinct_cves: number;
}

// --- Live run monitor (Phase 3) -------------------------------------------
export interface PriorRun {
  run_id: string;
  profile: string;
  status: string;
}

export interface LiveTarget {
  alert_file: string;
  cve_id: string;
  cwe_id: string;
  cwe_name: string;
  project_slug: string;
  finding_id: string;
  sources_present: boolean;
  /** Whether fetch_one.py knows how to clone this source (present in project_info.csv). */
  clonable?: boolean;
  prior_runs?: PriorRun[];
  prior_run_ids?: string[];
  vuln_count: number;
}

export type CloneState = "absent" | "queued" | "cloning" | "done" | "error";

export interface SourceStatus {
  project_slug: string;
  state: CloneState;
  present: boolean;
  clonable: boolean;
  started: string | null;
  finished: string | null;
  error: string | null;
  log_tail: string[];
}

export interface ProfileOption {
  value: string;
  stages: string[];
  patcher_evidence: string;
  description: string;
}

export interface ModelOption {
  value: string;
  label: string;
  /** Alternate providers use isolated per-run Claude Code gateway settings. */
  provider?: string;
}

export interface LaunchOptionsMeta {
  profiles: ProfileOption[];
  default_profile: string;
  efforts: string[];
  models: ModelOption[];
  hardening_rounds: { default: number; min: number; max: number };
  correction_attempts: { default: number; min: number; max: number };
  exploit_attempts: { default: number; min: number; max: number };
}

export interface LaunchOptions {
  effort: string;
  model: string | null;
  profile: string;
  label: string;
  dry_run: boolean;
  skip_docker_build: boolean;
  rerun: boolean;
  max_rounds?: number;
  max_correction_attempts?: number;
  max_exploit_attempts?: number;
  cve_id: string;
  cwe_id: string;
  project_slug: string;
  finding_id: string;
}

export interface LaunchResponse {
  launch_id: string;
  alert_file: string;
  options: LaunchOptions;
  started_at: string;
  run_id: string | null;
  target: LiveTarget;
}

export interface LaunchRecord {
  launch_id: string;
  alert_file: string;
  options: LaunchOptions;
  state?: string; // queued | running | done | stopped | error | interrupted
  queued_at?: string;
  started_at: string;
  run_id: string | null;
  cve_id: string | null;
  project_slug: string | null;
  is_running: boolean;
  note?: string | null; // e.g. "reattached after backend restart"
}

export interface SchedulerStatus {
  concurrency: number;
  paused: boolean;
  running: number;
  queued: number;
}

export interface BatchLaunchResult {
  launch_id?: string;
  alert_file?: string;
  error?: string;
  cve_id?: string | null;
  project_slug?: string | null;
}

export interface BatchResponse {
  concurrency: number;
  queued: number;
  launches: BatchLaunchResult[];
}

export interface AgentActivity {
  agent: string;
  phase: string; // "starting" | "thinking" | "responding" | "tool:<name>" | "done"
  turns: number;
  tool_count: number;
  recent_tools: string[];
  thinking_tail: string;
  text_tail: string;
  output_tokens: number | null;
  done: boolean;
}

export interface LiveSnapshot {
  launch_id: string;
  alert_file: string;
  options: LaunchOptions;
  state?: string;
  started_at: string;
  elapsed_seconds: number;
  alive: boolean;
  returncode: number | null;
  run_id: string | null;
  run_dir: string | null;
  status: string;
  reason: string;
  terminal: boolean;
  stages: Stage[];
  running_stage: string | null;
  running_stage_label: string | null;
  running_stage_elapsed: number | null;
  steps: Record<string, unknown>[];
  commands: { name: string; exit_code: number; timed_out: boolean }[];
  agents: AgentSummary[];
  agent_activity: AgentActivity | null;
  hardening?: HardeningSummary | null;
  retries?: RetrySummary | null;
  summary: Record<string, unknown> | null;
  log_bytes: number;
}

// --- San2Patch baseline-tool benchmark (dashboard/backend/san2patch.py) -------
/** Score-only headline from a fixpov/respov replay against one case's patch. */
export interface PovHeadline {
  score: number | null;
  total: number | null;
  all_blocked: boolean | null;
  all_hardened: boolean | null;
}

export interface San2PatchRow {
  key: string;
  project: string;
  cve: string;
  status: string;
  /** False when the row is a recorded non-attempt rather than a repair failure -- a
   *  case shredded by an API usage limit still wrote a res.txt saying it failed.
   *  Excluded from every rate. */
  valid: boolean;
  patch_found: boolean;
  elapsed_seconds: number | null;
  tries: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cost_usd: number | null;
  mean_load: number | null;
  /** Host was busy enough (>70% of cores) that this duration is not comparable. */
  contended: boolean | null;
  batch: string | null;
  /** Present when the case ran to completion twice. The EARLIEST attempt is counted --
   *  San2Patch already retries 5 times, so taking the better of two full runs would be
   *  best-of-10 and not comparable with the paper. */
  superseded_by: { batch: string; status: string } | null;
  message: string;
  fix_pov: PovHeadline | null;
  residual: PovHeadline | null;
}

export interface San2PatchStats {
  total: number;
  patched: number;
  failed: number;
  success_rate: number;
  total_cost_usd: number;
  total_tokens: number;
}

/** Held-out coverage headline for one baseline and one oracle family, scored
 *  INTENTION-TO-TREAT: `n` (not `scored`) is the denominator, so a subject that
 *  carries a certified suite but got no patch counts as zero. `mean_scored_only`
 *  is the same numerator over `scored` alone — kept so the two policies stay
 *  visibly distinct rather than one silently standing in for the other. */
export interface BaselineCoverage {
  scored: number;
  /** Subjects with a certified suite that the system produced no patch for. */
  zero_credited: number;
  /** The intention-to-treat denominator: `scored + zero_credited`. */
  n: number;
  fully_blocked: number;
  score_sum: number;
  /** Intention-to-treat mean — the number the paper reports. */
  mean_score: number | null;
  mean_scored_only: number | null;
  policy: string;
  errored?: number;
  claimed_repaired?: number;
}

export interface San2PatchList {
  stats: San2PatchStats;
  /** fixPOVs: blocked is good. */
  pov: BaselineCoverage | null;
  /** Residual: a POV still reproducing is the expected neutral result, so this is
   *  kept SEPARATE from `pov` rather than averaged with it. */
  pov_residual: BaselineCoverage | null;
  results: San2PatchRow[];
}

/** One case's full bundle. */
export interface San2PatchResult extends San2PatchRow {
  has_patch: boolean;
  /** "stage_<N>_<M>/<name>_graph_output.json" -- Tree-of-Thought state per attempt. */
  traces: string[];
  /** Per-try outcome lines San2Patch writes ("try: 0\tstage: 0\tcode: ..."). */
  res_txt: string | null;
  fix_pov_eval: FixPovEval | null;
  residual_eval: ResidualEval | null;
  logs_available: string[];
}

// --- PatchAgent baseline-tool benchmark (dashboard/backend/patchagent.py) -----
// Reuses PovHeadline / FixPovEval / ResidualEval above rather than declaring
// its own: the backend writes PatchAgent's POV outcomes in the same shape a pipeline
// run and a San2Patch case use, so the sign convention (fixPOV blocked = good,
// residual still-reproducing = expected neutral) is literally the same code path.

export interface PatchAgentRow {
  key: string;
  project: string;
  cve: string;
  status: string;
  /** False for a case PatchAgent never attempted (its functional gate is unusable on
   *  this machine, so validate() would reject every candidate). Excluded from every
   *  rate rather than counted as a repair failure. */
  valid: boolean;
  patch_found: boolean;
  elapsed_seconds: number | null;
  /** validate() calls — PatchAgent's own retry unit. */
  tries: number | null;
  agents_used: number | null;
  rejected_attempts: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  /** MEASURED from recorded traffic, and a FLOOR — langchain did not propagate usage,
   *  so retried and internally-issued calls were billed but never recorded. */
  cost_usd: number | null;
  /** cost_usd x the 1.68 factor billed ground truth implies. The better estimate. */
  cost_basis: string | null;
  llm_calls: number | null;
  /** The attempt budget this case actually ran at. 3 for 14 cases, 15 for one. */
  max_iteration: number | null;
  /** False when this row's budget was not the protocol's 3 — it is not comparable
   *  with the others on effort, and the table says so instead of implying it is. */
  effort_comparable: boolean | null;
  batch: string | null;
  /** Non-empty when ONE PatchAgent run's single patch covers more than one of our
   *  CVEs. Cost and effort on those rows belong to the run, not to the CVE. */
  shared_run_with: string[];
  functional_baseline: { status: string; seconds: number; exit_code: number } | null;
  message: string;
  fix_pov: PovHeadline | null;
  residual: PovHeadline | null;
}

export interface PatchAgentStats {
  total: number;
  patched: number;
  failed: number;
  not_runnable: number;
  not_runnable_ids: string[];
  success_rate: number;
  /** PatchAgent invocations, which is FEWER than `patched` — one run's patch covers
   *  two of our CVEs. Every cost/effort total below de-duplicates on the run. */
  patchagent_runs: number;
  /** The MEASURED floor. */
  total_cost_usd: number;
  cost_basis: string;
  cost_note: string;
  total_tokens: number;
  llm_calls: number | null;
  /** How many runs used the protocol cap, and which one did not. */
  max_iteration_3: number | null;
  max_iteration_other: Record<string, number>;
  cases_sharing_a_run: { patchagent_case: string; case_ids: string[] }[];
  model: string | null;
  baseline_commit: string | null;
}

/** `povs_*` are per-POV; `scored`/`fully_blocked`/`n` are per-case. */
export interface PatchAgentPovSummary extends BaselineCoverage {
  povs_total: number | null;
  povs_blocked: number | null;
  scoring_note: string;
}

export interface PatchAgentList {
  stats: PatchAgentStats;
  /** fixPOVs: blocked is good. */
  pov: PatchAgentPovSummary | null;
  /** Residual: a POV still reproducing is the expected neutral result, so this is
   *  kept SEPARATE from `pov` rather than averaged with it. */
  pov_residual: PatchAgentPovSummary | null;
  results: PatchAgentRow[];
}

/** One candidate patch submitted to PatchAgent's own validate(). A rejection's
 *  `verdict` carries the full post-patch symbolized sanitizer report. */
export interface PatchAgentAttempt {
  case: string;
  agent_number: string;
  attempt_in_agent: string;
  patch: string;
  verdict: string;
  accepted: string;
}

/** One case's full bundle. */
export interface PatchAgentResult extends PatchAgentRow {
  has_patch: boolean;
  /** "agent_<NN>.json" — one agent attempt's full nvwa context. */
  traces: string[];
  attempts: PatchAgentAttempt[];
  fix_pov_eval: FixPovEval | null;
  residual_eval: ResidualEval | null;
  logs_available: string[];
}
