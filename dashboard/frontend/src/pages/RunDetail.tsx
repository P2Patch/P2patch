import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { PUBLISHED, api } from "../api";
import { useAsync } from "../lib/useAsync";
import { absTime, cost, cweShort, duration, statusTone } from "../lib/format";
import type { CommandResult, RunDetail as RunDetailT } from "../types";
import { StatusPill } from "../components/StatusPill";
import { StageRail } from "../components/StageRail";
import { AgentPanel } from "../components/AgentPanel";
import { GroundTruthPanel } from "../components/GroundTruthPanel";
import { TraceView } from "../components/TraceView";
import { DiffViewer } from "../components/DiffViewer";
import { EvaluationTab } from "../components/EvaluationTab";
import { profileTone, shortModel } from "../components/RunsExplorer";
import { HardeningPanel } from "../components/HardeningPanel";
import { RetriesPanel } from "../components/RetriesPanel";
import { FixPovEvalPanel } from "../components/FixPovEvalPanel";
import { ResidualEvalPanel } from "../components/ResidualEvalPanel";
import { RetrofitControl } from "../components/RetrofitControl";
import { RerunVerifierControl } from "../components/RerunVerifierControl";
import { RetrofitGatesPanel } from "../components/RetrofitGatesPanel";
import { FixPovReplayControl } from "../components/FixPovReplayControl";
import { ResidualReplayControl } from "../components/ResidualReplayControl";

type SubTab = "workflow" | "agents" | "diffs" | "eval" | "truth";

export function RunDetail() {
  const { id = "" } = useParams();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, error, loading } = useAsync<RunDetailT>(() => api.run(id), [id, refreshKey]);
  const [tab, setTab] = useState<SubTab>("workflow");
  const [activeStage, setActiveStage] = useState<string | undefined>();

  if (loading) return <div className="mx-auto max-w-6xl px-6 py-10 font-mono text-xs text-txt-faint animate-pulse2">loading run…</div>;
  if (error || !data)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Link to="/" className="text-iris hover:underline">← back</Link>
        <div className="panel mt-4 border-fail/40 p-4 font-mono text-xs text-fail">{error ?? "not found"}</div>
      </div>
    );

  const tone = statusTone(data.status);
  const gt = data.ground_truth;

  function onStage(key: string) {
    setActiveStage(key);
    const stage = data!.stages.find((s) => s.key === key);
    if (stage?.kind === "agent") setTab("agents");
    else setTab("workflow");
  }

  const tabs: { key: SubTab; label: string; badge?: string }[] = [
    { key: "workflow", label: "Workflow" },
    { key: "agents", label: "Agents", badge: `${data.agents.length}` },
    { key: "diffs", label: "Diffs" },
    { key: "eval", label: "Evaluation" },
    { key: "truth", label: "Ground truth", badge: gt ? cweShort(gt.cwe_id) : undefined },
  ];

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <Link to="/" className="focusable font-mono text-2xs text-txt-faint hover:text-iris">← experiments</Link>

      {/* Header */}
      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-2xl font-bold text-txt">{gt?.cve_id ?? "run"}</h1>
            <StatusPill status={data.status} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className={`chip ${profileTone(data.profile)}`} title="experiment profile">{data.profile}</span>
            {data.hardening && <span className="chip text-iris">≤ {data.hardening.max_rounds} rounds</span>}
            {data.label && <span className="chip text-txt-dim" title="run label">{data.label}</span>}
            <span className="chip" title="model">{shortModel(data.model)}</span>
            {gt && <span className="chip">{cweShort(gt.cwe_id)}</span>}
            {data.project?.build_system && <span className="chip">{data.project.build_system}</span>}
            <span className="chip" title={data.run_id}>{data.run_id}</span>
            <span className="font-mono text-2xs text-txt-faint">{absTime(data.timestamp)}</span>
          </div>
          {gt?.project_slug && <div className="mt-1 font-mono text-2xs text-txt-dim">{gt.project_slug}</div>}
        </div>
        <div className="flex gap-5 font-mono text-2xs text-txt-dim">
          <Metric
            label={data.totals.cost_source === "openrouter_generation_api" ? "cost · billed" : "cost"}
            value={cost(data.totals.cost_usd)}
          />
          <Metric label="turns" value={`${data.totals.num_turns}`} />
          <Metric label="agent time" value={duration(data.totals.agent_duration_ms)} />
        </div>
        {!PUBLISHED && (
          <a
            href={api.runExportUrl(data.run_id)}
            download
            className="focusable rounded-md border border-iris/50 px-3 py-1.5 font-mono text-2xs text-iris hover:bg-iris/10"
          >
            download ZIP
          </a>
        )}
      </header>

      {/* Reason banner */}
      <div className={`mt-4 rounded-md border bg-panel px-4 py-2.5 text-sm ${tone.ring}`}>
        <span className={`font-mono text-2xs uppercase tracking-wide ${tone.text}`}>{data.status}</span>
        <span className="ml-3 text-txt-dim">{data.reason}</span>
      </div>

      {/* Signature: the pipeline signal rail */}
      <div className="panel mt-4 px-4 py-4">
        <StageRail stages={data.stages} activeKey={activeStage} onSelect={onStage} />
      </div>

      {/* Sub tabs */}
      <nav className="mt-6 flex gap-1 border-b border-hairline">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`focusable -mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm transition-colors ${
              tab === t.key ? "border-iris text-txt" : "border-transparent text-txt-dim hover:text-txt"
            }`}
          >
            {t.label}
            {t.badge && <span className="chip">{t.badge}</span>}
          </button>
        ))}
      </nav>

      <div className="mt-5">
        {tab === "workflow" && (
          <WorkflowTab data={data} onReplayComplete={() => setRefreshKey((key) => key + 1)} />
        )}
        {tab === "agents" && (
          <div className="space-y-3">
            {data.agents.length === 0 && <Empty>no agents ran</Empty>}
            {data.agents.map((a) => (
              <AgentPanel key={a.name} runId={data.run_id} agent={a} />
            ))}
          </div>
        )}
        {tab === "diffs" && <DiffsTab runId={data.run_id} available={data.artifacts.diffs} />}
        {tab === "eval" && <EvaluationTab runId={data.run_id} hasGroundTruth={!!gt} />}
        {tab === "truth" &&
          (gt ? (
            <GroundTruthPanel gt={gt} runId={data.run_id} />
          ) : (
            <Empty>no CVE mapping found for this run</Empty>
          ))}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-right">
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 text-sm text-txt">{value}</div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="panel p-6 text-center font-mono text-2xs text-txt-faint">{children}</div>;
}

function WorkflowTab({
  data,
  onReplayComplete,
}: {
  data: RunDetailT;
  onReplayComplete: () => void;
}) {
  return (
    <div className="space-y-6">
      {data.hardening && <HardeningPanel summary={data.hardening} />}
      {data.retries && <RetriesPanel summary={data.retries} />}
      {data.status === "accepted" && (
        <RetrofitControl runId={data.run_id} onComplete={onReplayComplete} />
      )}
      {data.status !== "accepted" && (
        <RerunVerifierControl runId={data.run_id} onComplete={onReplayComplete} />
      )}
      {data.retrofit_gates && <RetrofitGatesPanel res={data.retrofit_gates} />}
      {data.ground_truth && data.status === "accepted" && (
        <FixPovReplayControl runId={data.run_id} onComplete={onReplayComplete} />
      )}
      {data.fix_pov_eval && <FixPovEvalPanel gte={data.fix_pov_eval} />}
      {data.ground_truth && data.status === "accepted" && (
        <ResidualReplayControl runId={data.run_id} onComplete={onReplayComplete} />
      )}
      {data.residual_eval && <ResidualEvalPanel res={data.residual_eval} />}
      <div className="grid gap-6 lg:grid-cols-2">
        <section className="space-y-3">
          <div className="eyebrow">taint trace · source → sink</div>
          <div className="panel p-4">
            {data.alert_trace ? <TraceView trace={data.alert_trace} /> : <Empty>no trace</Empty>}
          </div>
        </section>
        <section className="space-y-3">
          <div className="eyebrow">container commands</div>
          <div className="space-y-2">
            {data.commands.length === 0 && <Empty>no commands ran</Empty>}
            {/* A gate that retried runs the same command name more than once
                (one POV-after per correction attempt), so the index is part of
                the key. */}
            {data.commands.map((c, i) => (
              <CommandRow key={`${c.name}-${i}`} runId={data.run_id} cmd={c} />
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

function CommandRow({ runId, cmd }: { runId: string; cmd: CommandResult }) {
  const [open, setOpen] = useState(false);
  const [log, setLog] = useState<string | null>(null);
  const isResidualPov = cmd.name.startsWith("respov_");
  // Exploit checks after patching are meant to fail (non-zero == blocked).
  const expectedFail =
    cmd.expected_failure ??
    (cmd.name === "pov_after_patch" ||
      /^harden_(variant_after|original_recheck|final_replay)_r\d+$/.test(cmd.name));
  // An evaluation POV carries the evaluator's own verdict, which is not the raw
  // exit code: a harness error (exit 2) or a timeout (124) is inconclusive, not a
  // blocked exploit, and must not read as green here while the coverage panel
  // calls the same run errored. A reproduced residual POV is neutral because it
  // means the patch matches the official fix; a reproduced fixPOV is
  // still a coverage miss.
  const good = cmd.outcome
    ? cmd.outcome === "blocked"
    : expectedFail
      ? cmd.exit_code !== 0
      : cmd.exit_code === 0;
  const dot =
    cmd.outcome === "errored"
      ? "bg-warn"
      : isResidualPov && cmd.outcome === "reproduced"
        ? "bg-txt-faint"
        : good
          ? "bg-pass"
          : "bg-fail";

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && log == null && cmd.log) api.log(runId, cmd.log).then(setLog).catch((e) => setLog(String(e)));
  }

  return (
    <div className="panel overflow-hidden">
      <button
        type="button"
        onClick={toggle}
        disabled={!cmd.log}
        className="focusable flex w-full items-center gap-3 px-4 py-2.5 text-left card-hover disabled:cursor-default"
      >
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <span className="font-mono text-xs text-txt">{cmd.name}</span>
        <span className="ml-auto flex items-center gap-3 font-mono text-2xs text-txt-faint">
          <span>exit {cmd.exit_code}</span>
          {cmd.outcome && <span className="text-txt-faint">({cmd.outcome})</span>}
          {!cmd.outcome && expectedFail && <span className="text-txt-faint">(expected)</span>}
          {cmd.log && <span className={`transition-transform ${open ? "rotate-90" : ""}`}>›</span>}
        </span>
      </button>
      {open && (
        <div className="max-h-96 overflow-auto border-t border-hairline bg-ink2/40">
          <pre className="whitespace-pre-wrap break-words p-3 font-mono text-2xs leading-relaxed text-txt-dim">
            {log ?? "loading…"}
          </pre>
        </div>
      )}
    </div>
  );
}

function DiffsTab({ runId, available }: { runId: string; available: Record<string, boolean> }) {
  const kinds = [
    { key: "patch_only", label: "patch only" },
    { key: "full", label: "full (patch + POV)" },
    { key: "pov", label: "POV only" },
  ].filter((k) => available[k.key]);
  const [kind, setKind] = useState(kinds[0]?.key ?? "patch_only");
  const { data, error, loading } = useAsync<string>(() => api.diff(runId, kind), [runId, kind]);

  return (
    <div className="space-y-3">
      <div className="flex gap-1">
        {kinds.map((k) => (
          <button
            key={k.key}
            type="button"
            onClick={() => setKind(k.key)}
            className={`focusable rounded-md border px-3 py-1.5 font-mono text-2xs transition-colors ${
              kind === k.key ? "border-iris/50 bg-elevated text-txt" : "border-hairline text-txt-dim hover:text-txt"
            }`}
          >
            {k.label}
          </button>
        ))}
      </div>
      <div className="panel overflow-hidden py-2">
        {loading && <div className="p-4 font-mono text-2xs text-txt-faint animate-pulse2">loading diff…</div>}
        {error && <div className="p-4 font-mono text-2xs text-fail">{error}</div>}
        {data != null && <DiffViewer diff={data} />}
      </div>
    </div>
  );
}
