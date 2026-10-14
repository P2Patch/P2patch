import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost, duration, statusTone, tokens } from "../lib/format";
import type { San2PatchResult } from "../types";
import { StatusPill } from "../components/StatusPill";
import { DiffViewer } from "../components/DiffViewer";
import { PovReplayControl } from "../components/PovReplayControl";
import { FixPovEvalPanel } from "../components/FixPovEvalPanel";
import { ResidualEvalPanel } from "../components/ResidualEvalPanel";

type SubTab = "summary" | "patch" | "povreplay" | "attempts" | "log" | "traces";

function Field({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-1 font-mono text-sm text-txt">{value}</div>
      {hint && <div className="mt-0.5 text-2xs text-txt-faint">{hint}</div>}
    </div>
  );
}

/** Lazily fetched text panel — traces are ~230 KB each, so they load on demand. */
function TextFetch({ load, empty }: { load: () => Promise<string>; empty: string }) {
  const { data, error, loading } = useAsync<string>(load, []);
  if (loading) return <div className="font-mono text-2xs text-txt-faint animate-pulse2">loading…</div>;
  if (error) return <div className="font-mono text-2xs text-fail">{error}</div>;
  if (!data) return <div className="font-mono text-2xs text-txt-faint">{empty}</div>;
  return (
    <pre className="max-h-[36rem] overflow-auto whitespace-pre-wrap break-all font-mono text-2xs text-txt-dim">
      {data}
    </pre>
  );
}

/** DiffViewer renders text it is given; this fetches it first. */
function LazyDiff({ load }: { load: () => Promise<string> }) {
  const { data, error, loading } = useAsync<string>(load, []);
  if (loading) return <div className="panel p-4 font-mono text-2xs text-txt-faint animate-pulse2">loading diff…</div>;
  if (error) return <div className="panel p-4 font-mono text-2xs text-fail">{error}</div>;
  return (
    <div className="panel overflow-hidden">
      <DiffViewer diff={data ?? ""} emptyLabel="patch is empty" />
    </div>
  );
}

export function San2PatchDetail() {
  const { key = "" } = useParams();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, error, loading } = useAsync<San2PatchResult>(() => api.san2patchResult(key), [key, refreshKey]);
  const [tab, setTab] = useState<SubTab>("summary");
  const [trace, setTrace] = useState<string | null>(null);
  const onReplayComplete = () => setRefreshKey((k) => k + 1);

  if (loading)
    return <div className="mx-auto max-w-6xl px-6 py-10 font-mono text-xs text-txt-faint animate-pulse2">loading case…</div>;
  if (error || !data)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Link to="/san2patch" className="text-iris hover:underline">← San2Patch</Link>
        <div className="panel mt-4 border-fail/40 p-4 font-mono text-xs text-fail">{error ?? "not found"}</div>
      </div>
    );

  const tone = statusTone(data.valid === false ? "skipped" : data.patch_found ? "pass" : "fail");
  const tabs: { key: SubTab; label: string; badge?: string }[] = [
    { key: "summary", label: "Summary" },
    { key: "patch", label: "Patch", badge: data.has_patch ? undefined : "none" },
    { key: "povreplay", label: "POV replay" },
    { key: "attempts", label: "Attempts" },
    { key: "log", label: "Runtime log", badge: data.logs_available.length ? undefined : "none" },
    { key: "traces", label: "ToT traces", badge: `${data.traces.length}` },
  ];

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <Link to="/san2patch" className="focusable font-mono text-2xs text-txt-faint hover:text-iris">← San2Patch</Link>

      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-2xl font-bold text-txt">{data.cve}</h1>
            <StatusPill status={data.status} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="chip">San2Patch</span>
            <span className="chip">{data.project}</span>
            {data.batch && <span className="chip text-txt-dim" title="batch that produced this attempt">{data.batch}</span>}
          </div>
        </div>
        <div className={`font-mono text-2xs ${tone.text}`}>
          {data.valid === false ? "no attempt reached the model" : data.patch_found ? "patch produced" : "no patch"}
        </div>
      </header>

      {/* A case that ran twice: say so on the page, not just in the CSV. Which
          attempt is being shown is the difference between a comparable number and
          an inflated one. */}
      {data.superseded_by && (
        <div className="panel mt-4 border-warn/40 p-4 text-2xs text-txt-dim">
          This case ran to completion twice. You are viewing the <strong className="text-txt">first</strong> attempt
          ({data.status}), which is the one counted; a later attempt in{" "}
          <span className="font-mono">{data.superseded_by.batch}</span> ended{" "}
          <span className="font-mono">{data.superseded_by.status}</span>. San2Patch already retries 5 times
          internally, so counting the better of two full runs would be best-of-10 and not comparable with the paper.
        </div>
      )}

      <nav className="mt-6 flex flex-wrap gap-1 border-b border-hairline">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`focusable -mb-px border-b-2 px-3 py-2 font-mono text-2xs ${
              tab === t.key ? "border-iris text-iris" : "border-transparent text-txt-dim hover:text-txt"
            }`}
          >
            {t.label}
            {t.badge && <span className="ml-1.5 text-txt-faint">{t.badge}</span>}
          </button>
        ))}
      </nav>

      <div className="mt-6">
        {tab === "summary" && (
          <div className="space-y-4">
            <div className="panel grid grid-cols-2 gap-5 p-5 md:grid-cols-4">
              <Field label="tries" value={`${data.tries ?? "—"}`} hint="of 5 allowed" />
              <Field
                label="wall time"
                value={data.elapsed_seconds ? duration(data.elapsed_seconds * 1000) : "—"}
                hint={data.contended ? "⚠ host was loaded — exclude from timings" : undefined}
              />
              <Field label="cost" value={cost(data.cost_usd)} />
              <Field label="tokens" value={tokens(data.total_tokens)} />
            </div>
            {data.message && <div className="panel p-4 text-2xs text-txt-dim">{data.message}</div>}
            {data.fix_pov_eval && <FixPovEvalPanel gte={data.fix_pov_eval} />}
            {data.residual_eval && <ResidualEvalPanel res={data.residual_eval} />}
          </div>
        )}

        {tab === "patch" &&
          (data.has_patch ? (
            <LazyDiff load={() => api.san2patchDiff(key)} />
          ) : (
            <div className="panel p-5 font-mono text-2xs text-txt-faint">
              San2Patch produced no patch for this case — it exhausted all {data.tries ?? 5} tries.
            </div>
          ))}

        {tab === "povreplay" && (
          <div className="space-y-4">
            <PovReplayControl
              targetKey={key}
              family="fix-pov"
              toolLabel="San2Patch"
              fetchStatus={api.san2patchFixpovReplay}
              startReplay={api.startSan2patchFixpovReplay}
              onComplete={onReplayComplete}
            />
            <PovReplayControl
              targetKey={key}
              family="residual"
              toolLabel="San2Patch"
              fetchStatus={api.san2patchRespovReplay}
              startReplay={api.startSan2patchRespovReplay}
              onComplete={onReplayComplete}
            />
            {data.fix_pov_eval && <FixPovEvalPanel gte={data.fix_pov_eval} />}
            {data.residual_eval && <ResidualEvalPanel res={data.residual_eval} />}
          </div>
        )}

        {tab === "attempts" && (
          <div className="panel p-5">
            <p className="mb-3 text-2xs text-txt-dim">
              San2Patch's own per-try record (<span className="font-mono">res.txt</span>). One line per attempt;
              <span className="font-mono"> code</span> is its own verdict, not ours.
            </p>
            <pre className="overflow-auto font-mono text-2xs text-txt-dim">{data.res_txt ?? "no res.txt"}</pre>
          </div>
        )}

        {tab === "log" &&
          (data.logs_available.length ? (
            <div className="panel p-5">
              <p className="mb-3 text-2xs text-txt-dim">
                This case's own runtime log, sliced out of its batch's interleaved{" "}
                <span className="font-mono">run.log</span> by time window — the per-batch log holds five cases at once.
              </p>
              <TextFetch load={() => api.san2patchLog(key)} empty="log is empty" />
            </div>
          ) : (
            <div className="panel p-5 font-mono text-2xs text-txt-faint">no per-case log for this case</div>
          ))}

        {tab === "traces" && (
          <div className="space-y-3">
            <p className="text-2xs text-txt-dim">
              Full Tree-of-Thought state per attempt: every stage's reasoning, the candidate patches considered, and
              which was selected. These are large (~200 KB) and load on demand.
            </p>
            <div className="flex flex-wrap gap-2">
              {data.traces.map((t) => (
                <button
                  key={t}
                  onClick={() => setTrace(t)}
                  className={`focusable chip ${trace === t ? "bg-iris/15 text-iris" : "text-txt-dim hover:text-txt"}`}
                >
                  {t}
                </button>
              ))}
              {data.traces.length === 0 && <span className="font-mono text-2xs text-txt-faint">no traces</span>}
            </div>
            {trace && (
              <div className="panel p-4">
                <TextFetch key={trace} load={() => api.san2patchTrace(key, trace)} empty="trace is empty" />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
