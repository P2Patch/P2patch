import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost, duration, statusTone, tokens } from "../lib/format";
import type { PatchAgentResult } from "../types";
import { StatusPill } from "../components/StatusPill";
import { DiffViewer } from "../components/DiffViewer";
import { PovReplayControl } from "../components/PovReplayControl";
import { FixPovEvalPanel } from "../components/FixPovEvalPanel";
import { ResidualEvalPanel } from "../components/ResidualEvalPanel";

type SubTab = "summary" | "patch" | "povscores" | "attempts" | "logs" | "traces";

function Field({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-1 font-mono text-sm text-txt">{value}</div>
      {hint && <div className="mt-0.5 text-2xs text-txt-faint">{hint}</div>}
    </div>
  );
}

/** Lazily fetched text panel — the 15-iteration case's driver log is ~1 MB. */
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

export function PatchAgentDetail() {
  const { key = "" } = useParams();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, error, loading } = useAsync<PatchAgentResult>(
    () => api.patchAgentResult(key),
    [key, refreshKey],
  );
  const [tab, setTab] = useState<SubTab>("summary");
  const [trace, setTrace] = useState<string | null>(null);
  const [log, setLog] = useState<string | null>(null);
  // A finished replay rewrites <case>/fix_pov/results.json, so refetch rather
  // than leave the panel showing the score the page loaded with.
  const onReplayComplete = () => setRefreshKey((k) => k + 1);

  if (loading)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10 font-mono text-xs text-txt-faint animate-pulse2">loading case…</div>
    );
  if (error || !data)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Link to="/patchagent" className="text-iris hover:underline">
          ← PatchAgent
        </Link>
        <div className="panel mt-4 border-fail/40 p-4 font-mono text-xs text-fail">{error ?? "not found"}</div>
      </div>
    );

  const tone = statusTone(data.valid === false ? "skipped" : data.patch_found ? "pass" : "fail");
  const activeLog = log ?? data.logs_available[0] ?? null;
  const tabs: { key: SubTab; label: string; badge?: string }[] = [
    { key: "summary", label: "Summary" },
    { key: "patch", label: "Patch", badge: data.has_patch ? undefined : "none" },
    { key: "povscores", label: "POV scores" },
    { key: "attempts", label: "Attempts", badge: `${data.attempts.length}` },
    { key: "logs", label: "Logs", badge: data.logs_available.length ? undefined : "none" },
    { key: "traces", label: "Agent traces", badge: `${data.traces.length}` },
  ];

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <Link to="/patchagent" className="focusable font-mono text-2xs text-txt-faint hover:text-iris">
        ← PatchAgent
      </Link>

      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-2xl font-bold text-txt">{data.cve}</h1>
            <StatusPill status={data.status} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="chip">PatchAgent</span>
            <span className="chip">{data.project}</span>
            {data.batch && (
              <span className="chip text-txt-dim" title="batch that ran this case">
                {data.batch}
              </span>
            )}
            {data.max_iteration != null && (
              <span className={`chip ${data.effort_comparable ? "text-txt-dim" : "text-warn"}`}>
                --max-iteration {data.max_iteration}
              </span>
            )}
          </div>
        </div>
        <div className={`font-mono text-2xs ${tone.text}`}>
          {data.valid === false ? "never attempted" : data.patch_found ? "patch produced" : "no patch"}
        </div>
      </header>

      {/* A case that ran at a different attempt budget than the rest: say so on the
          page, not just in the manifest. It is the difference between a comparable
          number and one that is not. */}
      {data.effort_comparable === false && data.max_iteration != null && (
        <div className="panel mt-4 border-warn/40 p-4 text-2xs text-txt-dim">
          This case ran at <strong className="text-txt">--max-iteration {data.max_iteration}</strong>, not the{" "}
          <span className="font-mono">3</span> every other case in this arm used — it fails at 3 and needed the full
          <span className="font-mono"> DefaultPolicy</span> ladder. Its effort and cost are{" "}
          <strong className="text-txt">not</strong> comparable with the other rows: {data.tries ?? "?"} candidate
          patches across {data.agents_used ?? "?"} agents.
        </div>
      )}

      {data.shared_run_with.length > 0 && (
        <div className="panel mt-4 border-warn/40 p-4 text-2xs text-txt-dim">
          This is <strong className="text-txt">one</strong> PatchAgent run whose single patch also answers{" "}
          {data.shared_run_with.map((c) => (
            <Link key={c} to={`/patchagent/${encodeURIComponent(c)}`} className="font-mono text-iris hover:underline">
              {c}
            </Link>
          ))}
          . The cost, tokens and attempts below belong to that run, not to this CVE alone — the arm's totals count
          them once. Our POV sets score the two CVEs separately and can disagree, which is why they are separate rows.
        </div>
      )}

      {data.valid === false && (
        <div className="panel mt-4 border-hairline p-4 text-2xs text-txt-dim">{data.message}</div>
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
              <Field
                label="validate() calls"
                value={`${data.tries ?? "—"}`}
                hint={data.rejected_attempts ? `${data.rejected_attempts} rejected` : undefined}
              />
              <Field
                label="wall time"
                value={data.elapsed_seconds ? duration(data.elapsed_seconds * 1000) : "—"}
                hint={data.llm_calls ? `${data.llm_calls} LLM calls` : undefined}
              />
              <Field
                label="cost (measured)"
                value={cost(data.cost_usd)}
                hint="from measured token counts"
              />
              <Field
                label="tokens"
                value={tokens(data.total_tokens)}
                hint={`${tokens(data.prompt_tokens)} in / ${tokens(data.completion_tokens)} out`}
              />
            </div>

            {data.functional_baseline && (
              <div className="panel p-4 text-2xs text-txt-dim">
                <span className="eyebrow">pre-LLM functional baseline</span>{" "}
                <span className={data.functional_baseline.status === "passed" ? "text-pass" : "text-fail"}>
                  {data.functional_baseline.status}
                </span>{" "}
                in {data.functional_baseline.seconds}s (exit {data.functional_baseline.exit_code}) — the project's own
                suite on the <em>unpatched</em> tree. PatchAgent's <span className="font-mono">validate()</span> gate
                compares against this, so a red baseline means no patch could ever be accepted.
              </div>
            )}

            {data.message && data.valid !== false && (
              <div className="panel p-4 text-2xs text-txt-dim">{data.message}</div>
            )}
            {data.fix_pov_eval && <FixPovEvalPanel gte={data.fix_pov_eval} />}
            {data.residual_eval && <ResidualEvalPanel res={data.residual_eval} />}
          </div>
        )}

        {tab === "patch" &&
          (data.has_patch ? (
            <LazyDiff load={() => api.patchAgentDiff(key)} />
          ) : (
            <div className="panel p-5 font-mono text-2xs text-txt-faint">
              No PatchAgent patch exists for this case.
            </div>
          ))}

        {tab === "povscores" && (
          <div className="space-y-4">
            <p className="text-2xs text-txt-dim">
              Our re-scoring of this patch. The buttons below re-run one family against the current certified
              manifests — the same <span className="font-mono">fixpov replay-patch</span> oracle a pipeline run and a
              San2Patch case use, so the numbers stay comparable. Read the two panels in{" "}
              <strong className="text-txt">opposite directions</strong>: a blocked fixPOV means the patch
              matches what upstream's official fix closes, while a residual POV that still reproduces means the patch
              is exactly as good as upstream, which is the expected neutral result and not a failure.
            </p>
            <PovReplayControl
              targetKey={key}
              family="fix-pov"
              toolLabel="PatchAgent"
              fetchStatus={api.patchAgentFixpovReplay}
              startReplay={api.startPatchAgentFixpovReplay}
              onComplete={onReplayComplete}
            />
            <PovReplayControl
              targetKey={key}
              family="residual"
              toolLabel="PatchAgent"
              fetchStatus={api.patchAgentRespovReplay}
              startReplay={api.startPatchAgentRespovReplay}
              onComplete={onReplayComplete}
            />
            {data.fix_pov_eval ? (
              <FixPovEvalPanel gte={data.fix_pov_eval} />
            ) : (
              <div className="panel p-5 font-mono text-2xs text-txt-faint">
                no curated fixPOV manifest scored for this case
              </div>
            )}
            {data.residual_eval ? (
              <ResidualEvalPanel res={data.residual_eval} />
            ) : (
              <div className="panel p-5 font-mono text-2xs text-txt-faint">
                no curated residual POV manifest for this case — which is not a score of zero
              </div>
            )}
          </div>
        )}

        {tab === "attempts" && (
          <div className="space-y-3">
            <p className="text-2xs text-txt-dim">
              Every candidate submitted to PatchAgent's own <span className="font-mono">validate()</span>, with the
              full validator verdict — a rejection carries the post-patch symbolized sanitizer report it fed back to
              the agent. <span className="font-mono">accepted</span> is its verdict, not ours.
            </p>
            {data.attempts.length === 0 && (
              <div className="panel p-5 font-mono text-2xs text-txt-faint">no candidates were submitted</div>
            )}
            {data.attempts.map((a, i) => (
              <details key={i} className="panel p-4">
                <summary className="cursor-pointer font-mono text-2xs text-txt-dim">
                  <span className={a.accepted === "True" ? "text-pass" : "text-txt-faint"}>
                    {a.accepted === "True" ? "accepted" : "rejected"}
                  </span>{" "}
                  · agent {a.agent_number} · attempt {a.attempt_in_agent}
                </summary>
                <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all font-mono text-2xs text-txt-dim">
                  {a.verdict}
                </pre>
              </details>
            ))}
          </div>
        )}

        {tab === "logs" &&
          (data.logs_available.length ? (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {data.logs_available.map((n) => (
                  <button
                    key={n}
                    onClick={() => setLog(n)}
                    className={`focusable chip ${
                      activeLog === n ? "bg-iris/15 text-iris" : "text-txt-dim hover:text-txt"
                    }`}
                  >
                    {n}
                  </button>
                ))}
              </div>
              {activeLog && (
                <div className="panel p-5">
                  <TextFetch key={activeLog} load={() => api.patchAgentLog(key, activeLog)} empty="log is empty" />
                </div>
              )}
            </div>
          ) : (
            <div className="panel p-5 font-mono text-2xs text-txt-faint">no logs kept for this case</div>
          ))}

        {tab === "traces" && (
          <div className="space-y-3">
            <p className="text-2xs text-txt-dim">
              One file per agent attempt on PatchAgent's <span className="font-mono">DefaultPolicy</span> ladder: every{" "}
              <span className="font-mono">viewcode</span> / <span className="font-mono">locate</span> /{" "}
              <span className="font-mono">validate</span> call, its arguments and its result. These are large and load
              on demand.
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
                <TextFetch key={trace} load={() => api.patchAgentTrace(key, trace)} empty="trace is empty" />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
