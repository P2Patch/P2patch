import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { PUBLISHED, api } from "../api";
import type { AnalysisResponse } from "../types";

interface Props<T> {
  runId: string;
  agent: string;
  intro: string;
  runLabel: string;
  runningLabel?: string;
  /** Optional second trigger that runs the judge N times and stabilizes the score. */
  ensemble?: { samples: number; label: string; note?: string };
  render: (result: T) => ReactNode;
}

/** Generic driver for an on-demand analysis agent: fetch → poll while running →
 *  trigger, with a caller-supplied result renderer. */
export function AnalysisPanel<T>({ runId, agent, intro, runLabel, runningLabel, ensemble, render }: Props<T>) {
  const [resp, setResp] = useState<AnalysisResponse<T> | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const r = await api.analysis<T>(runId, agent);
      setResp(r);
      setErr(null);
      return r;
    } catch (e) {
      setErr(String((e as Error).message ?? e));
      return null;
    }
  }, [runId, agent]);

  useEffect(() => {
    setInitialLoading(true);
    refresh().finally(() => setInitialLoading(false));
  }, [refresh]);

  const running = resp?.status.state === "running";
  useEffect(() => {
    if (!running) return;
    const t = setInterval(refresh, 2500);
    return () => clearInterval(t);
  }, [running, refresh]);

  async function run(force = false, samples?: number) {
    setErr(null);
    try {
      await api.startAnalysis(runId, agent, force, samples);
      await refresh();
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    }
  }

  if (initialLoading) return <div className="font-mono text-2xs text-txt-faint animate-pulse2">loading…</div>;

  const state = resp?.status.state ?? "absent";
  const result = resp?.result ?? null;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-txt-dim">{intro}</p>
        {/* Re-running the judge spends Claude tokens — only in the live app. */}
        {!PUBLISHED && result && state !== "running" && (
          <div className="flex shrink-0 items-center gap-2">
            {ensemble && (
              <button
                type="button"
                onClick={() => run(true, ensemble.samples)}
                title={ensemble.note}
                className="focusable rounded-md border border-iris/50 bg-iris/10 px-3 py-1.5 font-mono text-2xs text-iris hover:bg-iris/20"
              >
                {ensemble.label}
              </button>
            )}
            <button
              type="button"
              onClick={() => run(true)}
              className="focusable rounded-md border border-hairline bg-elevated px-3 py-1.5 font-mono text-2xs text-txt-dim hover:border-iris/50 hover:text-txt"
            >
              re-run
            </button>
          </div>
        )}
      </div>

      {err && <Note tone="fail">{err}</Note>}

      {state === "running" && (
        <div className="panel flex items-center gap-3 p-5">
          <span className="h-2.5 w-2.5 animate-pulse2 rounded-full bg-warn" />
          <span className="text-sm text-txt-dim">{runningLabel ?? "Running — this takes ~1–3 minutes."}</span>
        </div>
      )}

      {state === "error" && (
        <Note tone="fail">
          Failed: {resp?.status.error}
          {!PUBLISHED && (
            <div className="mt-2">
              <RunButton onClick={() => run(true)}>try again</RunButton>
            </div>
          )}
        </Note>
      )}

      {state === "absent" && !err && (
        PUBLISHED ? (
          <div className="panel p-6 text-sm text-txt-faint">
            This evaluation wasn’t run for this experiment, so it isn’t part of the published snapshot.
          </div>
        ) : (
          <div className="panel flex flex-col items-start gap-3 p-6">
            <p className="text-sm text-txt-dim">Not run yet for this experiment.</p>
            <div className="flex flex-wrap items-center gap-3">
              <RunButton onClick={() => run(false)}>{runLabel}</RunButton>
              {ensemble && (
                <button
                  type="button"
                  onClick={() => run(false, ensemble.samples)}
                  className="focusable rounded-md border border-iris/40 bg-iris/5 px-4 py-2 text-sm text-iris hover:bg-iris/15"
                >
                  {ensemble.label}
                </button>
              )}
            </div>
            {ensemble?.note && <p className="max-w-xl text-2xs text-txt-faint">{ensemble.note}</p>}
          </div>
        )
      )}

      {result && <div className={state === "running" ? "opacity-50" : ""}>{render(result)}</div>}
    </div>
  );
}

export function RunButton({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="focusable rounded-md border border-iris/50 bg-iris/10 px-4 py-2 text-sm text-txt hover:bg-iris/20"
    >
      {children}
    </button>
  );
}

export function Note({ children, tone }: { children: ReactNode; tone?: "fail" }) {
  return (
    <div className={`panel p-4 text-sm ${tone === "fail" ? "border-fail/40 text-fail" : "text-txt-dim"}`}>{children}</div>
  );
}
