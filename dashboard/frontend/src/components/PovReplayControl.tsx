import { useCallback, useEffect, useRef, useState } from "react";
import { PUBLISHED } from "../api";
import type { FixPovReplayStatus, ResidualReplayStatus } from "../types";

type ReplayStatus = FixPovReplayStatus | ResidualReplayStatus;

/**
 * "Re-score this patch against our curated POVs" — one control for every
 * (baseline tool × POV family) pair.
 *
 * There is nothing tool-specific in the behaviour: every one of these is the same
 * `run_jobs.JobKind` background job, polled the same way, and differs only in which
 * two endpoints it calls and what the copy says. It was two near-identical files
 * (LoopRepair × fixpov/respov) and adding San2Patch would have made four, at which
 * point a fix applied to one and not the others is a matter of time.
 *
 * The caller passes the two API functions rather than a tool name, so adding a third
 * baseline needs no change here at all.
 */
export function PovReplayControl({
  targetKey,
  family,
  toolLabel,
  fetchStatus,
  startReplay,
  onComplete,
}: {
  targetKey: string;
  family: "fix-pov" | "residual";
  toolLabel: string;
  fetchStatus: (key: string) => Promise<ReplayStatus>;
  startReplay: (key: string) => Promise<ReplayStatus>;
  onComplete: () => void;
}) {
  const [status, setStatus] = useState<ReplayStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sawRunning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const next = await fetchStatus(targetKey);
      setStatus(next);
      setError(null);
      return next;
    } catch (err) {
      setError(String((err as Error).message ?? err));
      return null;
    }
  }, [targetKey, fetchStatus]);

  useEffect(() => {
    if (!PUBLISHED) void refresh();
  }, [refresh]);

  useEffect(() => {
    if (status?.state !== "running") return;
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => window.clearInterval(timer);
  }, [status?.state, refresh]);

  // Fire onComplete only on a running -> done transition, not on every poll that
  // happens to see "done" — otherwise landing on an already-scored case would
  // refetch the page forever.
  useEffect(() => {
    if (status?.state === "running") {
      sawRunning.current = true;
    } else if (sawRunning.current && status?.state === "done") {
      sawRunning.current = false;
      onComplete();
    }
  }, [status?.state, onComplete]);

  if (PUBLISHED) return null;

  async function start() {
    setError(null);
    sawRunning.current = true;
    try {
      setStatus(await startReplay(targetKey));
    } catch (err) {
      sawRunning.current = false;
      setError(String((err as Error).message ?? err));
    }
  }

  const running = status?.state === "running";
  const available = status?.available === true;
  const buttonLabel = running
    ? `replaying ${family} POVs…`
    : status?.state === "done"
      ? "replay again"
      : status?.state === "error"
        ? "try replay again"
        : `replay ${family} POVs`;

  const idle =
    family === "fix-pov"
      ? `Score this case's ${toolLabel} patch against the same certified fixPOVs the pipeline's own runs are measured with.`
      : `Check whether this case's ${toolLabel} patch closes gaps the official upstream fix leaves open. A score of 0 is the normal result.`;

  return (
    <section className="panel flex flex-wrap items-center justify-between gap-4 border-iris/25 px-4 py-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse2 bg-warn" : "bg-iris"}`} />
          <span className="font-mono text-xs text-txt">{family} replay</span>
          {status?.state === "done" && <span className="chip text-pass">complete</span>}
          {status?.state === "error" && <span className="chip text-fail">failed</span>}
        </div>
        <p className="mt-1 text-2xs text-txt-dim">
          {running
            ? `Applying ${toolLabel}'s patch to the vulnerable revision and running the curated ${family} POVs against it.`
            : (status?.unavailable_reason ?? idle)}
        </p>
        {(error || status?.error) && (
          <p className="mt-1 font-mono text-2xs text-fail">{error ?? status?.error}</p>
        )}
        {status?.state === "error" && status.log_tail.length > 0 && (
          <pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap font-mono text-2xs text-txt-faint">
            {status.log_tail.join("\n")}
          </pre>
        )}
      </div>
      <button
        type="button"
        onClick={start}
        disabled={!available || running}
        className="focusable shrink-0 rounded-md border border-iris/50 bg-iris/10 px-4 py-2 font-mono text-2xs text-iris hover:bg-iris/20 disabled:cursor-not-allowed disabled:border-hairline disabled:bg-transparent disabled:text-txt-faint"
      >
        {buttonLabel}
      </button>
    </section>
  );
}
