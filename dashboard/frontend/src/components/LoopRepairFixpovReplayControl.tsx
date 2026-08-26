import { useCallback, useEffect, useRef, useState } from "react";
import { PUBLISHED, api } from "../api";
import type { FixPovReplayStatus } from "../types";

// Mirrors FixPovReplayControl, pointed at a LoopRepair CVE instead of a
// pipeline run — same job shape (run_jobs.JobKind), just keyed by the
// LoopRepair "<project>__<cve>" key instead of a run_id.
export function LoopRepairFixpovReplayControl({
  cveKey,
  onComplete,
}: {
  cveKey: string;
  onComplete: () => void;
}) {
  const [status, setStatus] = useState<FixPovReplayStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sawRunning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const next = await api.loopRepairFixpovReplay(cveKey);
      setStatus(next);
      setError(null);
      return next;
    } catch (err) {
      setError(String((err as Error).message ?? err));
      return null;
    }
  }, [cveKey]);

  useEffect(() => {
    if (!PUBLISHED) void refresh();
  }, [refresh]);

  useEffect(() => {
    if (status?.state !== "running") return;
    const timer = window.setInterval(() => void refresh(), 2000);
    return () => window.clearInterval(timer);
  }, [status?.state, refresh]);

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
      setStatus(await api.startLoopRepairFixpovReplay(cveKey));
    } catch (err) {
      sawRunning.current = false;
      setError(String((err as Error).message ?? err));
    }
  }

  const running = status?.state === "running";
  const available = status?.available === true;
  const label = running
    ? "replaying POVs…"
    : status?.state === "done"
      ? "replay again"
      : status?.state === "error"
        ? "try replay again"
        : "replay fixPOVs";

  return (
    <section className="panel flex flex-wrap items-center justify-between gap-4 border-iris/25 px-4 py-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse2 bg-warn" : "bg-iris"}`} />
          <span className="font-mono text-xs text-txt">fixPOV replay</span>
          {status?.state === "done" && <span className="chip text-pass">complete</span>}
          {status?.state === "error" && <span className="chip text-fail">failed</span>}
        </div>
        <p className="mt-1 text-2xs text-txt-dim">
          {running
            ? "Applying LoopRepair's patch to the vulnerable revision and running the curated fixPOVs against it."
            : status?.unavailable_reason ??
              "Score this CVE's LoopRepair patch against the same certified fixPOVs the pipeline's own runs are measured with."}
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
        {label}
      </button>
    </section>
  );
}
