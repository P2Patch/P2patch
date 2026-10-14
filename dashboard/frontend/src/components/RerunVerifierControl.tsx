import { useCallback, useEffect, useRef, useState } from "react";
import { PUBLISHED, api } from "../api";
import type { VerifierRerunJobStatus } from "../types";

/**
 * Re-runs the verifier for a run that was rejected only because the verifier
 * AGENT crashed (an expired OAuth session, structured-output-retry exhaustion, a
 * transient API error) while every objective gate — POV-after, hardening,
 * regression — passed. A crashed agent is infrastructure, not a verdict.
 *
 * Unlike the retrofit control this DOES change the run's status — but only on a
 * genuine `accepted` verdict. A fresh `rejected` verdict is left as a rejection,
 * so this never launders a real rejection into a pass. The control only appears
 * for a rejected run whose verifier crashed.
 */
export function RerunVerifierControl({
  runId,
  onComplete,
}: {
  runId: string;
  onComplete: () => void;
}) {
  const [status, setStatus] = useState<VerifierRerunJobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sawRunning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const next = await api.rerunVerifier(runId);
      setStatus(next);
      setError(null);
      return next;
    } catch (err) {
      setError(String((err as Error).message ?? err));
      return null;
    }
  }, [runId]);

  useEffect(() => {
    if (!PUBLISHED) void refresh();
  }, [refresh]);

  useEffect(() => {
    if (status?.state !== "running") return;
    // The verifier reviews the patch and may rebuild/test in the container, so
    // this is minutes — poll gently.
    const timer = window.setInterval(() => void refresh(), 4000);
    return () => window.clearInterval(timer);
  }, [status?.state, refresh]);

  useEffect(() => {
    if (status?.state === "running") {
      sawRunning.current = true;
    } else if (sawRunning.current && status?.state === "done") {
      sawRunning.current = false;
      // The run's status may have flipped to accepted — reload the whole run.
      onComplete();
    }
  }, [status?.state, onComplete]);

  if (PUBLISHED) return null;
  // Only relevant for a rejected run whose verifier crashed; otherwise hide.
  if (status && !status.available && status.state === "absent") return null;

  async function start() {
    setError(null);
    sawRunning.current = true;
    try {
      setStatus(await api.startRerunVerifier(runId));
    } catch (err) {
      sawRunning.current = false;
      setError(String((err as Error).message ?? err));
    }
  }

  const running = status?.state === "running";
  const available = status?.available === true;
  const result = status?.result ?? null;
  const flipped = result?.flipped === true;
  const label = running
    ? "re-running verifier…"
    : status?.state === "done"
      ? "re-run verifier again"
      : status?.state === "error"
        ? "try again"
        : "re-run verifier";

  return (
    <section className="panel flex flex-wrap items-center justify-between gap-4 border-warn/30 px-4 py-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse2 bg-warn" : "bg-warn"}`} />
          <span className="font-mono text-xs text-txt">re-run verifier</span>
          {status?.state === "done" && flipped && <span className="chip text-pass">flipped to accepted</span>}
          {status?.state === "done" && result && !flipped && (
            <span className="chip text-fail">
              {result.status === "errored" ? "still errored" : "verifier rejected"}
            </span>
          )}
          {status?.state === "error" && <span className="chip text-fail">failed</span>}
        </div>
        <p className="mt-1 text-2xs text-txt-dim">
          {running
            ? "The verifier is reviewing this patch again. This takes minutes."
            : result && !flipped
              ? result.status === "errored"
                ? "The verifier agent crashed again (e.g. an expired OAuth session). Refresh the pipeline's Claude session and try again."
                : "The verifier reviewed the patch and rejected it — this run's rejection stands."
              : status?.unavailable_reason ??
                "This run was rejected only because the verifier agent crashed (no verdict) while the objective gates passed. Re-run the verifier; if it accepts, the run flips to accepted. A genuine rejection is left unchanged."}
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
        className="focusable shrink-0 rounded-md border border-warn/50 bg-warn/10 px-4 py-2 font-mono text-2xs text-warn hover:bg-warn/20 disabled:cursor-not-allowed disabled:border-hairline disabled:bg-transparent disabled:text-txt-faint"
      >
        {label}
      </button>
    </section>
  );
}
