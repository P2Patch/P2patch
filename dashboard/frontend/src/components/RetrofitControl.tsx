import { useCallback, useEffect, useRef, useState } from "react";
import { PUBLISHED, api } from "../api";
import type { RetrofitJobStatus } from "../types";

/**
 * Runs the verifier against a finished run's existing patch.
 *
 * The copy here is load-bearing. This is **assess-only**: the patch is never
 * rewritten and the run's verdict never changes, so a "would not pass" outcome
 * on an accepted run is information rather than a contradiction. Wording that
 * implied a re-judgement (or a button labelled "re-verify") would invite the
 * reader to treat the run's status pill as stale, which it is not.
 */
export function RetrofitControl({
  runId,
  onComplete,
}: {
  runId: string;
  onComplete: () => void;
}) {
  const [status, setStatus] = useState<RetrofitJobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const sawRunning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const next = await api.retrofit(runId);
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
    // The verifier builds and tests the project, so this is minutes, not
    // seconds — poll less eagerly than the POV replay does.
    const timer = window.setInterval(() => void refresh(), 4000);
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
  // Nothing to offer and nothing to report: a run that already has its verifier
  // and has never been retrofitted should not show this control at all.
  if (status && !status.available && status.state === "absent") return null;

  async function start() {
    setError(null);
    sawRunning.current = true;
    try {
      setStatus(await api.startRetrofit(runId));
    } catch (err) {
      sawRunning.current = false;
      setError(String((err as Error).message ?? err));
    }
  }

  const running = status?.state === "running";
  const available = status?.available === true;
  const label = running
    ? "running verifier…"
    : status?.state === "done"
      ? "run verifier again"
      : status?.state === "error"
        ? "try again"
        : "run verifier";

  return (
    <section className="panel flex flex-wrap items-center justify-between gap-4 border-iris/25 px-4 py-3">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${running ? "animate-pulse2 bg-warn" : "bg-iris"}`} />
          <span className="font-mono text-xs text-txt">retrofit verifier</span>
          {status?.state === "done" && <span className="chip text-pass">complete</span>}
          {status?.state === "error" && <span className="chip text-fail">failed</span>}
        </div>
        <p className="mt-1 text-2xs text-txt-dim">
          {running
            ? "The verifier is reviewing this patch and running the project's tests in the container. This takes minutes."
            : status?.unavailable_reason ??
              "This run finished before its profile included the verifier. Review the recorded patch against the alert and the project's tests — the patch and this run's verdict are left unchanged."}
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
