import type { RetrofitGates } from "../types";

// Gates replayed against a finished run's patch by `security-pipeline retrofit`.
//
// These runs were accepted under a profile that did not yet include the
// regression gate or the verifier. The retrofit re-runs those gates against the
// patch *as recorded* and never re-patches, so this panel reports a measurement,
// not a re-judgement — which drives the whole colour language here:
//
//   passed  -> the patch clears a gate it never faced. Green.
//   failed  -> it would not have. WARN, not fail: the run's own verdict stands,
//              and painting it red would read as "this accepted run is actually
//              rejected", which is precisely what it does not mean.
//   errored -> the gate could not be assessed (agent crash, container error).
//              Neutral, and re-runnable — `retrofit` retries these by default.
//
// The run's status pill is deliberately untouched by any of this.

function gateTone(gate: string, res: RetrofitGates): { dot: string; text: string; label: string } {
  if (res.passed.includes(gate)) return { dot: "bg-pass", text: "text-pass", label: "passed" };
  if (res.failed.includes(gate)) return { dot: "bg-warn", text: "text-warn", label: "would not pass" };
  return { dot: "bg-txt-faint", text: "text-txt-faint", label: "not assessed" };
}

function summaryChip(res: RetrofitGates): { dot: string; text: string; label: string } {
  if (res.failed.length > 0) {
    return {
      dot: "bg-warn",
      text: "text-warn",
      label: `${res.failed.length} gate${res.failed.length === 1 ? "" : "s"} would not pass`,
    };
  }
  if (res.errored.length > 0) {
    return { dot: "bg-txt-faint", text: "text-txt-faint", label: "incomplete" };
  }
  return { dot: "bg-pass", text: "text-pass", label: "clears every replayed gate" };
}

const GATE_LABELS: Record<string, string> = {
  regression: "regression tests",
  verifier: "LLM verifier",
};

export function RetrofitGatesPanel({ res }: { res: RetrofitGates }) {
  const summary = summaryChip(res);

  return (
    <section className="space-y-3" aria-labelledby="retrofit-gates-heading">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div id="retrofit-gates-heading" className="eyebrow">
          retrofitted gates · replayed after the run finished (assess-only)
        </div>
        <span className={`chip ${summary.text}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${summary.dot}`} />
          {summary.label}
        </span>
      </div>

      <div className="panel overflow-hidden">
        {res.gates.map((gate) => {
          const tone = gateTone(gate, res);
          const detail = res.detail?.[gate];
          return (
            <div
              key={gate}
              className="flex items-start gap-3 border-b border-hairline/60 px-4 py-3 last:border-0"
            >
              <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${tone.dot}`} />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-mono text-xs text-txt">{GATE_LABELS[gate] ?? gate}</span>
                  <span className={`font-mono text-2xs uppercase ${tone.text}`}>{tone.label}</span>
                  {detail?.verdict && (
                    <span className="font-mono text-2xs text-txt-faint">verdict {detail.verdict}</span>
                  )}
                </div>
                {detail?.detail && (
                  <div className="mt-1 break-words text-2xs leading-relaxed text-txt-dim">
                    {detail.detail}
                  </div>
                )}
                {detail?.commands && detail.commands.length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {detail.commands.map((command) => (
                      <div key={command} className="break-all font-mono text-2xs text-txt-faint">
                        {command}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="font-mono text-2xs leading-relaxed text-txt-faint">
        this run was accepted before its profile included these gates. they were replayed
        against the recorded patch and never re-patched it, so the verdict above is unchanged —
        a gate that would not pass is information about the patch, not a rejection
        {res.evaluation_mode === "worktree" && " · scored the run's preserved worktree"}
        {res.evaluation_mode === "reconstructed" && " · scored a tree rebuilt from the base commit + the run's patch"}
      </div>
    </section>
  );
}
