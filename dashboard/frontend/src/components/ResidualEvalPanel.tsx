import type { ResidualEval, ResidualPov } from "../types";

// Residual-gap panel for the non-gating residual_eval stage.
//
// The INVERSE of FixPovEvalPanel, and the colour language reflects that.
// These POVs exploit paths the CVE's *official upstream fix* leaves open, so:
//
//   blocked    -> the patch beat upstream. A bonus. Green.
//   reproduced -> the patch has the same gap upstream does. Expected and
//                 perfectly acceptable — rendered NEUTRAL, never red, because
//                 matching the official fix is exactly what the fixPOV
//                 score already rewards. Painting it red would tell the reader
//                 a correct patch had failed something.
//
// A 0 here is therefore not a bad result; it is the default one.

function pct(score: number | null): string {
  return score == null ? "—" : `${Math.round(score * 100)}`;
}

function scoreTone(score: number | null): string {
  if (score == null) return "text-txt-faint";
  if (score > 0) return "text-pass";
  return "text-txt-dim";
}

function summaryChip(res: ResidualEval): { dot: string; text: string; label: string } {
  if (res.score == null) {
    return { dot: "bg-txt-faint", text: "text-txt-faint", label: "inconclusive" };
  }
  if (res.all_hardened) {
    return { dot: "bg-pass", text: "text-pass", label: "beat upstream on every gap" };
  }
  if (res.hardened_beyond_fix > 0) {
    return {
      dot: "bg-pass",
      text: "text-pass",
      label: `${res.hardened_beyond_fix} gap${res.hardened_beyond_fix === 1 ? "" : "s"} closed beyond upstream`,
    };
  }
  return { dot: "bg-txt-faint", text: "text-txt-dim", label: "matches the official fix" };
}

function outcomeChip(outcome: ResidualPov["outcome"]): { dot: string; text: string; label: string } {
  // Keep the evaluator's blocked/reproduced/errored vocabulary visible, just as
  // FixPovEvalPanel does. "reproduced" remains neutral here because a
  // residual POV reproducing means the patch matches the official fix.
  if (outcome === "blocked") return { dot: "bg-pass", text: "text-pass", label: "blocked" };
  if (outcome === "reproduced") {
    return { dot: "bg-txt-faint", text: "text-txt-dim", label: "reproduced" };
  }
  return { dot: "bg-txt-faint", text: "text-txt-faint", label: "errored" };
}

export function ResidualEvalPanel({ res }: { res: ResidualEval }) {
  const tone = scoreTone(res.score);
  const summary = summaryChip(res);
  const conclusive = res.hardened_beyond_fix + res.matches_official_fix;
  const width = res.score == null ? 0 : Math.max(0, Math.min(100, res.score * 100));

  return (
    <section className="space-y-3" aria-labelledby="residual-eval-heading">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div id="residual-eval-heading" className="eyebrow">
          residual gaps · holes the official fix leaves open (bonus, non-gating)
        </div>
        <span className={`chip ${summary.text}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${summary.dot}`} />
          {summary.label}
        </span>
      </div>

      <div className="panel flex flex-wrap items-center gap-x-8 gap-y-4 p-5">
        <div>
          <div className="eyebrow">beyond-upstream score</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`font-display text-5xl font-bold tabular-nums ${tone}`}>{pct(res.score)}</span>
            {res.score != null && <span className="text-txt-faint">/100</span>}
          </div>
          <div className="mt-1.5 font-mono text-2xs text-txt-faint">
            {conclusive > 0
              ? `${res.hardened_beyond_fix}/${conclusive} upstream gaps also closed`
              : "no conclusive gaps"}
          </div>
        </div>
        <div className="hidden h-16 w-px bg-hairline sm:block" />
        <div className="flex flex-wrap gap-2">
          <span className="chip text-pass">
            <span className="h-1.5 w-1.5 rounded-full bg-pass" />
            {res.hardened_beyond_fix} blocked
          </span>
          <span className="chip text-txt-dim">
            <span className="h-1.5 w-1.5 rounded-full bg-txt-faint" />
            {res.matches_official_fix} reproduced
          </span>
          {res.errored > 0 && (
            <span className="chip text-txt-faint">
              <span className="h-1.5 w-1.5 rounded-full bg-txt-faint" />
              {res.errored} errored
            </span>
          )}
          <span className="chip text-txt-dim">{res.total} POVs</span>
        </div>
        <div className="basis-full">
          <div
            className="h-1.5 overflow-hidden rounded-full bg-hairline-strong"
            role="progressbar"
            aria-label="Gaps closed beyond the official upstream fix"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={res.score == null ? undefined : Math.round(res.score * 100)}
            aria-valuetext={
              res.score == null
                ? "No conclusive residual POV results"
                : `${Math.round(res.score * 100)} percent of known upstream gaps also closed by this patch`
            }
          >
            <div className="h-full rounded-full bg-pass" style={{ width: `${width}%` }} />
          </div>
          <div className="mt-1.5 font-mono text-2xs text-txt-faint">
            these exploits survive the official fix — blocking one means this patch is
            stronger than upstream; leaving one open matches upstream and is not a defect
          </div>
        </div>
      </div>

      <div className="panel overflow-hidden">
        {res.povs.length === 0 ? (
          <div className="px-4 py-6 text-center font-mono text-2xs text-txt-faint">
            no residual POV results were recorded
          </div>
        ) : (
          res.povs.map((pov) => {
            const chip = outcomeChip(pov.outcome);
            return (
              <div key={pov.id} className="flex items-start gap-3 border-b border-hairline/60 px-4 py-3 last:border-0">
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${chip.dot}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="break-all font-mono text-xs text-txt">{pov.id}</span>
                    <span className={`font-mono text-2xs uppercase ${chip.text}`}>{chip.label}</span>
                    {pov.exit_code != null && (
                      <span className="font-mono text-2xs text-txt-faint">exit {pov.exit_code}</span>
                    )}
                  </div>
                  {pov.gap_summary && (
                    <div className="mt-1 text-2xs text-txt-dim">
                      <span className="text-txt-faint">upstream gap: </span>
                      {pov.gap_summary}
                    </div>
                  )}
                  {pov.description && <div className="mt-1 text-2xs text-txt-dim">{pov.description}</div>}
                  {pov.exploit_path && (
                    <div className="mt-1 break-words font-mono text-2xs leading-relaxed text-txt-faint">
                      {pov.exploit_path}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}
