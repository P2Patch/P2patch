import type { FixPovEval, FixPov } from "../types";

// Coverage panel for the non-gating fix_pov_eval stage: how many of the
// CVE's curated real exploits the pipeline's patch actually blocked. This is a
// metric, never a gate — a reproduced POV is a miss, not a run rejection.

function pct(score: number | null): string {
  return score == null ? "—" : `${Math.round(score * 100)}`;
}

function scoreTone(score: number | null): string {
  if (score == null) return "text-txt-faint";
  if (score >= 1) return "text-pass";
  if (score >= 0.5) return "text-warn";
  return "text-fail";
}

function summaryChip(gte: FixPovEval): { dot: string; text: string; label: string } {
  if (gte.score == null) {
    return { dot: "bg-txt-faint", text: "text-txt-faint", label: "inconclusive" };
  }
  if (gte.all_blocked) {
    return { dot: "bg-pass", text: "text-pass", label: "all paths blocked" };
  }
  if (gte.reproduced === 0 && gte.errored > 0) {
    return {
      dot: "bg-warn",
      text: "text-warn",
      label: `${gte.errored} path${gte.errored === 1 ? "" : "s"} inconclusive`,
    };
  }
  return {
    dot: "bg-warn",
    text: "text-warn",
    label: `${gte.reproduced} path${gte.reproduced === 1 ? "" : "s"} still reproduced`,
  };
}

function outcomeChip(outcome: FixPov["outcome"]): { dot: string; text: string; label: string } {
  if (outcome === "blocked") return { dot: "bg-pass", text: "text-pass", label: "blocked" };
  if (outcome === "reproduced") return { dot: "bg-fail", text: "text-fail", label: "reproduced" };
  return { dot: "bg-txt-faint", text: "text-txt-faint", label: "errored" };
}

export function FixPovEvalPanel({ gte }: { gte: FixPovEval }) {
  const tone = scoreTone(gte.score);
  const summary = summaryChip(gte);
  const conclusive = gte.blocked + gte.reproduced;
  const coverageWidth = gte.score == null ? 0 : Math.max(0, Math.min(100, gte.score * 100));

  return (
    <section className="space-y-3" aria-labelledby="fix-pov-eval-heading">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div id="fix-pov-eval-heading" className="eyebrow">
          fixPOV coverage · real exploits blocked by the patch (non-gating)
        </div>
        <span className={`chip ${summary.text}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${summary.dot}`} />
          {summary.label}
        </span>
      </div>

      <div className="panel flex flex-wrap items-center gap-x-8 gap-y-4 p-5">
        <div>
          <div className="eyebrow">coverage score</div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`font-display text-5xl font-bold tabular-nums ${tone}`}>{pct(gte.score)}</span>
            {gte.score != null && <span className="text-txt-faint">/100</span>}
          </div>
          <div className="mt-1.5 font-mono text-2xs text-txt-faint">
            {conclusive > 0 ? `${gte.blocked}/${conclusive} conclusive paths blocked` : "no conclusive paths"}
          </div>
        </div>
        <div className="hidden h-16 w-px bg-hairline sm:block" />
        <div className="flex flex-wrap gap-2">
          <span className="chip text-pass">
            <span className="h-1.5 w-1.5 rounded-full bg-pass" />
            {gte.blocked} blocked
          </span>
          <span className="chip text-fail">
            <span className="h-1.5 w-1.5 rounded-full bg-fail" />
            {gte.reproduced} reproduced
          </span>
          {gte.errored > 0 && (
            <span className="chip text-txt-faint">
              <span className="h-1.5 w-1.5 rounded-full bg-txt-faint" />
              {gte.errored} errored
            </span>
          )}
          <span className="chip text-txt-dim">{gte.total} POVs</span>
        </div>
        <div className="basis-full">
          <div
            className="h-1.5 overflow-hidden rounded-full bg-hairline-strong"
            role="progressbar"
            aria-label="fixPOV coverage"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={gte.score == null ? undefined : Math.round(gte.score * 100)}
            aria-valuetext={
              gte.score == null
                ? "No conclusive fixPOV results"
                : `${Math.round(gte.score * 100)} percent of conclusive fixPOV exploits blocked`
            }
          >
            <div
              className={`h-full rounded-full ${gte.all_blocked ? "bg-pass" : "bg-warn"}`}
              style={{ width: `${coverageWidth}%` }}
            />
          </div>
          {gte.errored > 0 && (
            <div className="mt-1.5 font-mono text-2xs text-txt-faint">
              {gte.errored} inconclusive POV{gte.errored === 1 ? "" : "s"} excluded from the score
            </div>
          )}
        </div>
      </div>

      <div className="panel overflow-hidden">
        {gte.povs.length === 0 ? (
          <div className="px-4 py-6 text-center font-mono text-2xs text-txt-faint">
            no fixPOV results were recorded
          </div>
        ) : (
          gte.povs.map((pov) => {
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
