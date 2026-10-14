import type { RetrySummary } from "../types";

/** Human name for the gate a patcher correction answered. */
function gateLabel(gate: string): string {
  if (gate === "converge") return "POV-after + regressions";
  if (gate === "pov_after") return "POV after patch";
  if (gate === "regression") return "regression tests";
  const round = /^harden_r([0-9]+)$/.exec(gate);
  if (round) return `hardening round ${round[1]}`;
  return gate;
}

/** Retries the pipeline performed instead of rejecting the run.
 *
 * A failing objective check is not a verdict — it goes back to the agent that
 * owns it (the patcher for a POV that still reproduces or a broken test, the
 * exploiter for a POV that never reproduced) with the failure as feedback. This
 * panel is that history: what failed and which attempt answered it. Each attempt
 * names its own agent-IO folder, listed in the Agents tab.
 */
export function RetriesPanel({ summary }: { summary: RetrySummary }) {
  const corrections = summary.patch_corrections;
  const exploits = summary.exploit_retries;
  const apiErrors = summary.api_error_retries ?? [];
  const apiErrorCount = apiErrors.reduce((n, r) => n + r.attempts, 0);
  const total = corrections.length + exploits.length + apiErrorCount;
  if (total === 0) return null;

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-hairline px-4 py-3">
        <span className="h-2 w-2 rounded-full bg-warn" />
        <div>
          <div className="font-display text-sm font-semibold text-txt">Self-correction</div>
          <div className="font-mono text-2xs text-warn">
            {total} retr{total === 1 ? "y" : "ies"} · work sent back instead of rejecting
          </div>
        </div>
        <div className="ml-auto text-right font-mono text-2xs text-txt-faint">
          <div>≤ {summary.max_correction_attempts} patch attempts per gate</div>
          <div>≤ {summary.max_exploit_attempts} exploit attempts</div>
          {apiErrorCount > 0 && (
            <div>≤ {summary.max_api_error_attempts} API-error re-rolls</div>
          )}
        </div>
      </div>

      <div className="divide-y divide-hairline/60 px-4 py-2">
        {apiErrors.map((retry, i) => (
          <div key={`a${i}`} className="py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip text-warn">API retry</span>
              <span className="font-mono text-xs text-txt">
                {retry.kind === "content_filter" ? "content filter" : "connection dropped"}
              </span>
              <span className="font-mono text-2xs text-txt-faint">
                re-rolled ×{retry.attempts} · {retry.recovered ? "recovered" : "ran out of budget"}
              </span>
              {retry.agent && (
                <span className="ml-auto font-mono text-2xs text-txt-faint">{retry.agent}</span>
              )}
            </div>
            {retry.detail && <p className="mt-1.5 text-2xs text-txt-faint">{retry.detail}</p>}
          </div>
        ))}
        {exploits.map((retry) => (
          <div key={`x${retry.attempt}`} className="py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip text-warn">exploiter</span>
              <span className="font-mono text-xs text-txt">POV before patch</span>
              <span className="font-mono text-2xs text-txt-faint">attempt {retry.attempt} rejected</span>
              <span className="ml-auto font-mono text-2xs text-txt-faint">{retry.agent}</span>
            </div>
            {retry.detail && <p className="mt-1.5 text-2xs text-txt-faint">{retry.detail}</p>}
          </div>
        ))}
        {corrections.map((correction, i) => (
          <div key={`c${i}`} className="py-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="chip text-warn">patcher</span>
              <span className="font-mono text-xs text-txt">{gateLabel(correction.gate)}</span>
              <span className="font-mono text-2xs text-txt-faint">
                attempt {correction.attempt} failed
              </span>
              <span className="ml-auto font-mono text-2xs text-txt-faint">{correction.agent}</span>
            </div>
            {correction.detail && (
              <p className="mt-1.5 text-2xs text-txt-faint">{correction.detail}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
