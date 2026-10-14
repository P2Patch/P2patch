import type { HardeningCheck, HardeningSummary } from "../types";

function statusStyle(status: string): { dot: string; text: string; label: string } {
  if (status === "stable") return { dot: "bg-pass", text: "text-pass", label: "stable" };
  if (status === "hardened") return { dot: "bg-info", text: "text-info", label: "patch strengthened" };
  if (status === "max_rounds_reached") return { dot: "bg-warn", text: "text-warn", label: "round limit reached" };
  if (status === "failed") return { dot: "bg-fail", text: "text-fail", label: "failed" };
  if (status === "running") return { dot: "bg-warn", text: "text-warn", label: "running" };
  return { dot: "bg-hairline-strong", text: "text-txt-faint", label: status || "pending" };
}

function checkOutcome(key: string, check: HardeningCheck, roundStatus: string): { passed: boolean; label: string } {
  if (check.timed_out || check.exit_code == null) return { passed: false, label: "check incomplete" };
  if (key === "variant_before") {
    if (check.exit_code === 0) return { passed: true, label: "bypass reproduced" };
    return {
      passed: roundStatus === "stable",
      label: roundStatus === "stable" ? "candidate did not bypass" : "bypass did not reproduce",
    };
  }
  return {
    passed: check.exit_code !== 0,
    label: key === "variant_after" ? "bypass blocked" : "original still blocked",
  };
}

function CheckChip({ checkKey, check, roundStatus }: { checkKey: string; check: HardeningCheck; roundStatus: string }) {
  const outcome = checkOutcome(checkKey, check, roundStatus);
  return (
    <span
      className={`chip ${outcome.passed ? "text-pass" : "text-fail"}`}
      title={`${check.name}: exit ${check.exit_code ?? "—"}`}
    >
      {outcome.passed ? "✓" : "✕"} {outcome.label}
    </span>
  );
}

export function HardeningPanel({ summary, compact = false }: { summary: HardeningSummary; compact?: boolean }) {
  const overall = statusStyle(summary.status);
  const slots = Array.from({ length: summary.max_rounds }, (_, i) => summary.rounds.find((r) => r.round === i + 1));

  return (
    <div className="panel overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-hairline px-4 py-3">
        <span className={`h-2 w-2 rounded-full ${overall.dot} ${summary.status === "running" ? "animate-pulse2" : ""}`} />
        <div>
          <div className="font-display text-sm font-semibold text-txt">Iterative hardening</div>
          <div className={`font-mono text-2xs ${overall.text}`}>{overall.label}</div>
        </div>
        <div className="ml-auto text-right font-mono text-2xs text-txt-faint">
          <div>{summary.rounds_hardened} strengthened · {summary.rounds_attempted} attempted</div>
          <div>{summary.max_rounds} round maximum</div>
        </div>
      </div>

      <div className="flex gap-1 px-4 pt-3" aria-label={`${summary.rounds_attempted} of ${summary.max_rounds} hardening rounds attempted`}>
        {slots.map((round, i) => {
          const style = statusStyle(round?.status ?? "pending");
          return <span key={i} className={`h-1.5 flex-1 rounded-full ${round ? style.dot : "bg-hairline"}`} />;
        })}
      </div>

      <div className="divide-y divide-hairline/60 px-4 py-2">
        {summary.rounds.length === 0 && (
          <div className="py-3 font-mono text-2xs text-txt-faint">waiting for the first bypass hunt…</div>
        )}
        {summary.rounds.map((round) => {
          const style = statusStyle(round.status);
          const checks = Object.entries(round.commands) as [string, HardeningCheck][];
          return (
            <div key={round.round} className="py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full ${style.dot} ${round.status === "running" ? "animate-pulse2" : ""}`} />
                <span className="font-mono text-xs text-txt">round {round.round}</span>
                <span className={`font-mono text-2xs ${style.text}`}>{style.label}</span>
                <span className="ml-auto font-mono text-2xs text-txt-faint">
                  {round.agents.exploiter && "exploiter"}
                  {round.agents.exploiter && round.agents.patcher && " → "}
                  {round.agents.patcher && "patcher"}
                </span>
              </div>
              {!compact && checks.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5 pl-3.5">
                  {checks.map(([key, check]) => (
                    <CheckChip key={key} checkKey={key} check={check} roundStatus={round.status} />
                  ))}
                </div>
              )}
              {!compact && round.reason && <p className="mt-1.5 pl-3.5 text-2xs text-txt-faint">{round.reason}</p>}
            </div>
          );
        })}
      </div>
      {!compact && summary.reason && summary.rounds.every((r) => r.reason !== summary.reason) && (
        <div className="border-t border-hairline px-4 py-2.5 text-2xs text-txt-faint">{summary.reason}</div>
      )}
    </div>
  );
}
