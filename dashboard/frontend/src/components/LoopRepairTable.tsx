import { Link } from "react-router-dom";
import type { LoopRepairPovHeadline, LoopRepairResultSummary } from "../types";
import { cost, statusTone, tokens } from "../lib/format";

function PovBadge({ label, headline }: { label: string; headline: LoopRepairPovHeadline | null }) {
  if (!headline || headline.score == null) {
    return <span className="chip text-txt-faint">{label} —</span>;
  }
  const allGood = headline.all_blocked || headline.all_hardened;
  const tone = allGood ? "text-pass" : headline.score > 0 ? "text-warn" : "text-fail";
  return (
    <span className={`chip ${tone}`} title={`${headline.total ?? "?"} POV(s)`}>
      {label} {Math.round(headline.score * 100)}%
    </span>
  );
}

export function LoopRepairTable({ results }: { results: LoopRepairResultSummary[] }) {
  return (
    <div className="panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              {["", "CVE", "Project", "Status", "POV replay", "Tokens", "Cost", ""].map((h) => (
                <th key={h} className="px-4 py-2.5 font-mono text-2xs uppercase tracking-wider text-txt-faint">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((r) => {
              // LoopRepair's own statuses (patched / no_patch / no_report) map onto
              // the same pass/fail palette the pipeline's own runs use.
              const mapped = r.status === "patched" ? "pass" : "fail";
              const tone = statusTone(mapped);
              return (
                <tr key={r.key} className="group border-b border-hairline/60 last:border-0 hover:bg-elevated">
                  <td className="px-4 py-3">
                    <span className={`inline-block h-2 w-2 rounded-full ${tone.dot}`} title={r.status} />
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/other-projects/${encodeURIComponent(r.key)}`}
                      className="focusable font-mono text-xs text-txt hover:text-iris"
                    >
                      {r.cve}
                    </Link>
                    <div className={`font-mono text-2xs ${tone.text}`}>{r.status}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{r.project}</td>
                  <td className="px-4 py-3">
                    <span className="chip">{r.patch_found ? "patch found" : "no patch"}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1.5">
                      <PovBadge label="fix" headline={r.fix_pov} />
                      <PovBadge label="res" headline={r.residual} />
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{tokens(r.total_tokens)}</td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{cost(r.cost_usd)}</td>
                  <td className="max-w-[22rem] truncate px-4 py-3 font-mono text-2xs text-txt-faint" title={r.message}>
                    {r.message}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
