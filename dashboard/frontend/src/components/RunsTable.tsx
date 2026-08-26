import { Link } from "react-router-dom";
import type { RunSummary } from "../types";
import { cost, cweShort, relTime, statusTone } from "../lib/format";

function AgentDots({ agents }: { agents: RunSummary["agents"] }) {
  const all = ["exploiter", "patcher", "verifier"];
  const byName = new Map(agents.map((a) => [a.name, a.ok]));
  const hardeningCount = agents.filter((a) => /^(exploiter|patcher)_harden_r\d+$/.test(a.name)).length;
  return (
    <span className="flex items-center gap-1" title={agents.map((a) => `${a.name}: ${a.ok ? "ok" : "fail"}`).join(", ")}>
      {all.map((name) => {
        const ran = byName.has(name);
        const ok = byName.get(name);
        return (
          <span
            key={name}
            className={`h-1.5 w-1.5 rounded-full ${!ran ? "bg-hairline-strong" : ok ? "bg-pass" : "bg-fail"}`}
          />
        );
      })}
      {hardeningCount > 0 && <span className="ml-0.5 font-mono text-[9px] text-pass">+{hardeningCount}</span>}
    </span>
  );
}

export function RunsTable({ runs }: { runs: RunSummary[] }) {
  return (
    <div className="panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              {["", "CVE", "Project", "CWE", "Agents", "Cost", "When"].map((h) => (
                <th key={h} className="px-4 py-2.5 font-mono text-2xs uppercase tracking-wider text-txt-faint">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => {
              const tone = statusTone(run.status);
              return (
                <tr key={run.run_id} className="group border-b border-hairline/60 last:border-0 hover:bg-elevated">
                  <td className="px-4 py-3">
                    <span className={`inline-block h-2 w-2 rounded-full ${tone.dot}`} title={run.status} />
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/runs/${run.run_id}`}
                      className="focusable font-mono text-xs text-txt hover:text-iris"
                    >
                      {run.cve_id ?? run.run_id.slice(16)}
                    </Link>
                    <div className={`font-mono text-2xs ${tone.text}`}>{run.status}</div>
                  </td>
                  <td className="max-w-[16rem] truncate px-4 py-3 font-mono text-2xs text-txt-dim" title={run.project_slug ?? ""}>
                    {run.project_slug?.split("_")[0] ?? "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span className="chip">{cweShort(run.cwe_id)}</span>
                  </td>
                  <td className="px-4 py-3">
                    <AgentDots agents={run.agents} />
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{cost(run.totals.cost_usd)}</td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-faint">{relTime(run.timestamp)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
