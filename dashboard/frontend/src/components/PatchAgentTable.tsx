import { Link } from "react-router-dom";
import type { PatchAgentRow, PovHeadline } from "../types";
import { cost, statusTone, tokens } from "../lib/format";

/**
 * gt/res score for one row — the same two-badge treatment San2PatchTable uses, and
 * deliberately the same component shape so the two baselines read identically.
 *
 * A missing score renders as "—", NOT as 0%: "nothing has been scored" and "this
 * patch blocked no exploits" are opposite conclusions. And the tone for `res` comes
 * from `all_hardened`, so a residual POV that still reproduces is neutral rather than
 * red — leaving upstream's own hole open is the expected result, not a failure.
 */
function PovBadge({ label, headline }: { label: string; headline: PovHeadline | null }) {
  if (!headline || headline.score == null) {
    return <span className="chip text-txt-faint">{label} —</span>;
  }
  const allGood = headline.all_blocked || headline.all_hardened;
  const residual = label === "res";
  const tone = allGood
    ? "text-pass"
    : headline.score > 0
      ? residual
        ? "text-pass"
        : "text-warn"
      : residual
        ? "text-txt-dim"
        : "text-fail";
  return (
    <span
      className={`chip ${tone}`}
      title={
        residual
          ? `${headline.total ?? "?"} residual POV(s) — 0% means the patch left exactly the holes upstream leaves open, which is the expected result`
          : `${headline.total ?? "?"} fixPOV(s)`
      }
    >
      {label} {Math.round(headline.score * 100)}%
    </span>
  );
}

export function PatchAgentTable({ results }: { results: PatchAgentRow[] }) {
  return (
    <div className="panel overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="border-b border-hairline text-left">
              {["", "Case", "Project", "Cap", "Agents", "validate()", "Status", "POV score", "Tokens", "Cost", ""].map(
                // Index key, not the label: the first and last columns are both
                // unlabelled, and two "" keys is a React duplicate-key warning.
                (h, i) => (
                  <th
                    key={i}
                    className="px-4 py-2.5 font-mono text-2xs uppercase tracking-wider text-txt-faint"
                  >
                    {h}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {results.map((r) => {
              // Same palette mapping as the San2Patch table: a case that never ran is
              // greyed, not marked failed.
              const mapped = r.valid === false ? "skipped" : r.patch_found ? "pass" : "fail";
              const tone = statusTone(mapped);
              return (
                <tr key={r.key} className="group border-b border-hairline/60 last:border-0 hover:bg-elevated">
                  <td className="px-4 py-3">
                    <span className={`inline-block h-2 w-2 rounded-full ${tone.dot}`} title={r.status} />
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      to={`/patchagent/${encodeURIComponent(r.key)}`}
                      className="focusable font-mono text-xs text-txt hover:text-iris"
                    >
                      {r.cve}
                    </Link>
                    <div className={`font-mono text-2xs ${tone.text}`}>{r.status}</div>
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{r.project}</td>
                  {/* The iteration cap, per row, with the odd one out marked. This is
                      the column that stops the page reading as one uniform run. */}
                  <td className="px-4 py-3 font-mono text-2xs">
                    {r.max_iteration == null ? (
                      <span className="text-txt-faint">—</span>
                    ) : r.effort_comparable ? (
                      <span className="text-txt-dim">{r.max_iteration}</span>
                    ) : (
                      <span
                        className="text-warn"
                        title="ran at a higher attempt budget than every other case — not comparable on effort"
                      >
                        {r.max_iteration} ⚠
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{r.agents_used ?? "—"}</td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">
                    {r.tries ?? "—"}
                    {r.rejected_attempts ? (
                      <span className="text-txt-faint" title="candidates the validator rejected">
                        {" "}
                        ({r.rejected_attempts} rej)
                      </span>
                    ) : null}
                  </td>
                  <td className="px-4 py-3">
                    <span className="chip">
                      {r.valid === false ? "not runnable" : r.patch_found ? "patch found" : "no patch"}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1.5">
                      <PovBadge label="fix" headline={r.fix_pov} />
                      <PovBadge label="res" headline={r.residual} />
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">{tokens(r.total_tokens)}</td>
                  <td className="px-4 py-3 font-mono text-2xs text-txt-dim">
                    <span title="from measured token counts">{cost(r.cost_usd)}</span>
                  </td>
                  <td className="max-w-[20rem] px-4 py-3 font-mono text-2xs text-txt-faint">
                    {/* One run answering two of our CVEs is stated on the row, not
                        buried in a footnote: the cost shown is the run's, not this
                        CVE's alone. */}
                    {r.shared_run_with.length > 0 && (
                      <span className="chip mr-1 text-warn" title={r.message}>
                        shared run
                      </span>
                    )}
                    <span className="align-middle" title={r.message}>
                      {r.message.length > 60 ? `${r.message.slice(0, 60)}…` : r.message}
                    </span>
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
