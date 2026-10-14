import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost, cweShort, relTime } from "../lib/format";
import { DiffViewer } from "../components/DiffViewer";
import { StatusPill } from "../components/StatusPill";
import { profileTone, shortModel } from "../components/RunsExplorer";
import type { PatchEval, RunDetail } from "../types";

interface RunBundle {
  detail: RunDetail;
  diff: string;
  patchEval: PatchEval | null;
}

function agentOk(detail: RunDetail, name: string): boolean | null {
  const a = detail.agents.find((x) => x.name === name);
  if (!a) return null;
  return a.ok;
}

function OkMark({ ok }: { ok: boolean | null }) {
  if (ok === null) return <span className="text-txt-faint">—</span>;
  return <span className={ok ? "text-pass" : "text-fail"}>{ok ? "✓" : "✗"}</span>;
}

function score(pe: PatchEval | null): string {
  if (!pe) return "—";
  const ens = pe.ensemble?.overall?.score_median;
  const s = ens ?? pe.overall?.score;
  if (s == null) return "—";
  const band = pe.overall?.band;
  return band ? `${s} · ${band}` : `${s}`;
}

// The comparison matrix: one column per run, one attribute per row.
const ROWS: { label: string; render: (b: RunBundle) => ReactNode }[] = [
  { label: "Profile", render: (b) => <span className={`chip ${profileTone(b.detail.profile)}`}>{b.detail.profile}</span> },
  {
    label: "Label",
    render: (b) =>
      b.detail.label ? (
        <span className="chip text-txt-dim">{b.detail.label}</span>
      ) : (
        <span className="text-txt-faint">—</span>
      ),
  },
  { label: "Model", render: (b) => <span className="font-mono text-2xs text-txt-dim">{shortModel(b.detail.model)}</span> },
  { label: "Status", render: (b) => <StatusPill status={b.detail.status} size="sm" /> },
  { label: "Patch score", render: (b) => <span className="font-mono text-xs text-txt">{score(b.patchEval)}</span> },
  { label: "Cost", render: (b) => <span className="font-mono text-2xs text-txt-dim">{cost(b.detail.totals.cost_usd)}</span> },
  { label: "Turns", render: (b) => <span className="font-mono text-2xs text-txt-dim">{b.detail.totals.num_turns || "—"}</span> },
  { label: "Exploiter", render: (b) => <OkMark ok={agentOk(b.detail, "exploiter")} /> },
  { label: "Patcher", render: (b) => <OkMark ok={agentOk(b.detail, "patcher")} /> },
  { label: "Verifier", render: (b) => <OkMark ok={agentOk(b.detail, "verifier")} /> },
  { label: "When", render: (b) => <span className="font-mono text-2xs text-txt-faint">{relTime(b.detail.timestamp)}</span> },
];

export function Compare() {
  const [params] = useSearchParams();
  const ids = (params.get("ids") ?? "").split(",").map((s) => s.trim()).filter(Boolean);

  const q = useAsync<RunBundle[]>(async () => {
    return Promise.all(
      ids.map(async (id) => {
        const [detail, diff, evalResp] = await Promise.all([
          api.run(id),
          api.diff(id, "patch_only").catch(() => ""),
          api.analysis<PatchEval>(id, "patch-eval").then((r) => r.result).catch(() => null),
        ]);
        return { detail, diff, patchEval: evalResp };
      }),
    );
  }, [ids.join(",")]);

  const bundles = q.data ?? [];
  const findings = new Set(bundles.map((b) => b.detail.finding_id));
  const sameFinding = findings.size === 1 && bundles.length > 0;
  const head = bundles[0]?.detail;

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <Link to="/" className="focusable font-mono text-2xs text-txt-faint hover:text-txt">
          ← back to experiments
        </Link>
        <h1 className="mt-2 font-display text-3xl font-bold tracking-tight text-txt">Compare runs</h1>
        {sameFinding && head && (
          <p className="mt-2 font-mono text-2xs text-txt-dim">
            <span className="text-txt">{head.ground_truth?.cve_id ?? head.finding_id}</span> ·{" "}
            {head.ground_truth?.project_slug ?? "—"} · {cweShort(head.ground_truth?.cwe_id)}
          </p>
        )}
        {!sameFinding && bundles.length > 0 && (
          <p className="mt-2 rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-2xs text-warn">
            These runs are from different findings — comparison is across projects, not apples-to-apples.
          </p>
        )}
      </header>

      {ids.length < 2 && (
        <div className="panel p-4 font-mono text-xs text-txt-dim">
          Select at least two runs on the Experiments page to compare them.
        </div>
      )}
      {q.loading && <div className="panel p-6 font-mono text-2xs text-txt-faint animate-pulse2">loading runs…</div>}
      {q.error && (
        <div className="panel border-fail/40 p-4 font-mono text-xs text-fail">{q.error}</div>
      )}

      {bundles.length > 0 && (
        <>
          {/* Attribute matrix */}
          <div className="panel mb-6 overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-hairline text-left">
                  <th className="px-4 py-2.5 font-mono text-2xs uppercase tracking-wider text-txt-faint">Attribute</th>
                  {bundles.map((b) => (
                    <th key={b.detail.run_id} className="px-4 py-2.5">
                      <Link
                        to={`/runs/${b.detail.run_id}`}
                        className="focusable font-mono text-2xs text-txt hover:text-iris"
                      >
                        {b.detail.run_id.slice(0, 15)}
                      </Link>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ROWS.map((row) => (
                  <tr key={row.label} className="border-b border-hairline/60 last:border-0">
                    <td className="px-4 py-2.5 font-mono text-2xs text-txt-faint">{row.label}</td>
                    {bundles.map((b) => (
                      <td key={b.detail.run_id} className="px-4 py-2.5">
                        {row.render(b)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Patch diffs, side by side */}
          <div className="mb-2 eyebrow">patch diffs</div>
          <div
            className="grid gap-4 overflow-x-auto pb-2"
            style={{ gridTemplateColumns: `repeat(${bundles.length}, minmax(20rem, 1fr))` }}
          >
            {bundles.map((b) => (
              <div key={b.detail.run_id} className="panel flex min-w-0 flex-col overflow-hidden">
                <div className="flex items-center justify-between gap-2 border-b border-hairline px-3 py-2">
                  <span className={`chip ${profileTone(b.detail.profile)}`}>{b.detail.profile}</span>
                  <span className="font-mono text-2xs text-txt-faint">{shortModel(b.detail.model)}</span>
                </div>
                <div className="max-h-[32rem] overflow-auto">
                  <DiffViewer diff={b.diff} emptyLabel="no patch diff" />
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
