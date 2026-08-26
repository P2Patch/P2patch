import { useState } from "react";
import { PUBLISHED, api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost, cweShort } from "../lib/format";
import { RunsExplorer } from "../components/RunsExplorer";
import type { CweBucket, Stats } from "../types";

function Readout({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="px-5 py-4 first:pl-0">
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 font-display text-3xl font-semibold tabular-nums ${accent ? "text-iris" : "text-txt"}`}>
        {value}
      </div>
    </div>
  );
}

function CweBars({ buckets }: { buckets: CweBucket[] }) {
  const max = Math.max(1, ...buckets.map((b) => b.total));
  return (
    <div className="space-y-3">
      {buckets.map((b) => {
        const acceptedPct = (b.accepted / max) * 100;
        const totalPct = (b.total / max) * 100;
        return (
          <div key={b.cwe_id} className="flex items-center gap-3">
            <div className="w-20 shrink-0 font-mono text-2xs text-txt-dim">{cweShort(b.cwe_id)}</div>
            <div className="relative h-5 flex-1 overflow-hidden rounded-sm bg-ink2">
              <div className="absolute inset-y-0 left-0 bg-hairline-strong" style={{ width: `${totalPct}%` }} />
              <div className="absolute inset-y-0 left-0 bg-pass/70" style={{ width: `${acceptedPct}%` }} />
            </div>
            <div className="w-16 shrink-0 text-right font-mono text-2xs text-txt-faint">
              {b.accepted}/{b.total}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function Overview() {
  const [nonce, setNonce] = useState(0);
  const reload = () => setNonce((n) => n + 1);
  const statsQ = useAsync<Stats>(() => api.stats(), [nonce]);
  const runsQ = useAsync(() => api.runs(), [nonce]);

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <div className="eyebrow">exploit · patch · verify pipeline</div>
        <h1 className="mt-2 font-display text-4xl font-bold tracking-tight text-txt">Experiments</h1>
        <p className="mt-2 max-w-2xl text-sm text-txt-dim">
          Every run of the automated remediation pipeline — the agents that exploited, patched and verified each
          finding, checked against the real-world CVE fix.
        </p>
      </header>

      {statsQ.error && <ErrorBox msg={statsQ.error} />}

      {statsQ.data && (
        <div className="mb-8 grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <div className="panel flex flex-wrap divide-x divide-hairline px-1">
            <Readout label="runs" value={`${statsQ.data.total_runs}`} />
            <Readout label="accept rate" value={`${Math.round(statsQ.data.accept_rate * 100)}%`} accent />
            <Readout label="accepted" value={`${statsQ.data.accepted}`} />
            <Readout label="rejected" value={`${statsQ.data.rejected}`} />
            <Readout label="cves" value={`${statsQ.data.distinct_cves}`} />
            <Readout label="spend" value={cost(statsQ.data.total_cost_usd)} />
          </div>
          <div className="panel px-5 py-4">
            <div className="eyebrow mb-3">outcomes by weakness</div>
            <CweBars buckets={statsQ.data.by_cwe} />
          </div>
        </div>
      )}

      {runsQ.loading && <SkeletonTable />}
      {runsQ.error && <ErrorBox msg={runsQ.error} />}
      {runsQ.data && <RunsExplorer runs={runsQ.data} onChanged={reload} />}
    </div>
  );
}

function ErrorBox({ msg }: { msg: string }) {
  return (
    <div className="panel border-fail/40 p-4 font-mono text-xs text-fail">
      {PUBLISHED ? "Couldn’t load the published snapshot data." : "Couldn’t reach the API — is the backend running on :8000?"}
      <div className="mt-1 text-txt-faint">{msg}</div>
    </div>
  );
}

function SkeletonTable() {
  return (
    <div className="panel space-y-2 p-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="h-8 animate-pulse2 rounded bg-elevated" />
      ))}
    </div>
  );
}
