import { PUBLISHED, api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost } from "../lib/format";
import { LoopRepairTable } from "../components/LoopRepairTable";
import type { LoopRepairList } from "../types";

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

export function OtherProjects() {
  const { data, error, loading } = useAsync<LoopRepairList>(() => api.loopRepairList(), []);

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <div className="eyebrow">baseline comparison</div>
        <h1 className="mt-2 font-display text-4xl font-bold tracking-tight text-txt">Other projects</h1>
        <p className="mt-2 max-w-2xl text-sm text-txt-dim">
          LoopRepair (ICSE '26), run against the same 40-vulnerability VulnLoc+ benchmark it reports numbers on in
          its own paper — a side-by-side reference point for this pipeline's own results.
        </p>
      </header>

      {loading && <SkeletonTable />}
      {error && <ErrorBox msg={error} />}

      {data && (
        <>
          <div className="mb-8 panel flex flex-wrap divide-x divide-hairline px-1">
            <Readout label="CVEs" value={`${data.stats.total}`} />
            <Readout label="patched" value={`${data.stats.patched}`} accent />
            <Readout label="failed" value={`${data.stats.failed}`} />
            <Readout label="success rate" value={`${Math.round(data.stats.success_rate * 100)}%`} />
            <Readout label="spend" value={cost(data.stats.total_cost_usd)} />
          </div>
          <LoopRepairTable results={data.results} />
        </>
      )}
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
