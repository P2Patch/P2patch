import { PUBLISHED, api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost } from "../lib/format";
import { LoopRepairTable } from "../components/LoopRepairTable";
import type { LoopRepairList } from "../types";

function Readout({
  label,
  value,
  accent,
  hint,
}: {
  label: string;
  value: string;
  accent?: boolean;
  hint?: string;
}) {
  return (
    <div className="px-5 py-4 first:pl-0">
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 font-display text-3xl font-semibold tabular-nums ${accent ? "text-iris" : "text-txt"}`}>
        {value}
      </div>
      {hint && <div className="mt-0.5 text-2xs text-txt-faint">{hint}</div>}
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
            <Readout label="success rate" value={`${Math.round(data.stats.success_rate * 100)}%`} />
            <Readout
              label="fix-closed coverage"
              value={data.pov ? (data.pov.mean_score?.toFixed(3) ?? "—") : "—"}
              hint={data.pov ? `${data.pov.fully_blocked}/${data.pov.n} fully blocked · n=${data.pov.n}` : "not scored yet"}
            />
            <Readout
              label="beyond-upstream coverage"
              value={data.pov_residual ? (data.pov_residual.mean_score?.toFixed(3) ?? "—") : "—"}
              hint={
                data.pov_residual
                  ? `${data.pov_residual.fully_blocked}/${data.pov_residual.n} fully blocked · n=${data.pov_residual.n}`
                  : "no residual suite"
              }
            />
            <Readout label="spend" value={cost(data.stats.total_cost_usd)} />
          </div>

          {data.pov && (
            <div className="mb-6 panel border-hairline p-4 text-2xs text-txt-dim">
              <div className="eyebrow mb-1">coverage is intention-to-treat</div>
              LoopRepair's own oracle accepts a case when its single crashing input stops crashing; the two coverage
              readouts above are our independent re-scoring against the certified POV suites a pipeline run is
              measured with. The denominator is every shared subject carrying a certified suite (n={data.pov.n}), so
              the <strong className="text-txt">{data.pov.zero_credited}</strong> subjects LoopRepair shipped no patch
              for count as zero rather than dropping out. Subjects with no certified suite, and one whose replay could
              not be measured at all, are excluded rather than scored zero — see{" "}
              <span className="font-mono">baselines/COMPARISON.md</span>.
            </div>
          )}

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
