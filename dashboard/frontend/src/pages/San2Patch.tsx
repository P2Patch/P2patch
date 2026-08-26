import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost } from "../lib/format";
import { San2PatchTable } from "../components/San2PatchTable";
import type { San2PatchList } from "../types";

function Readout({ label, value, accent, hint }: { label: string; value: string; accent?: boolean; hint?: string }) {
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

export function San2Patch() {
  const { data, error, loading } = useAsync<San2PatchList>(() => api.san2patchList(), []);

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <div className="eyebrow">baseline comparison</div>
        <h1 className="mt-2 font-display text-4xl font-bold tracking-tight text-txt">San2Patch</h1>
        <p className="mt-2 max-w-3xl text-sm text-txt-dim">
          San2Patch (USENIX Security '25) run in-house on its own VulnLoc benchmark, as a reference point for this
          pipeline. It counts a case repaired when the PoC stops crashing <em>and</em> the project's own{" "}
          <span className="font-mono text-2xs">make check</span> still passes — its own oracle. The{" "}
          <span className="font-mono text-2xs">gt</span>/<span className="font-mono text-2xs">res</span> column is our
          independent re-scoring of the same patches against the certified POV manifests a pipeline run is measured
          with, which is a stricter question: does the patch close the <em>vulnerability</em>, or only the one input
          that demonstrated it?
        </p>
      </header>

      {loading && <div className="panel h-64 animate-pulse" />}
      {error && <div className="panel p-5 text-sm text-fail">{error}</div>}

      {data && (
        <>
          <div className="mb-6 panel flex flex-wrap divide-x divide-hairline px-1">
            <Readout
              label="repaired (its own oracle)"
              value={`${data.stats.patched}/${data.stats.patched + data.stats.failed}`}
              accent
              hint="of cases that reached the model"
            />
            <Readout label="rate" value={`${Math.round(data.stats.success_rate * 100)}%`} />
            <Readout
              label="fully fixed (our POVs)"
              value={data.pov ? `${data.pov.fully_blocked}/${data.pov.scored}` : "—"}
              hint={data.pov ? `mean ${data.pov.mean_score?.toFixed(2) ?? "—"}` : "not scored yet"}
            />
            <Readout label="spend" value={cost(data.stats.total_cost_usd)} />
          </div>

          {/* The gap between the two middle numbers is the finding, so it is stated
              rather than left for the reader to subtract. */}
          {data.pov && data.pov.scored > data.pov.fully_blocked && (
            <div className="mb-6 panel border-warn/30 p-4 text-2xs text-txt-dim">
              <strong className="text-txt">
                {data.pov.scored - data.pov.fully_blocked} of {data.pov.scored}
              </strong>{" "}
              patches San2Patch declared correct still leave at least one certified exploit variant working. Its own
              oracle re-runs only the single PoC, so a guard narrow enough to reject exactly those bytes passes it.
              Cases with no POV manifest, and patches that would not apply to our reconstruction, are excluded from
              this count rather than scored zero — see <span className="font-mono">baselines/COMPARISON.md</span>.
            </div>
          )}

          <San2PatchTable results={data.results} />
        </>
      )}
    </div>
  );
}
