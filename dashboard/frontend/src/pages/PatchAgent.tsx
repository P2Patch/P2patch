import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost } from "../lib/format";
import { PatchAgentTable } from "../components/PatchAgentTable";
import type { PatchAgentList } from "../types";

function Readout({
  label,
  value,
  accent,
  hint,
  title,
}: {
  label: string;
  value: string;
  accent?: boolean;
  hint?: string;
  title?: string;
}) {
  return (
    <div className="px-5 py-4 first:pl-0" title={title}>
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 font-display text-3xl font-semibold tabular-nums ${accent ? "text-iris" : "text-txt"}`}>
        {value}
      </div>
      {hint && <div className="mt-0.5 text-2xs text-txt-faint">{hint}</div>}
    </div>
  );
}

export function PatchAgent() {
  const { data, error, loading } = useAsync<PatchAgentList>(() => api.patchAgentList(), []);

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <div className="eyebrow">baseline comparison</div>
        <h1 className="mt-2 font-display text-4xl font-bold tracking-tight text-txt">PatchAgent</h1>
        <p className="mt-2 max-w-3xl text-sm text-txt-dim">
          PatchAgent (USENIX Security '25) run in-house on the cases its own skyset shares with this pipeline's C
          corpus. It counts a case repaired when its <span className="font-mono text-2xs">validate()</span> tool
          accepts a candidate — the patch compiles, the sanitizer PoC stops reproducing, <em>and</em> the project's
          own test suite still passes. The <span className="font-mono text-2xs">gt</span>/
          <span className="font-mono text-2xs">res</span> column is our independent re-scoring of the same patches
          against the certified POV manifests a pipeline run is measured with, which asks the stricter question: does
          the patch close the <em>vulnerability</em>, or only the one input that demonstrated it?
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
              hint={`${data.stats.patchagent_runs} PatchAgent runs`}
              title="Cases counted by CVE. Fewer runs than CVEs because one run's patch covers two of them."
            />
            <Readout
              label="fully fixed (our gt POVs)"
              value={data.stats.patched && data.pov ? `${data.pov.fully_blocked}/${data.pov.scored}` : "—"}
              hint={
                data.pov
                  ? `${data.pov.povs_blocked}/${data.pov.povs_total} POVs · mean ${data.pov.mean_score?.toFixed(2) ?? "—"}`
                  : "not scored yet"
              }
            />
            <Readout
              label="beat upstream (res POVs)"
              value={data.pov_residual ? `${data.pov_residual.povs_blocked}/${data.pov_residual.povs_total}` : "—"}
              hint="0 is a fine result — see below"
            />
            <Readout
              label="spend (measured)"
              value={cost(data.stats.total_cost_usd)}
              hint="measured from recorded traffic"
              title={data.stats.cost_note}
            />
          </div>

          {/* Three properties of this data that a table of rates would hide. All three
              are stated on the page rather than left in a manifest nobody opens. */}
          <div className="mb-6 grid gap-3 md:grid-cols-3">
            {Object.keys(data.stats.max_iteration_other).length > 0 && (
              <div className="panel border-warn/30 p-4 text-2xs text-txt-dim">
                <div className="eyebrow mb-1 text-warn">the budget is not uniform</div>
                <strong className="text-txt">{data.stats.max_iteration_3}</strong> cases ran at{" "}
                <span className="font-mono">--max-iteration 3</span>, but{" "}
                {Object.entries(data.stats.max_iteration_other).map(([id, n]) => (
                  <span key={id}>
                    <span className="font-mono text-txt">{id}</span> ran at{" "}
                    <strong className="text-txt">{n}</strong>
                  </span>
                ))}{" "}
                because it fails at 3. That case is <em>not</em> comparable with the rest on effort — it used 53
                candidate patches and 62% of the arm's entire spend. Rows carry their own cap in the{" "}
                <span className="font-mono">Cap</span> column; a ⚠ marks the odd one out.
              </div>
            )}

            <div className="panel border-hairline p-4 text-2xs text-txt-dim">
              <div className="eyebrow mb-1">costs are measured token counts</div>
              The cost column is derived from <strong className="text-txt">measured</strong> token counts:
              every recorded call re-counted through Anthropic's token counter, including the three tool
              schemas billed on every request. Totals de-duplicate on the underlying run, so a single patch
              covering two CVEs is counted once. Raw traces are committed alongside the results, so the
              counts can be re-derived rather than taken on trust.
            </div>

            <div className="panel border-hairline p-4 text-2xs text-txt-dim">
              <div className="eyebrow mb-1">gt and res score in opposite directions</div>
              A <span className="font-mono">gt</span> POV blocked means the patch matches what the official upstream
              fix closes — higher is better. A <span className="font-mono">res</span> POV exploits a hole upstream
              leaves open, so one that <em>still reproduces</em> means the patch is exactly as good as upstream: the
              expected, neutral outcome, never a failure. That is why{" "}
              <strong className="text-txt">
                {data.pov_residual?.povs_blocked ?? 0}/{data.pov_residual?.povs_total ?? 0}
              </strong>{" "}
              residual is not a bad number, and why the two are never averaged together.
            </div>
          </div>

          {/* The gap between "its oracle says repaired" and "our POVs say fully fixed"
              is the finding, so it is stated rather than left for the reader to subtract. */}
          {data.pov && data.pov.scored > data.pov.fully_blocked && (
            <div className="mb-6 panel border-warn/30 p-4 text-2xs text-txt-dim">
              <strong className="text-txt">
                {data.pov.scored - data.pov.fully_blocked} of {data.pov.scored}
              </strong>{" "}
              patches PatchAgent declared correct still leave at least one certified exploit variant working (
              {(data.pov.povs_total ?? 0) - (data.pov.povs_blocked ?? 0)} POVs of {data.pov.povs_total} in total). Its
              own oracle re-runs only the single PoC that produced the sanitizer report, so a guard narrow enough to
              reject exactly those bytes passes it. Every POV here was first re-run on the <em>unpatched</em> tree to
              prove it reproduces at all — see <span className="font-mono">baselines/POV_SCORES.md</span>.
            </div>
          )}

          {data.stats.not_runnable > 0 && (
            <div className="mb-6 panel border-hairline p-4 text-2xs text-txt-dim">
              <strong className="text-txt">{data.stats.not_runnable}</strong> of the{" "}
              {data.stats.total} shared CVEs could not run here and is recorded as{" "}
              <span className="font-mono">not runnable</span>, not as a failure:{" "}
              <span className="font-mono text-txt">{data.stats.not_runnable_ids.join(", ")}</span>. It reproduces
              fine; its <span className="font-mono">test.sh</span> hardcodes an expected failure count that does not
              match this machine, so PatchAgent's functional gate would reject every candidate regardless of
              correctness, and there is no PatchAgent patch for it. It is out of every denominator above. (The{" "}
              {data.stats.total} CVEs come from {data.stats.patchagent_runs + 1} PatchAgent cases: one case's patch
              covers two CVEs, and this one never ran.)
            </div>
          )}

          {data.stats.cases_sharing_a_run.length > 0 && (
            <div className="mb-6 panel border-hairline p-4 text-2xs text-txt-dim">
              {data.stats.cases_sharing_a_run.map((s) => (
                <div key={s.patchagent_case}>
                  <span className="font-mono text-txt">{s.case_ids.join(" + ")}</span> are two of our CVEs answered by{" "}
                  <strong className="text-txt">one</strong> PatchAgent run (
                  <span className="font-mono">{s.patchagent_case}</span>) and one patch. Both rows show that run's
                  cost and effort — totals de-duplicate, individual rows do not — and our POV sets score them
                  separately and <em>disagree</em>. San2Patch's own benchmark excludes both as unreproducible under
                  sanitizer instrumentation, so there is no San2Patch column for them.
                </div>
              ))}
            </div>
          )}

          <PatchAgentTable results={data.results} />
        </>
      )}
    </div>
  );
}
