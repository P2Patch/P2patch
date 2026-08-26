import type { EnsembleDim, PatchEval } from "../types";
import { Gate, Issues, Rubric, ScoreHeader, SignalRow } from "./scorecardParts";
import { EnsembleStrip } from "./EnsembleStrip";

const EQUIV_LABEL: Record<string, string> = {
  equivalent: "equivalent to official fix",
  superset_stronger: "stronger than official fix",
  subset_weaker: "weaker than official fix",
  different_valid: "different but valid location",
  different_wrong: "different and wrong",
};

function equivTone(v: string): string {
  if (v === "equivalent" || v === "superset_stronger") return "text-pass";
  if (v === "different_valid") return "text-info";
  if (v === "subset_weaker") return "text-warn";
  return "text-fail";
}

export function PatchScorecard({ ev }: { ev: PatchEval }) {
  const overlap = ev.structural_overlap;
  const ens = ev.ensemble;
  const score = ens ? ens.overall.score_median : ev.overall.score;
  const band = ens ? ens.overall.band_mode : ev.overall.band;
  const spreads: Record<string, EnsembleDim> | undefined = ens
    ? Object.fromEntries(ens.dimensions.map((d) => [d.key, d]))
    : undefined;
  return (
    <div className="space-y-5">
      <ScoreHeader
        label="patch score"
        score={score}
        band={band}
        caption={ens ? `median of ${ens.samples} judges · σ${ens.overall.score_stdev}` : undefined}
      >
        <div className="eyebrow">gates</div>
        <div className="flex flex-wrap gap-2">
          <Gate ok={ev.gates.vulnerability_eliminated} label="vuln eliminated" />
          <Gate ok={ev.gates.no_regressions} label="no regressions" />
        </div>
        <div className={`font-mono text-2xs ${equivTone(ev.equivalence_verdict)}`}>
          vs official: {EQUIV_LABEL[ev.equivalence_verdict] ?? ev.equivalence_verdict}
        </div>
      </ScoreHeader>

      {ens && <EnsembleStrip ens={ens} />}

      <div className="panel space-y-3 p-5">
        <p className="text-sm leading-relaxed text-txt">{ev.summary}</p>
        <div className="rounded-md border border-hairline bg-ink2/50 p-3">
          <div className="eyebrow mb-1">root cause</div>
          <p className="text-sm text-txt-dim">{ev.root_cause}</p>
        </div>
      </div>

      <Rubric dims={ev.dimensions} spreads={spreads} />
      <Issues issues={ev.issues} />

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="panel p-4">
          <div className="eyebrow mb-2">file overlap with official fix</div>
          <div className="space-y-1 font-mono text-2xs">
            <SignalRow label="jaccard" value={`${overlap.jaccard}`} />
            <SignalRow label="same files" value={overlap.overlap_files.join(", ") || "none"} />
            <SignalRow label="ours only" value={overlap.ours_only.join(", ") || "—"} />
            <SignalRow label="official only" value={overlap.official_only.join(", ") || "—"} />
          </div>
        </div>
        <div className="panel p-4">
          <div className="eyebrow mb-2">execution signals</div>
          <div className="space-y-1 font-mono text-2xs">
            {Object.entries(ev.execution_signals).map(([k, v]) => (
              <SignalRow key={k} label={k} value={`${v}`} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
