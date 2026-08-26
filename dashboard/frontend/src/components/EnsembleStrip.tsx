import type { Ensemble } from "../types";
import { bandTone } from "./scorecardParts";

// How much the judge disagreed with itself, made legible. A single LLM pass
// hides its own variance; this strip shows the whole distribution so the
// headline median can be trusted (or distrusted) on sight.

function confTone(c: string): { text: string; border: string; dot: string; label: string } {
  if (c === "high") return { text: "text-pass", border: "border-pass/40", dot: "bg-pass", label: "high confidence" };
  if (c === "medium") return { text: "text-info", border: "border-info/40", dot: "bg-info", label: "medium confidence" };
  return { text: "text-warn", border: "border-warn/40", dot: "bg-warn", label: "low confidence" };
}

/** A dot per sample over a padded min→max track, with a median tick. Makes the
 *  spread and the clustering visible at a glance. */
function DistTrack({ ens }: { ens: Ensemble }) {
  const scores = ens.per_sample.map((s) => s.score ?? 0);
  const lo = Math.min(...scores);
  const hi = Math.max(...scores);
  const pad = Math.max(5, (hi - lo) * 0.35);
  const min = Math.max(0, lo - pad);
  const max = Math.min(100, hi + pad);
  const span = max - min || 1;
  const pos = (x: number) => `${((x - min) / span) * 100}%`;
  return (
    <div className="relative h-8">
      <div className="absolute inset-x-0 top-1/2 h-px -translate-y-1/2 bg-hairline-strong" />
      {/* min–max range fill */}
      <div
        className="absolute top-1/2 h-0.5 -translate-y-1/2 rounded-full bg-iris/30"
        style={{ left: pos(lo), right: `${100 - ((hi - min) / span) * 100}%` }}
      />
      {/* median tick */}
      <div
        className="absolute top-1/2 h-4 w-0.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-iris"
        style={{ left: pos(ens.overall.score_median) }}
        title={`median ${ens.overall.score_median}`}
      />
      {ens.per_sample.map((s, i) => (
        <div
          key={i}
          className={`absolute top-1/2 h-2.5 w-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full border border-ink ${
            i === ens.medoid_index ? "bg-iris ring-2 ring-iris/30" : "bg-txt-faint"
          }`}
          style={{ left: pos(s.score ?? 0) }}
          title={`sample ${i + 1}: ${s.score} (${s.band})${i === ens.medoid_index ? " · shown below" : ""}`}
        />
      ))}
      <span className="absolute -bottom-0.5 left-0 font-mono text-2xs text-txt-faint">{min}</span>
      <span className="absolute -bottom-0.5 right-0 font-mono text-2xs text-txt-faint">{max}</span>
    </div>
  );
}

export function EnsembleStrip({ ens }: { ens: Ensemble }) {
  const tone = confTone(ens.confidence);
  const o = ens.overall;
  const dropped = (ens.samples_attempted ?? ens.samples) - ens.samples;
  return (
    <div className="panel space-y-4 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="eyebrow">ensemble · {ens.samples} judge samples</div>
        <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-2xs uppercase ${tone.border} ${tone.text}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
          {tone.label}
        </span>
      </div>

      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-1 font-mono text-2xs text-txt-faint">
        <span>
          median <span className="text-sm text-txt">{o.score_median}</span>
        </span>
        <span>
          range <span className="text-txt-dim">{o.score_min}–{o.score_max}</span>
        </span>
        <span>
          σ <span className="text-txt-dim">{o.score_stdev}</span>
        </span>
        <span>
          band agreement{" "}
          <span className="text-txt-dim">{Math.round(o.band_agreement * ens.samples)}/{ens.samples}</span>
        </span>
      </div>

      <DistTrack ens={ens} />

      <div className="flex flex-wrap items-center gap-2 pt-1">
        <span className="font-mono text-2xs text-txt-faint">samples</span>
        {ens.per_sample.map((s, i) => (
          <span
            key={i}
            className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-2xs ${bandTone(s.band ?? "")} ${
              i === ens.medoid_index ? "ring-1 ring-iris/40" : ""
            }`}
            title={i === ens.medoid_index ? "medoid — its rationale is shown below" : undefined}
          >
            <span className="tabular-nums text-txt">{s.score}</span>
            <span className="opacity-70">{s.band}</span>
          </span>
        ))}
        {dropped > 0 && (
          <span className="font-mono text-2xs text-warn" title="samples that errored and were excluded">
            {dropped} dropped
          </span>
        )}
      </div>

      {Object.keys(ens.gate_agreement).length > 0 && (
        <div className="flex flex-wrap gap-x-5 gap-y-1 border-t border-hairline/60 pt-3 font-mono text-2xs text-txt-faint">
          <span>gate agreement</span>
          {Object.entries(ens.gate_agreement).map(([g, frac]) => (
            <span key={g}>
              {g} <span className={frac >= 0.99 ? "text-pass" : frac >= 0.5 ? "text-warn" : "text-fail"}>
                {Math.round(frac * ens.samples)}/{ens.samples}
              </span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
