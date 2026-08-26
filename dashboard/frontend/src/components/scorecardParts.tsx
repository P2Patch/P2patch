import { useState } from "react";
import type { EnsembleDim, EvalDimension, EvalIssue } from "../types";

export function scoreTone(score: number): { text: string; bar: string } {
  if (score >= 4) return { text: "text-pass", bar: "bg-pass" };
  if (score >= 3) return { text: "text-warn", bar: "bg-warn" };
  return { text: "text-fail", bar: "bg-fail" };
}

// Handles both vocabularies: patch (good/acceptable/incomplete/bad) and
// exploit (strong/solid/weak/invalid).
export function bandTone(band: string): string {
  if (band === "good" || band === "strong") return "text-pass border-pass/40";
  if (band === "acceptable" || band === "solid") return "text-info border-info/40";
  if (band === "incomplete" || band === "weak") return "text-warn border-warn/40";
  return "text-fail border-fail/40";
}

export function Meter({ score }: { score: number }) {
  const tone = scoreTone(score);
  return (
    <span className="flex items-center gap-0.5" title={`${score}/5`}>
      {[1, 2, 3, 4, 5].map((n) => (
        <span key={n} className={`h-3.5 w-1.5 rounded-sm ${n <= score ? tone.bar : "bg-hairline-strong"}`} />
      ))}
    </span>
  );
}

export function Gate({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`chip ${ok ? "text-pass" : "text-fail"}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${ok ? "bg-pass" : "bg-fail"}`} />
      {label}
    </span>
  );
}

function SpreadBadge({ spread }: { spread: EnsembleDim }) {
  const n = spread.samples.length;
  const agree = Math.round(spread.agreement * n);
  const agrTone = spread.agreement >= 0.99 ? "text-pass" : spread.agreement >= 0.5 ? "text-warn" : "text-fail";
  return (
    <span
      className="hidden shrink-0 items-center gap-1.5 font-mono text-2xs text-txt-faint sm:flex"
      title={`samples ${spread.samples.join(", ")} · σ${spread.stdev}`}
    >
      {spread.min !== spread.max ? (
        <span className="text-txt-dim">
          {spread.min}–{spread.max}
        </span>
      ) : (
        <span className="text-txt-faint">±0</span>
      )}
      <span className={agrTone}>
        {agree}/{n}
      </span>
    </span>
  );
}

export function DimRow({ dim, spread }: { dim: EvalDimension; spread?: EnsembleDim }) {
  const [open, setOpen] = useState(false);
  const shown = spread ? spread.median : dim.score;
  const tone = scoreTone(shown);
  return (
    <div className="border-b border-hairline/60 last:border-0">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="focusable flex w-full items-center gap-4 px-4 py-3 text-left hover:bg-elevated"
      >
        <Meter score={shown} />
        <span className={`w-6 font-mono text-sm tabular-nums ${tone.text}`}>{shown}</span>
        <span className="flex-1 text-sm text-txt">{dim.label ?? dim.key}</span>
        {spread && <SpreadBadge spread={spread} />}
        <span className="hidden max-w-[34%] truncate text-2xs text-txt-faint lg:block">{dim.rationale}</span>
        <span className={`text-txt-faint transition-transform ${open ? "rotate-90" : ""}`}>›</span>
      </button>
      {open && (
        <div className="space-y-2 bg-ink2/40 px-4 pb-4 pt-1">
          {spread && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-2xs text-txt-faint">
              <span>
                samples{" "}
                {spread.samples.map((s, i) => (
                  <span key={i} className="ml-1 rounded bg-panel px-1.5 py-0.5 text-txt-dim">
                    {s}
                  </span>
                ))}
              </span>
              <span>median {spread.median}</span>
              <span>σ {spread.stdev}</span>
            </div>
          )}
          <p className="text-sm text-txt-dim">{dim.rationale}</p>
          {dim.evidence && (
            <p className="rounded border border-hairline bg-panel px-3 py-2 font-mono text-2xs text-txt-faint">
              {dim.evidence}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

export function IssueRow({ issue }: { issue: EvalIssue }) {
  const dot = issue.severity === "high" ? "bg-fail" : issue.severity === "medium" ? "bg-warn" : "bg-info";
  const text = issue.severity === "high" ? "text-fail" : issue.severity === "medium" ? "text-warn" : "text-info";
  return (
    <li className="flex gap-3 px-4 py-2.5">
      <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} />
      <span className="text-sm text-txt-dim">
        <span className={`mr-2 font-mono text-2xs uppercase ${text}`}>{issue.severity}</span>
        {issue.description}
      </span>
    </li>
  );
}

export function SignalRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3">
      <span className="w-32 shrink-0 text-txt-faint">{label}</span>
      <span className="text-txt-dim">{value}</span>
    </div>
  );
}

export function ScoreHeader({
  label,
  score,
  band,
  caption,
  children,
}: {
  label: string;
  score: number;
  band: string;
  caption?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="panel flex flex-wrap items-center gap-x-8 gap-y-4 p-5">
      <div>
        <div className="eyebrow">{label}</div>
        <div className="mt-1 flex items-baseline gap-2">
          <span className={`font-display text-5xl font-bold tabular-nums ${bandTone(band).split(" ")[0]}`}>
            {score}
          </span>
          <span className="text-txt-faint">/100</span>
        </div>
        <div className={`mt-1 inline-block rounded-full border px-2.5 py-0.5 font-mono text-2xs uppercase ${bandTone(band)}`}>
          {band}
        </div>
        {caption && <div className="mt-1.5 font-mono text-2xs text-txt-faint">{caption}</div>}
      </div>
      <div className="h-16 w-px bg-hairline" />
      <div className="space-y-2">{children}</div>
    </div>
  );
}

export function Rubric({ dims, spreads }: { dims: EvalDimension[]; spreads?: Record<string, EnsembleDim> }) {
  return (
    <div>
      <div className="eyebrow mb-2">
        rubric · {dims.length} dimensions{spreads ? " · ensemble medians" : ""}
      </div>
      <div className="panel overflow-hidden">
        {dims.map((d) => (
          <DimRow key={d.key} dim={d} spread={spreads?.[d.key]} />
        ))}
      </div>
    </div>
  );
}

export function Issues({ issues }: { issues: EvalIssue[] }) {
  if (issues.length === 0) return null;
  return (
    <div>
      <div className="eyebrow mb-2">issues · {issues.length}</div>
      <ul className="panel divide-y divide-hairline/60 py-1">
        {issues.map((i, idx) => (
          <IssueRow key={idx} issue={i} />
        ))}
      </ul>
    </div>
  );
}
