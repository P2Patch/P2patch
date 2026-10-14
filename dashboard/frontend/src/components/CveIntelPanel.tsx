import { useState } from "react";
import type { CveResearch } from "../types";
import { AnalysisPanel } from "./AnalysisPanel";

function sevTone(sev: string | undefined): string {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical" || s === "high") return "text-fail";
  if (s === "medium") return "text-warn";
  if (s === "low") return "text-info";
  return "text-txt-dim";
}

function Intel({ r }: { r: CveResearch }) {
  const [showCandidates, setShowCandidates] = useState(false);
  const nvd = r.metadata.nvd;
  const kev = r.kev;
  const best = r.judge.best_exploit;
  const hasExploit = !!best && best.kind !== "none" && !!best.url;
  const reviewed = r.judge.candidates_reviewed ?? [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        {nvd?.cvss && (
          <span className="chip">
            CVSS {nvd.cvss.score} <span className={sevTone(nvd.cvss.severity)}>{nvd.cvss.severity}</span>
          </span>
        )}
        <span className={`chip ${kev.known_exploited ? "text-fail" : "text-txt-dim"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${kev.known_exploited ? "bg-fail" : "bg-txt-faint"}`} />
          {kev.known_exploited ? "in CISA KEV" : "not in KEV"}
        </span>
        {r.metadata.osv?.fixed_versions?.length ? (
          <span className="chip">fixed in {r.metadata.osv.fixed_versions.join(", ")}</span>
        ) : null}
      </div>

      {nvd?.description && <p className="text-sm leading-relaxed text-txt-dim">{nvd.description}</p>}

      <div className="rounded-md border border-hairline bg-ink2/50 p-3">
        <div className="eyebrow mb-1">known exploitation</div>
        <p className="text-sm text-txt-dim">{r.judge.known_exploitation_summary}</p>
      </div>

      {/* Official exploit finding */}
      <div className={`panel p-4 ${hasExploit ? "border-warn/40" : ""}`}>
        <div className="eyebrow mb-2">official / public exploit</div>
        {hasExploit ? (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="chip text-warn">{best!.kind}</span>
              <a href={best!.url!} target="_blank" rel="noreferrer" className="focusable text-iris hover:underline">
                {best!.name ?? best!.url} ↗
              </a>
              <span className="font-mono text-2xs text-txt-faint">
                confidence {Math.round((best!.confidence ?? 0) * 100)}%
              </span>
            </div>
            <p className="text-2xs text-txt-faint">{best!.rationale}</p>
          </div>
        ) : (
          <p className="text-sm text-txt-faint">
            No genuine public exploit found in the queried sources (Metasploit, Exploit-DB, Nuclei, PoC repos).
            Exploit evaluation is scored on the absolute rubric.
          </p>
        )}
      </div>

      {reviewed.length > 0 && (
        <div>
          <button
            type="button"
            onClick={() => setShowCandidates((s) => !s)}
            className="focusable eyebrow flex items-center gap-1 hover:text-txt-dim"
          >
            <span className={`transition-transform ${showCandidates ? "rotate-90" : ""}`}>›</span>
            candidates reviewed · {reviewed.length}
          </button>
          {showCandidates && (
            <ul className="panel mt-2 divide-y divide-hairline/60 py-1">
              {reviewed.map((c, i) => (
                <li key={i} className="flex gap-3 px-4 py-2">
                  <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${c.genuine ? "bg-pass" : "bg-txt-faint"}`} />
                  <div className="min-w-0">
                    <div className="truncate font-mono text-2xs text-txt-dim">{c.url}</div>
                    <div className="text-2xs text-txt-faint">{c.reason}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export function CveIntelPanel({ runId }: { runId: string }) {
  return (
    <div className="space-y-3">
      <div className="eyebrow">CVE intelligence</div>
      <AnalysisPanel<CveResearch>
        runId={runId}
        agent="cve-research"
        runLabel="Run CVE research"
        runningLabel="Fetching CVE metadata and locating a public exploit…"
        intro="Fetches canonical metadata (NVD/OSV/GHSA), CISA KEV status, and searches Metasploit / Exploit-DB / Nuclei / PoC repos for a genuine public exploit — validated by a genuineness judge."
        render={(r) => <Intel r={r} />}
      />
    </div>
  );
}
