import { useState } from "react";
import type { GroundTruth } from "../types";
import { PUBLISHED, api } from "../api";
import { DiffViewer } from "./DiffViewer";
import { CveIntelPanel } from "./CveIntelPanel";

function ExtLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="focusable inline-flex items-center gap-1 rounded text-iris hover:text-txt hover:underline"
    >
      {children}
      <span className="text-2xs text-txt-faint">↗</span>
    </a>
  );
}

function CommitRef({ url, sha }: { url: string | null; sha: string }) {
  const short = sha.slice(0, 10);
  return url ? (
    <ExtLink href={url}>
      <span className="font-mono text-xs">{short}</span>
    </ExtLink>
  ) : (
    <span className="font-mono text-xs text-txt-dim">{short}</span>
  );
}

export function GroundTruthPanel({ gt, runId }: { gt: GroundTruth; runId: string }) {
  const [diffs, setDiffs] = useState<GroundTruth["official_fix_diffs"] | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function loadDiffs() {
    setLoading(true);
    setErr(null);
    api
      .groundTruth(runId, true)
      .then((full) => setDiffs(full.official_fix_diffs ?? []))
      .catch((e) => setErr(String(e.message ?? e)))
      .finally(() => setLoading(false));
  }

  const prodLoc = gt.fix_localizations.filter((l) => !l.is_test);
  const testLoc = gt.fix_localizations.filter((l) => l.is_test);

  return (
    <div className="space-y-4">
      <CveIntelPanel runId={runId} />

      <div className="grid gap-px overflow-hidden rounded-md border border-hairline bg-hairline sm:grid-cols-2">
        {[
          ["CVE", gt.cve_id],
          ["CWE", `${gt.cwe_id}`],
          ["project", gt.project_slug],
          ["advisory", gt.advisory_id || "—"],
        ].map(([k, v]) => (
          <div key={k} className="bg-panel px-3 py-2">
            <div className="eyebrow">{k}</div>
            <div className="mt-0.5 truncate font-mono text-xs text-txt">{v}</div>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
        {gt.links.nvd && <ExtLink href={gt.links.nvd}>NVD</ExtLink>}
        {gt.links.advisory && <ExtLink href={gt.links.advisory}>GitHub Advisory</ExtLink>}
        {gt.links.repo && <ExtLink href={gt.links.repo}>{gt.repo}</ExtLink>}
      </div>

      <div className="space-y-2">
        <div className="eyebrow">Commits</div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-xs">
          <span className="text-txt-faint">buggy</span>
          <CommitRef url={gt.links.buggy_commit} sha={gt.buggy_commit_id} />
          <span className="ml-2 text-txt-faint">fix</span>
          {gt.fix_commit_ids.map((sha) => (
            <CommitRef key={sha} url={gt.repo ? `https://github.com/${gt.repo}/commit/${sha}` : null} sha={sha} />
          ))}
        </div>
      </div>

      {prodLoc.length > 0 && (
        <div className="space-y-2">
          <div className="eyebrow">Official fix localization · {prodLoc.length} site(s)</div>
          <div className="overflow-hidden rounded-md border border-hairline">
            <table className="w-full border-collapse font-mono text-2xs">
              <thead>
                <tr className="bg-ink2 text-left text-txt-faint">
                  <th className="px-3 py-2 font-medium">file</th>
                  <th className="px-3 py-2 font-medium">class</th>
                  <th className="px-3 py-2 font-medium">method</th>
                  <th className="px-3 py-2 font-medium">lines</th>
                </tr>
              </thead>
              <tbody>
                {prodLoc.map((l, i) => (
                  <tr key={i} className="border-t border-hairline">
                    <td className="px-3 py-2 text-txt">{l.file.split("/").pop()}</td>
                    <td className="px-3 py-2 text-txt-dim">{l.class || "—"}</td>
                    <td className="px-3 py-2 text-iris/90">{l.method || "—"}</td>
                    <td className="px-3 py-2 text-txt-faint">
                      {l.method_start && l.method_end ? `${l.method_start}–${l.method_end}` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {testLoc.length > 0 && (
            <div className="text-2xs text-txt-faint">+ {testLoc.length} change(s) in tests</div>
          )}
        </div>
      )}

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="eyebrow">Official fix diff</div>
          {!diffs && (
            <button
              type="button"
              onClick={loadDiffs}
              disabled={loading}
              className="focusable rounded-md border border-hairline bg-elevated px-3 py-1.5 font-mono text-2xs text-txt-dim hover:border-iris/50 hover:text-txt disabled:opacity-50"
            >
              {loading ? "loading…" : PUBLISHED ? "show official fix diff" : "fetch from GitHub"}
            </button>
          )}
        </div>
        {err && <div className="font-mono text-2xs text-fail">{err}</div>}
        {diffs?.map((d) => (
          <div key={d.sha} className="panel overflow-hidden">
            <div className="flex items-center justify-between border-b border-hairline bg-ink2 px-3 py-1.5">
              <span className="font-mono text-2xs text-txt-dim">{d.sha.slice(0, 12)}</span>
              {d.url && <ExtLink href={d.url}>view on GitHub</ExtLink>}
            </div>
            {d.error ? (
              <div className="p-3 font-mono text-2xs text-fail">{d.error}</div>
            ) : (
              <div className="max-h-96 overflow-auto py-2">
                <DiffViewer diff={d.diff ?? ""} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
