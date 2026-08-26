import { Fragment, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { ResidualTriageOverview, ResidualTriageRow } from "../types";

/**
 * Residual-gap audit surface.
 *
 * A certified residual PoV proves only that the exploit survives the official
 * fix — it is an instrument, not a finding. This page shows the three
 * independent things that turn one into a claim, side by side and never merged:
 *
 *   certification  what `respov validate` recorded inside the manifest
 *   upstream       what the code at the project's current HEAD looks like now
 *   execution      what `respov reverify` got when it ran the PoV itself,
 *                  including the falsifiability control on a later tree
 *
 * Every row carries the commands to redo it, so a reader can check any claim by
 * hand rather than trusting the table.
 */

const STATUS_STYLE: Record<string, string> = {
  "open-at-head": "border-fail/40 bg-fail/10 text-fail",
  "fixed-later": "border-info/40 bg-info/10 text-info",
  "superseded-in-release": "border-hairline bg-elevated text-txt-dim",
  disputed: "border-warn/40 bg-warn/10 text-warn",
  unsound: "border-warn/40 bg-warn/10 text-warn",
  "needs-manual": "border-hairline bg-elevated text-txt-dim",
  untriaged: "border-hairline bg-surface text-txt-faint",
};

const SIGNAL_HELP: Record<string, string> = {
  fix_intact: "every line the official fix added is still verbatim at upstream HEAD — the fix has not been revised",
  fix_changed: "some of the official fix's lines are gone at HEAD — upstream rewrote it at some point",
  file_absent: "the guarded file is no longer at that path (rename/refactor) — needs a human",
  not_checked: "no upstream sweep has run for this suite yet",
  no_patch: "no official_fix.patch recorded",
};

const OUTCOME_STYLE: Record<string, string> = {
  reproduced: "text-fail",
  blocked: "text-pass",
  errored: "text-warn",
};

function Pill({ label, tone, title }: { label: string; tone: string; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-2xs ${tone}`}>
      {label}
    </span>
  );
}

function Stat({ value, label, hint }: { value: number | string; label: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-hairline bg-elevated px-4 py-3" title={hint}>
      <div className="font-display text-xl font-bold text-txt">{value}</div>
      <div className="mt-0.5 text-2xs uppercase tracking-wide text-txt-faint">{label}</div>
    </div>
  );
}

function Detail({ row }: { row: ResidualTriageRow }) {
  const trees = Object.entries(row.execution.trees ?? {});
  return (
    <div className="grid gap-4 border-t border-hairline bg-surface/50 px-4 py-4 lg:grid-cols-3">
      <section className="space-y-2">
        <h4 className="font-mono text-2xs uppercase tracking-wide text-txt-faint">The gap</h4>
        <p className="text-xs leading-relaxed text-txt-dim">{row.gap_summary || row.pov.gap_summary}</p>
        {row.pov.exploit_path && (
          <p className="font-mono text-2xs leading-relaxed text-txt-faint">{row.pov.exploit_path}</p>
        )}
        <div className="flex flex-wrap gap-1.5 pt-1">
          <Pill
            label={row.pov.certified ? "certified" : "not certified"}
            tone={row.pov.certified ? "border-pass/40 bg-pass/10 text-pass" : "border-warn/40 bg-warn/10 text-warn"}
            title={`respov validate: ${row.pov.certified_before} on unpatched, ${row.pov.certified_after} after the official fix`}
          />
          {row.claim_class && <Pill label={row.claim_class} tone="border-hairline bg-elevated text-txt-dim" />}
          {row.confidence && <Pill label={`confidence: ${row.confidence}`} tone="border-hairline bg-elevated text-txt-dim" />}
        </div>
        {row.pov.command && (
          <pre className="overflow-x-auto rounded border border-hairline bg-ink px-2 py-1 font-mono text-2xs text-txt-dim">
            {row.pov.command}
          </pre>
        )}
      </section>

      <section className="space-y-2">
        <h4 className="font-mono text-2xs uppercase tracking-wide text-txt-faint">Upstream today</h4>
        <div className="text-xs text-txt-dim">
          <span className="font-mono">{row.upstream_repo ?? "—"}</span>
          {row.upstream_liveness && (
            <span className="text-txt-faint">
              {" "}· pushed {row.upstream_liveness.pushed_at}
              {row.upstream_liveness.archived ? " · archived" : ""}
              {typeof row.upstream_liveness.stars === "number" ? ` · ★${row.upstream_liveness.stars}` : ""}
            </span>
          )}
        </div>
        <ul className="space-y-1">
          {(row.upstream_files ?? []).map((f) => (
            <li key={f.path} className="font-mono text-2xs text-txt-faint">
              <span className={f.state === "fix_intact" ? "text-fail" : "text-info"}>{f.state}</span>{" "}
              {f.path.split("/").slice(-2).join("/")}
              {typeof f.missing === "number" && f.missing > 0 && (
                <span className="text-txt-faint"> ({f.missing}/{f.signature_lines} fix lines gone)</span>
              )}
            </li>
          ))}
        </ul>
        {row.later_fix_commit && (
          <p className="text-xs text-txt-dim">
            closed by <span className="font-mono">{row.later_fix_commit}</span> ({row.later_fix_date})
            {row.later_fix_release ? ` — ${row.later_fix_release}` : ""}
            {typeof row.delta_days === "number" && (
              <span className="text-txt-faint"> · {(row.delta_days / 365).toFixed(1)}y after the official fix</span>
            )}
          </p>
        )}
        {row.corroboration && <p className="text-xs text-txt-faint">{row.corroboration}</p>}
        {row.evidence_urls?.length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1">
            {row.evidence_urls.map((u) => (
              <a key={u} href={u} target="_blank" rel="noreferrer" className="focusable font-mono text-2xs text-iris underline">
                {u.replace("https://github.com/", "")}
              </a>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h4 className="font-mono text-2xs uppercase tracking-wide text-txt-faint">Executed evidence</h4>
        {trees.length === 0 ? (
          <p className="text-xs text-txt-faint">
            No independent execution yet. The manifest's own certification is the only run on record.
          </p>
        ) : (
          <table className="w-full text-2xs">
            <tbody>
              {trees.map(([key, t]) => (
                <tr key={key} className="border-b border-hairline/60 last:border-0">
                  <td className="py-1 pr-2 font-mono text-txt-dim">{key}</td>
                  <td className={`py-1 pr-2 font-mono ${OUTCOME_STYLE[t.outcome] ?? "text-txt-dim"}`}>{t.outcome}</td>
                  <td className="py-1 pr-2 font-mono text-txt-faint">exit {t.exit_code ?? "—"}</td>
                  <td className="py-1 font-mono text-txt-faint">
                    {t.verdict === "as_expected" ? "✓ as expected" : t.verdict === "contradicts" ? "✗ contradicts" : "· inconclusive"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="text-2xs text-txt-faint">
          falsifiability control:{" "}
          <span className={row.execution.falsifiability_control === "passed" ? "text-pass" : "text-txt-dim"}>
            {row.execution.falsifiability_control}
          </span>
        </p>
        <pre className="overflow-x-auto rounded border border-hairline bg-ink px-2 py-1 font-mono text-2xs text-txt-dim">
{`python -m security_pipeline respov reverify \\
  --project ${row.project_slug}${row.later_fix_commit ? ` \\\n  --at ${row.later_fix_commit}` : ""}`}
        </pre>
        {row.notes && <p className="text-2xs leading-relaxed text-txt-faint">{row.notes}</p>}
        {row.verified_by && <p className="text-2xs text-txt-faint">verified by: {row.verified_by}</p>}
      </section>
    </div>
  );
}

export function ResidualTriage() {
  const [data, setData] = useState<ResidualTriageOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    api.residualTriage().then(setData).catch((e) => setError(String(e)));
  }, []);

  const rows = useMemo(() => {
    if (!data?.rows) return [];
    const q = query.trim().toLowerCase();
    return data.rows.filter((r) => {
      if (status !== "all" && r.status !== status) return false;
      if (!q) return true;
      return (
        r.project_slug.toLowerCase().includes(q) ||
        r.pov_id.toLowerCase().includes(q) ||
        r.cve_id.toLowerCase().includes(q) ||
        (r.gap_summary ?? "").toLowerCase().includes(q)
      );
    });
  }, [data, status, query]);

  if (error) return <div className="mx-auto max-w-6xl px-6 py-10 text-sm text-fail">{error}</div>;
  if (!data) return <div className="mx-auto max-w-6xl px-6 py-10 text-sm text-txt-faint">Loading…</div>;
  if (!data.available)
    return <div className="mx-auto max-w-6xl px-6 py-10 text-sm text-txt-dim">{data.reason}</div>;

  const s = data.summary;
  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <header className="mb-6">
        <h1 className="font-display text-2xl font-bold text-txt">Residual-gap audit</h1>
        <p className="mt-1 max-w-3xl text-sm leading-relaxed text-txt-dim">
          Each row is one certified residual PoV — an exploit that still works <em>after</em> the project's official
          CVE fix. Certification proves it is a usable instrument; it does not prove the gap mattered. These columns
          separate what the manifest claims, what upstream's code looks like today, and what we got when we ran the
          PoV ourselves.
        </p>
      </header>

      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Stat value={s.povs} label="residual PoVs" hint="certified exploits that survive the official fix" />
        <Stat value={s.projects} label="projects" />
        <Stat value={s.by_status["open-at-head"] ?? 0} label="open at head" hint="the same defect is still in upstream's current code" />
        <Stat value={s.by_status["fixed-later"] ?? 0} label="fixed later" hint="upstream itself closed this path, after the CVE fix" />
        <Stat value={s.executed} label="re-executed" hint="PoVs re-run independently by respov reverify" />
        <Stat
          value={s.falsifiability_controls_passed}
          label="controls passed"
          hint="PoVs proven falsifiable: blocked on a tree where upstream closed the gap"
        />
      </div>

      {s.execution_contradictions > 0 && (
        <div className="mb-4 rounded-lg border border-fail/40 bg-fail/10 px-4 py-3 text-sm text-fail">
          {s.execution_contradictions} PoV(s) behaved differently from what their tree expects — open those rows first.
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {["all", ...Object.keys(s.by_status)].map((k) => (
          <button
            key={k}
            onClick={() => setStatus(k)}
            className={`focusable rounded-full border px-3 py-1 font-mono text-2xs ${
              status === k ? "border-iris/50 bg-iris/10 text-iris" : "border-hairline bg-elevated text-txt-dim"
            }`}
          >
            {k}
            {k !== "all" && <span className="ml-1.5 text-txt-faint">{s.by_status[k]}</span>}
          </button>
        ))}
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="filter by project, CVE, PoV id…"
          className="focusable ml-auto w-64 rounded-md border border-hairline bg-elevated px-3 py-1.5 text-xs text-txt placeholder:text-txt-faint"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-hairline">
        <table className="w-full text-left text-xs">
          <thead className="bg-elevated text-2xs uppercase tracking-wide text-txt-faint">
            <tr>
              <th className="px-4 py-2 font-medium">Project / PoV</th>
              <th className="px-3 py-2 font-medium">CVE</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Upstream now</th>
              <th className="px-3 py-2 font-medium">Lead</th>
              <th className="px-3 py-2 font-medium">Executed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const expanded = open === r.pov_uid;
              return (
                <Fragment key={r.pov_uid}>
                  <tr
                    onClick={() => setOpen(expanded ? null : r.pov_uid)}
                    className={`cursor-pointer border-t border-hairline hover:bg-elevated/60 ${expanded ? "bg-elevated/60" : ""}`}
                  >
                    <td className="px-4 py-2">
                      <div className="font-mono text-txt">{r.pov_id}</div>
                      <div className="font-mono text-2xs text-txt-faint">{r.project_slug}</div>
                    </td>
                    <td className="px-3 py-2 font-mono text-2xs text-txt-dim">{r.cve_id}</td>
                    <td className="px-3 py-2">
                      <Pill label={r.status} tone={STATUS_STYLE[r.status] ?? STATUS_STYLE.untriaged} />
                    </td>
                    <td className="px-3 py-2 font-mono text-2xs text-txt-dim" title={SIGNAL_HELP[r.upstream_signal]}>
                      {r.upstream_signal}
                    </td>
                    <td className="px-3 py-2 font-mono text-2xs text-txt-faint">
                      {typeof r.delta_days === "number" ? `${(r.delta_days / 365).toFixed(1)}y` : r.later_fix_commit ? "—" : ""}
                    </td>
                    <td className="px-3 py-2 font-mono text-2xs">
                      {r.execution.ran ? (
                        <span
                          className={
                            r.execution.summary === "contradicts"
                              ? "text-fail"
                              : r.execution.falsifiability_control === "passed"
                                ? "text-pass"
                                : "text-txt-dim"
                          }
                        >
                          {r.execution.summary}
                          {r.execution.falsifiability_control === "passed" ? " · control ✓" : ""}
                        </span>
                      ) : (
                        <span className="text-txt-faint">not re-run</span>
                      )}
                    </td>
                  </tr>
                  {expanded && (
                    <tr>
                      <td colSpan={6} className="p-0">
                        <Detail row={r} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="mt-4 text-2xs leading-relaxed text-txt-faint">
        Generated {data.generated_at}. {data.note}
      </p>
    </div>
  );
}
