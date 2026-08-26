import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { PUBLISHED, api } from "../api";
import type { RunSummary } from "../types";
import { cost, cweShort, relTime, statusTone } from "../lib/format";

// Profile → chip tone. Keeps the experiment arm legible at a glance across a
// grouped project's runs.
export function profileTone(profile: string): string {
  switch (profile) {
    case "full":
      return "text-iris";
    case "baseline":
      return "text-warn";
    case "baseline_eval":
      return "text-info";
    case "hardening":
      return "text-pass";
    default:
      return "text-txt-dim";
  }
}

// Model families whose name is an acronym, so title-casing them reads wrong
// ("Glm 5.3", "Gpt 5.6"). Anything not listed keeps the title-cased default.
const MODEL_ACRONYMS = new Set(["glm", "gpt"]);

export function shortModel(model: string | null): string {
  if (!model) return "default";
  // An alternate-provider slug is `vendor/model[:variant]` ("z-ai/glm-5.2",
  // "deepseek/deepseek-v4-flash"). The vendor half is routing, not identity —
  // splitting the whole slug on "-" turned it into "Z ai/glm.5.3" — so keep the
  // model half and carry any routing variant through as a suffix.
  let m = model.replace(/^claude-/, "").replace(/-\d{8}$/, "");
  const slash = m.lastIndexOf("/");
  if (slash !== -1) m = m.slice(slash + 1);
  const colon = m.indexOf(":");
  const variant = colon === -1 ? "" : m.slice(colon + 1);
  if (colon !== -1) m = m.slice(0, colon);
  const oneM = /\[1m\]/i.test(m);
  m = m.replace(/\[1m\]/i, "");
  const parts = m.split("-").filter(Boolean);
  if (parts.length === 0) return model;
  const head = parts[0];
  const name = MODEL_ACRONYMS.has(head.toLowerCase())
    ? head.toUpperCase()
    : head.charAt(0).toUpperCase() + head.slice(1);
  const ver = parts.slice(1).join(".");
  let label = ver ? `${name} ${ver}` : name;
  if (oneM) label += " (1M)";
  return variant ? `${label} (${variant})` : label;
}

function AgentDots({ agents }: { agents: RunSummary["agents"] }) {
  const all = ["exploiter", "patcher", "verifier"];
  const byName = new Map(agents.map((a) => [a.name, a.ok]));
  const hardeningAgents = agents.filter((a) => /^(exploiter|patcher)_harden_r\d+$/.test(a.name));
  return (
    <span
      className="flex items-center gap-1"
      title={agents.map((a) => `${a.name}: ${a.ok ? "ok" : "fail"}`).join(", ")}
    >
      {all.map((name) => {
        const ran = byName.has(name);
        const ok = byName.get(name);
        return (
          <span
            key={name}
            className={`h-1.5 w-1.5 rounded-full ${!ran ? "bg-hairline-strong" : ok ? "bg-pass" : "bg-fail"}`}
          />
        );
      })}
      {hardeningAgents.length > 0 && (
        <span className="ml-0.5 font-mono text-[9px] text-pass">+{hardeningAgents.length}</span>
      )}
    </span>
  );
}

function ScoreCell({ run }: { run: RunSummary }) {
  if (!run.patch_eval) return <span className="text-txt-faint">—</span>;
  const { score, band } = run.patch_eval;
  return (
    <span className="tabular-nums text-txt" title={band ? `band: ${band}` : undefined}>
      {score}
      {band ? <span className="ml-1 text-2xs text-txt-faint">{band}</span> : null}
    </span>
  );
}

function CoverageCell({ run }: { run: RunSummary }) {
  const score = run.coverage_score;
  if (score == null) {
    return (
      <span
        className="text-txt-faint"
        title={run.has_ground_truth ? "No conclusive fixPOV coverage result" : "No fixPOVs"}
      >
        —
      </span>
    );
  }
  const tone = score >= 1 ? "text-pass" : score >= 0.5 ? "text-warn" : "text-fail";
  return (
    <span className={`tabular-nums ${tone}`} title="fixPOV coverage">
      {Math.round(score * 100)}%
    </span>
  );
}

function ResidualCell({ run }: { run: RunSummary }) {
  // Beyond-upstream score: fraction of gaps the OFFICIAL fix leaves open that
  // this patch nonetheless closed. A bonus, so the tone is only ever neutral
  // (0 = matches upstream, the expected norm) or green (>0 = beat upstream) —
  // never red, unlike CoverageCell. See ResidualEvalPanel.
  const score = run.residual_score;
  if (score == null) {
    return (
      <span className="text-txt-faint" title="No residual-gap POVs for this project">
        —
      </span>
    );
  }
  const tone = score > 0 ? "text-pass" : "text-txt-dim";
  return (
    <span
      className={`tabular-nums ${tone}`}
      title="Beyond-upstream: gaps closed that the official fix leaves open (0 = matches upstream, not a failure)"
    >
      {score > 0 ? "+" : ""}
      {Math.round(score * 100)}%
    </span>
  );
}

function RunRow({
  run,
  selected,
  onToggle,
  onDelete,
  onStop,
  busy,
  confirming,
}: {
  run: RunSummary;
  selected: boolean;
  onToggle: (id: string) => void;
  onDelete: (id: string) => void;
  onStop: (id: string) => void;
  busy: boolean;
  confirming: boolean;
}) {
  const tone = statusTone(run.status);
  const active = run.status === "created" || run.status === "running";
  return (
    <tr className={`group border-b border-hairline/60 last:border-0 hover:bg-elevated ${selected ? "bg-elevated/60" : ""}`}>
      <td className="px-3 py-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggle(run.run_id)}
          className="focusable h-3.5 w-3.5 cursor-pointer accent-iris"
          aria-label={`select ${run.run_id}`}
        />
      </td>
      <td className="px-3 py-3">
        <span className={`inline-block h-2 w-2 rounded-full ${tone.dot}`} title={run.status} />
      </td>
      <td className="px-3 py-3">
        <Link to={`/runs/${run.run_id}`} className="focusable font-mono text-xs text-txt hover:text-iris">
          {run.cve_id ?? run.run_id.slice(16)}
        </Link>
        <div className={`font-mono text-2xs ${tone.text}`}>{run.status}</div>
      </td>
      <td className="px-3 py-3">
        <div className="flex flex-wrap gap-1">
          <span className={`chip ${profileTone(run.profile)}`}>{run.profile}</span>
          {run.hardening && (
            <span className="chip text-txt-faint" title={run.hardening.status}>
              {run.hardening.rounds_attempted}/{run.hardening.max_rounds} rounds
            </span>
          )}
        </div>
      </td>
      <td className="px-3 py-3">
        {run.label ? (
          <span className="chip text-txt-dim" title="run label">{run.label}</span>
        ) : (
          <span className="text-txt-faint">—</span>
        )}
      </td>
      <td className="px-3 py-3 font-mono text-2xs text-txt-dim">{shortModel(run.model)}</td>
      <td className="px-3 py-3">
        <span className="chip">{cweShort(run.cwe_id)}</span>
      </td>
      <td className="px-3 py-3">
        <AgentDots agents={run.agents} />
      </td>
      <td className="px-3 py-3 font-mono text-2xs">
        <ScoreCell run={run} />
      </td>
      <td className="px-3 py-3 font-mono text-2xs">
        <CoverageCell run={run} />
      </td>
      <td className="px-3 py-3 font-mono text-2xs">
        <ResidualCell run={run} />
      </td>
      <td className="px-3 py-3 font-mono text-2xs text-txt-dim">{cost(run.totals.cost_usd)}</td>
      <td className="px-3 py-3 font-mono text-2xs text-txt-faint">{relTime(run.timestamp)}</td>
      <td className="px-3 py-3">
        {/* Destructive controls need the live backend — hidden in the published snapshot. */}
        <div
          className={`flex items-center justify-end gap-1.5 transition-opacity ${PUBLISHED ? "hidden" : ""} ${
            confirming ? "opacity-100" : "opacity-0 group-hover:opacity-100"
          }`}
        >
          <a
            href={api.runExportUrl(run.run_id)}
            download
            title="download this run as a ZIP"
            className="focusable rounded border border-iris/40 px-1.5 py-0.5 font-mono text-2xs text-iris hover:bg-iris/10"
          >
            zip
          </a>
          {active && (
            <button
              type="button"
              onClick={() => onStop(run.run_id)}
              disabled={busy}
              title="stop this run"
              className="focusable rounded border border-warn/40 px-1.5 py-0.5 font-mono text-2xs text-warn hover:bg-warn/10 disabled:opacity-40"
            >
              stop
            </button>
          )}
          <button
            type="button"
            onClick={() => onDelete(run.run_id)}
            disabled={busy}
            title={confirming ? "click again to confirm" : "delete this run"}
            className={`focusable rounded border px-1.5 py-0.5 font-mono text-2xs disabled:opacity-40 ${
              confirming
                ? "border-fail bg-fail/20 text-fail"
                : "border-fail/40 text-fail hover:bg-fail/10"
            }`}
          >
            {busy ? "…" : confirming ? "confirm?" : "delete"}
          </button>
        </div>
      </td>
    </tr>
  );
}

const COLS = ["", "", "CVE / Run", "Profile", "Label", "Model", "CWE", "Agents", "Score", "Coverage", "Beyond", "Cost", "When", ""];

interface Group {
  key: string;
  project_slug: string | null;
  cve_id: string | null;
  cwe_id: string | null;
  runs: RunSummary[];
  latest: string | null;
}

function groupRuns(runs: RunSummary[]): Group[] {
  const map = new Map<string, Group>();
  for (const run of runs) {
    const key = run.finding_id ?? run.project_slug ?? run.run_id;
    let g = map.get(key);
    if (!g) {
      g = {
        key,
        project_slug: run.project_slug,
        cve_id: run.cve_id,
        cwe_id: run.cwe_id,
        runs: [],
        latest: run.timestamp,
      };
      map.set(key, g);
    }
    g.runs.push(run);
    if ((run.timestamp ?? "") > (g.latest ?? "")) g.latest = run.timestamp;
  }
  const groups = [...map.values()];
  groups.forEach((g) => g.runs.sort((a, b) => (a.run_id < b.run_id ? 1 : -1)));
  groups.sort((a, b) => ((a.latest ?? "") < (b.latest ?? "") ? 1 : -1));
  return groups;
}

const NONE = "␀none"; // sentinel for "unlabelled" — U+2400 (␀) cannot appear in a real label and is printable, so the file never carries a raw NUL byte

export function RunsExplorer({ runs, onChanged }: { runs: RunSummary[]; onChanged?: () => void }) {
  const nav = useNavigate();
  const [mode, setMode] = useState<"grouped" | "flat">("grouped");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busyId, setBusyId] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Filters — data-driven from the runs themselves so the dropdowns only ever
  // offer values that exist. "all" == no constraint.
  const [search, setSearch] = useState("");
  const [profileF, setProfileF] = useState("all");
  const [labelF, setLabelF] = useState("all");
  const [statusF, setStatusF] = useState("all");

  const uniq = (vals: (string | null)[]) =>
    Array.from(new Set(vals.filter((v): v is string => !!v))).sort();
  const profiles = useMemo(() => uniq(runs.map((r) => r.profile)), [runs]);
  const labels = useMemo(() => uniq(runs.map((r) => r.label)), [runs]);
  const statuses = useMemo(() => uniq(runs.map((r) => r.status)), [runs]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return runs.filter((r) => {
      if (profileF !== "all" && r.profile !== profileF) return false;
      if (labelF === NONE) {
        if (r.label) return false;
      } else if (labelF !== "all" && r.label !== labelF) return false;
      if (statusF !== "all" && r.status !== statusF) return false;
      if (q) {
        const hay = [r.cve_id, r.project_slug, r.run_id, r.label, r.cwe_id, r.cwe_name]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [runs, search, profileF, labelF, statusF]);

  const filtersActive =
    search.trim() !== "" || profileF !== "all" || labelF !== "all" || statusF !== "all";
  function resetFilters() {
    setSearch("");
    setProfileF("all");
    setLabelF("all");
    setStatusF("all");
  }

  const groups = useMemo(() => groupRuns(filtered), [filtered]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function setGroupSelected(ids: string[], shouldSelect: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of ids) {
        if (shouldSelect) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  }

  function compare() {
    if (selected.size < 2) return;
    // Preserve list order (newest first) in the compare view.
    const ids = runs.map((r) => r.run_id).filter((id) => selected.has(id));
    nav(`/compare?ids=${ids.join(",")}`);
  }

  async function exportSelected() {
    if (selected.size === 0) return;
    setExporting(true);
    setErr(null);
    try {
      // Preserve the list's newest-first order in the archive.
      await api.exportRuns(runs.map((r) => r.run_id).filter((id) => selected.has(id)));
    } catch (e) {
      setErr(`Export failed: ${(e as Error).message}`);
    } finally {
      setExporting(false);
    }
  }

  // Two-step delete (click "delete" → "confirm?") — no native dialog.
  async function del(id: string) {
    if (confirmId !== id) {
      setConfirmId(id);
      return;
    }
    setConfirmId(null);
    setBusyId(id);
    setErr(null);
    try {
      await api.deleteRun(id);
      setSelected((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      onChanged?.();
    } catch (e) {
      setErr(`Delete failed: ${(e as Error).message}`);
    } finally {
      setBusyId(null);
    }
  }

  async function stop(id: string) {
    setBusyId(id);
    setErr(null);
    try {
      await api.stopRun(id);
      onChanged?.();
    } catch (e) {
      setErr(`Stop failed: ${(e as Error).message}`);
    } finally {
      setBusyId(null);
    }
  }

  const rowProps = (run: RunSummary) => ({
    selected: selected.has(run.run_id),
    onToggle: toggle,
    onDelete: del,
    onStop: stop,
    busy: busyId === run.run_id,
    confirming: confirmId === run.run_id,
  });

  const multiRunGroups = groups.filter((g) => g.runs.length > 1).length;

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex overflow-hidden rounded-md border border-hairline">
          {(["grouped", "flat"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`focusable px-3 py-1.5 font-mono text-2xs transition-colors ${
                mode === m ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
              }`}
            >
              {m === "grouped" ? "by project" : "all runs"}
            </button>
          ))}
        </div>
        {mode === "grouped" && multiRunGroups > 0 && (
          <span className="font-mono text-2xs text-txt-faint">
            {multiRunGroups} project{multiRunGroups === 1 ? "" : "s"} with multiple runs
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {selected.size > 0 && (
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              className="focusable font-mono text-2xs text-txt-faint hover:text-txt"
            >
              clear
            </button>
          )}
          <button
            type="button"
            onClick={compare}
            disabled={selected.size < 2}
            className="focusable rounded-md bg-iris px-3 py-1.5 text-2xs font-semibold text-ink transition-colors hover:bg-iris/90 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Compare{selected.size >= 2 ? ` (${selected.size})` : ""}
          </button>
          {!PUBLISHED && (
            <button
              type="button"
              onClick={exportSelected}
              disabled={selected.size === 0 || exporting}
              className="focusable rounded-md border border-iris/50 px-3 py-1.5 text-2xs font-semibold text-iris transition-colors hover:bg-iris/10 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {exporting ? "Preparing ZIP…" : `Download ZIP${selected.size ? ` (${selected.size})` : ""}`}
            </button>
          )}
        </div>
      </div>

      {/* Filter bar — search + profile / label / status */}
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search cve / project / run / label"
          className="focusable w-56 rounded-md border border-hairline bg-ink px-2.5 py-1.5 font-mono text-2xs text-txt placeholder:text-txt-faint"
        />
        <FilterSelect label="profile" value={profileF} onChange={setProfileF} options={profiles} />
        {labels.length > 0 && (
          <FilterSelect
            label="label"
            value={labelF}
            onChange={setLabelF}
            options={labels}
            extra={[{ value: NONE, label: "(unlabelled)" }]}
          />
        )}
        <FilterSelect label="status" value={statusF} onChange={setStatusF} options={statuses} />
        {filtersActive && (
          <>
            <button
              type="button"
              onClick={resetFilters}
              className="focusable font-mono text-2xs text-txt-faint hover:text-txt"
            >
              reset
            </button>
            <span className="font-mono text-2xs text-txt-faint">
              {filtered.length} of {runs.length}
            </span>
          </>
        )}
      </div>

      {selected.size === 1 && (
        <div className="font-mono text-2xs text-txt-faint">select one more run to compare.</div>
      )}
      {err && (
        <div className="rounded-md border border-fail/40 px-3 py-2 font-mono text-2xs text-fail">{err}</div>
      )}

      <div className="panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-hairline text-left">
                {COLS.map((h, i) => (
                  <th
                    key={i}
                    className="px-3 py-2.5 font-mono text-2xs uppercase tracking-wider text-txt-faint"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={COLS.length} className="px-3 py-8 text-center font-mono text-2xs text-txt-faint">
                    no runs match the current filters.
                  </td>
                </tr>
              ) : mode === "flat" ? (
                filtered.map((run) => <RunRow key={run.run_id} run={run} {...rowProps(run)} />)
              ) : (
                groups.map((g) => (
                  <GroupSection
                    key={g.key}
                    group={g}
                    rowProps={rowProps}
                    selected={selected}
                    onSetSelected={setGroupSelected}
                  />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
  extra = [],
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
  extra?: { value: string; label: string }[];
}) {
  const active = value !== "all";
  return (
    <label className="flex items-center gap-1.5">
      <span className="font-mono text-2xs text-txt-faint">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`focusable rounded-md border bg-ink px-2 py-1.5 font-mono text-2xs text-txt ${
          active ? "border-iris/60" : "border-hairline"
        }`}
      >
        <option value="all">all</option>
        {extra.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function GroupSection({
  group,
  rowProps,
  selected,
  onSetSelected,
}: {
  group: Group;
  rowProps: (run: RunSummary) => Omit<Parameters<typeof RunRow>[0], "run">;
  selected: Set<string>;
  onSetSelected: (ids: string[], shouldSelect: boolean) => void;
}) {
  const accepted = group.runs.filter((r) => r.status === "accepted").length;
  const selectedCount = group.runs.filter((run) => selected.has(run.run_id)).length;
  const allSelected = selectedCount === group.runs.length;
  return (
    <>
      <tr className="border-b border-hairline bg-ink2/40">
        <td colSpan={COLS.length} className="px-3 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <input
              type="checkbox"
              checked={allSelected}
              ref={(node) => {
                if (node) node.indeterminate = selectedCount > 0 && !allSelected;
              }}
              onChange={() => onSetSelected(group.runs.map((run) => run.run_id), !allSelected)}
              className="focusable h-3.5 w-3.5 cursor-pointer accent-iris"
              aria-label={`select all runs for ${group.project_slug ?? group.cve_id ?? group.key}`}
            />
            <span className="font-mono text-xs text-txt">{group.cve_id ?? group.key}</span>
            <span className="font-mono text-2xs text-txt-faint">{group.project_slug ?? "—"}</span>
            <span className="chip">{cweShort(group.cwe_id)}</span>
            <span className="ml-auto font-mono text-2xs text-txt-faint">
              {group.runs.length} run{group.runs.length === 1 ? "" : "s"} · {accepted} accepted
            </span>
          </div>
        </td>
      </tr>
      {group.runs.map((run) => (
        <RunRow key={run.run_id} run={run} {...rowProps(run)} />
      ))}
    </>
  );
}
