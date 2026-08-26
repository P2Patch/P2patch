import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type MouseEvent,
  type SetStateAction,
} from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cweShort, duration, statusTone } from "../lib/format";
import type { AgentActivity, AgentSummary, LaunchRecord, LiveSnapshot, LiveTarget, SchedulerStatus, Stage } from "../types";
import { StageRail } from "../components/StageRail";
import { StatusPill } from "../components/StatusPill";
import { LiveConsole } from "../components/LiveConsole";
import { HardeningPanel } from "../components/HardeningPanel";
import { RetriesPanel } from "../components/RetriesPanel";

const EFFORTS = ["low", "medium", "high", "xhigh", "max"];

/** Toggle one value of a config axis, never leaving the axis empty — an axis
 *  with no values selected would multiply the run matrix out to nothing. */
function toggleAxis(setter: Dispatch<SetStateAction<Set<string>>>, v: string) {
  setter((prev) => {
    const next = new Set(prev);
    if (next.has(v)) {
      if (next.size === 1) return prev;
      next.delete(v);
    } else {
      next.add(v);
    }
    return next;
  });
}

/** A bounded numeric knob (retry budgets, round limits). */
function Stepper({
  label,
  hint,
  value,
  min,
  max,
  onChange,
  disabled = false,
}: {
  label: string;
  hint?: string;
  value: number;
  min: number;
  max: number;
  onChange: (n: number) => void;
  disabled?: boolean;
}) {
  const step = (delta: number) => onChange(Math.min(max, Math.max(min, value + delta)));
  return (
    <div className={`flex items-center gap-2 ${disabled ? "opacity-40" : ""}`}>
      <button
        type="button"
        onClick={() => step(-1)}
        disabled={disabled || value <= min}
        className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt disabled:opacity-30"
      >
        −
      </button>
      <span className="w-8 text-center font-mono text-sm tabular-nums text-txt">{value}</span>
      <button
        type="button"
        onClick={() => step(1)}
        disabled={disabled || value >= max}
        className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt disabled:opacity-30"
      >
        +
      </button>
      <div className="ml-1 min-w-0">
        <div className="font-mono text-2xs text-txt">{label}</div>
        {hint && <div className="truncate font-mono text-2xs text-txt-faint">{hint}</div>}
      </div>
    </div>
  );
}

/** A multi-select row of config values — every selected value becomes a run. */
function AxisGroup({
  options,
  selected,
  onToggle,
  fill,
}: {
  options: { value: string; label: string }[];
  selected: Set<string>;
  onToggle: (v: string) => void;
  fill?: boolean;
}) {
  return (
    <div className={`flex gap-1 ${fill ? "" : "flex-wrap"}`}>
      {options.map((o) => {
        const on = selected.has(o.value);
        return (
          <button
            key={o.value || "default"}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(o.value)}
            className={`focusable rounded-md border px-2 py-1.5 font-mono text-2xs transition-colors ${
              fill ? "flex-1" : ""
            } ${on ? "border-iris/60 bg-elevated text-txt" : "border-hairline text-txt-dim hover:text-txt"}`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/** Ticks once a second while `on` — drives the live elapsed clocks. */
function useClock(on: boolean): number {
  const [, setN] = useState(0);
  useEffect(() => {
    if (!on) return;
    const t = setInterval(() => setN((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [on]);
  return Date.now();
}

function secs(s: number): string {
  if (s < 60) return `${Math.floor(s)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.floor(s % 60)}s`;
}

// ---------------------------------------------------------------------------
// Launch console
// ---------------------------------------------------------------------------
/**
 * Fetch a missing project source on demand. Kicks off a background clone on the
 * backend, polls until the source tree lands (or the job errors), then asks the
 * parent to refresh the target list so the row flips to runnable.
 */
function CloneButton({ slug, clonable, onCloned }: { slug: string; clonable?: boolean; onCloned: () => void }) {
  const [state, setState] = useState<"idle" | "cloning" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  async function clone(e: MouseEvent) {
    e.stopPropagation(); // don't toggle the row's selection
    if (state === "cloning") return;
    setState("cloning");
    setError(null);
    try {
      await api.cloneSource(slug);
      // Poll until the source is present or the job reports an error (~5 min cap).
      for (let i = 0; i < 150 && alive.current; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        if (!alive.current) return;
        const s = await api.sourceStatus(slug);
        if (s.present) { onCloned(); return; }
        if (s.state === "error") throw new Error(s.error || "clone failed");
      }
      if (alive.current) throw new Error("clone timed out");
    } catch (err) {
      if (alive.current) {
        setState("error");
        setError(String((err as Error).message ?? err));
      }
    }
  }

  if (clonable === false) {
    return <span className="chip text-warn" title="No clone metadata in project_info.csv">no sources</span>;
  }
  return (
    <button
      type="button"
      onClick={clone}
      disabled={state === "cloning"}
      title={error ?? "Clone the project source so this finding can be run for real"}
      className={`focusable rounded border px-1.5 py-0.5 font-mono text-2xs transition-colors ${
        state === "error"
          ? "border-fail/50 text-fail hover:bg-fail/10"
          : "border-iris/40 text-iris hover:bg-iris/10 disabled:opacity-60"
      }`}
    >
      {state === "cloning" ? "cloning…" : state === "error" ? "retry clone" : "clone source"}
    </button>
  );
}

function TargetRow({
  t,
  selected,
  onSelect,
  onCloned,
}: {
  t: LiveTarget;
  selected: boolean;
  onSelect: () => void;
  onCloned: () => void;
}) {
  return (
    <div
      className={`flex w-full items-center gap-3 border-l-2 pr-3 transition-colors ${
        selected ? "border-iris bg-elevated" : "border-transparent hover:bg-elevated/50"
      }`}
    >
      <button
        type="button"
        onClick={onSelect}
        className="focusable flex min-w-0 flex-1 items-center gap-3 px-3 py-2.5 text-left"
      >
        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${selected ? "bg-iris" : "bg-txt-faint/40"}`} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-txt">{t.cve_id}</span>
            <span className="chip">{cweShort(t.cwe_id)}</span>
          </div>
          <div className="mt-0.5 truncate font-mono text-2xs text-txt-faint">{t.project_slug}</div>
        </div>
      </button>
      <div className="flex shrink-0 flex-col items-end gap-1">
        {!t.sources_present && <CloneButton slug={t.project_slug} clonable={t.clonable} onCloned={onCloned} />}
        {(t.prior_runs ?? []).length > 0 && (
          <span className="font-mono text-2xs text-txt-faint">{(t.prior_runs ?? []).length} prior</span>
        )}
      </div>
    </div>
  );
}

function Toggle({
  label,
  hint,
  on,
  onChange,
  disabled,
}: {
  label: string;
  hint?: string;
  on: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onChange(!on)}
      className="focusable flex items-center gap-2.5 rounded-md px-1 py-1 text-left disabled:opacity-40"
    >
      <span
        className={`relative h-4 w-7 shrink-0 rounded-full transition-colors ${on ? "bg-iris" : "bg-hairline-strong"}`}
      >
        <span
          className={`absolute top-0.5 h-3 w-3 rounded-full bg-ink transition-transform ${on ? "translate-x-3.5" : "translate-x-0.5"}`}
        />
      </span>
      <span>
        <span className="text-xs text-txt">{label}</span>
        {hint && <span className="ml-2 font-mono text-2xs text-txt-faint">{hint}</span>}
      </span>
    </button>
  );
}

function LaunchPanel({
  onLaunched,
  onBatched,
}: {
  onLaunched: (launchId: string, target: LiveTarget) => void;
  onBatched: () => void;
}) {
  const [targetsNonce, setTargetsNonce] = useState(0);
  const targetsQ = useAsync<LiveTarget[]>(() => api.liveTargets(), [targetsNonce]);
  const optionsQ = useAsync(() => api.liveOptions(), []);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  // Each config axis is a set — the launcher queues the full cross product, so
  // one finding can be run across several profiles/models/efforts at once.
  const [efforts, setEfforts] = useState<Set<string>>(new Set(["high"]));
  const [profiles, setProfiles] = useState<Set<string>>(new Set(["full"]));
  const [models, setModels] = useState<Set<string>>(new Set([""]));
  const [maxRounds, setMaxRounds] = useState(4);
  // Retry budgets: how many times a failing gate is handed back to the patcher
  // (POV-after / regressions / a hardening round) or to the exploiter (POV-before).
  const [maxCorrections, setMaxCorrections] = useState(3);
  const [maxExploits, setMaxExploits] = useState(3);
  const [label, setLabel] = useState("");
  const [concurrency, setConcurrency] = useState(1);
  const [dryRun, setDryRun] = useState(false);
  const [skipDocker, setSkipDocker] = useState(false);
  const [rerun, setRerun] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const profileOpts = optionsQ.data?.profiles ?? [];
  const modelOpts = optionsQ.data?.models ?? [];
  const modelLabel = (v: string) => modelOpts.find((m) => m.value === v)?.label ?? (v || "default");
  // The blurb below the profile row only makes sense for a single profile.
  const soleProfile = profiles.size === 1 ? profileOpts.find((p) => profiles.has(p.value)) ?? null : null;
  const includesHardening = profiles.has("hardening");
  const includesExploiter = profileOpts.some(
    (p) => profiles.has(p.value) && p.stages.includes("exploiter"),
  );
  const roundLimits = optionsQ.data?.hardening_rounds ?? { default: 4, min: 1, max: 10 };
  const correctionLimits = optionsQ.data?.correction_attempts ?? { default: 3, min: 1, max: 10 };
  const exploitLimits = optionsQ.data?.exploit_attempts ?? { default: 3, min: 1, max: 10 };
  const targets = targetsQ.data ?? [];
  const selectedTargets = useMemo(() => targets.filter((t) => sel.has(t.alert_file)), [targets, sel]);
  const count = selectedTargets.length;
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter(
      (t) =>
        t.cve_id.toLowerCase().includes(q) ||
        t.project_slug.toLowerCase().includes(q) ||
        t.cwe_id.toLowerCase().includes(q),
    );
  }, [targets, query]);

  // "Select all" acts on what the filter is showing, so you can build a
  // selection from several searches in a row.
  const allShownSelected = filtered.length > 0 && filtered.every((t) => sel.has(t.alert_file));

  function toggle(af: string) {
    setSel((prev) => {
      const next = new Set(prev);
      if (next.has(af)) next.delete(af);
      else next.add(af);
      return next;
    });
  }

  function toggleAllShown() {
    setSel((prev) => {
      const next = new Set(prev);
      for (const t of filtered) {
        if (allShownSelected) next.delete(t.alert_file);
        else next.add(t.alert_file);
      }
      return next;
    });
  }

  // A real (non-dry) run needs local sources; those without are skipped.
  const missingSources = dryRun ? [] : selectedTargets.filter((t) => !t.sources_present);
  const runnable = selectedTargets.filter((t) => dryRun || t.sources_present);

  // One run per (finding × effort × profile × model).
  const combos = efforts.size * profiles.size * models.size;
  const totalRuns = runnable.length * combos;

  async function go() {
    if (totalRuns === 0) return;
    setBusy(true);
    setErr(null);
    const axes = {
      efforts: [...efforts],
      profiles: [...profiles],
      models: [...models].map((m) => m || null),
    };
    try {
      // A lone run skips the queue and opens the monitor directly.
      if (totalRuns === 1) {
        const t = runnable[0];
        const res = await api.launch({
          alert_file: t.alert_file,
          effort: axes.efforts[0],
          profile: axes.profiles[0],
          model: axes.models[0],
          label: label.trim(),
          dry_run: dryRun,
          skip_docker_build: skipDocker,
          rerun,
          max_rounds: maxRounds,
          max_correction_attempts: maxCorrections,
          max_exploit_attempts: maxExploits,
        });
        onLaunched(res.launch_id, t);
      } else {
        await api.launchBatch({
          alert_files: runnable.map((t) => t.alert_file),
          concurrency,
          label: label.trim(),
          dry_run: dryRun,
          skip_docker_build: skipDocker,
          rerun,
          max_rounds: maxRounds,
          max_correction_attempts: maxCorrections,
          max_exploit_attempts: maxExploits,
          ...axes,
        });
        setSel(new Set());
        onBatched();
      }
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[1.1fr_1fr]">
      {/* Target picker */}
      <div className="panel flex flex-col overflow-hidden">
        <div className="flex items-center justify-between border-b border-hairline px-4 py-3">
          <span className="eyebrow">select findings{count > 0 ? ` · ${count}` : ""}</span>
          <div className="flex items-center gap-2">
            {filtered.length > 0 && (
              <button
                type="button"
                onClick={toggleAllShown}
                className="focusable font-mono text-2xs text-iris hover:text-txt"
              >
                {allShownSelected ? "deselect all" : `select all${query.trim() ? ` (${filtered.length})` : ""}`}
              </button>
            )}
            {count > 0 && (
              <button
                type="button"
                onClick={() => setSel(new Set())}
                className="focusable font-mono text-2xs text-txt-faint hover:text-txt"
              >
                clear
              </button>
            )}
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter cve / project / cwe"
              className="focusable w-40 rounded border border-hairline bg-ink px-2 py-1 font-mono text-2xs text-txt placeholder:text-txt-faint"
            />
          </div>
        </div>
        <div className="max-h-[26rem] divide-y divide-hairline/60 overflow-auto">
          {targetsQ.loading && <div className="px-4 py-6 font-mono text-2xs text-txt-faint animate-pulse2">loading targets…</div>}
          {targetsQ.error && <div className="px-4 py-6 font-mono text-2xs text-fail">{targetsQ.error}</div>}
          {filtered.map((t) => (
            <TargetRow
              key={t.alert_file}
              t={t}
              selected={sel.has(t.alert_file)}
              onSelect={() => toggle(t.alert_file)}
              onCloned={() => setTargetsNonce((n) => n + 1)}
            />
          ))}
          {targetsQ.data && filtered.length === 0 && (
            <div className="px-4 py-6 font-mono text-2xs text-txt-faint">no findings match “{query}”.</div>
          )}
        </div>
      </div>

      {/* Options + arm */}
      <div className="panel flex flex-col p-5">
        <span className="eyebrow">run configuration</span>

        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="font-mono text-2xs text-txt-faint">reasoning effort</span>
            {efforts.size > 1 && <span className="font-mono text-2xs text-iris">{efforts.size} selected</span>}
          </div>
          <AxisGroup
            options={EFFORTS.map((e) => ({ value: e, label: e }))}
            selected={efforts}
            onToggle={(v) => toggleAxis(setEfforts, v)}
            fill
          />
        </div>

        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="font-mono text-2xs text-txt-faint">experiment profile</span>
            {soleProfile ? (
              <span className="font-mono text-2xs text-txt-faint">
                {soleProfile.patcher_evidence === "full" ? "patcher sees POV" : "patcher: alert-only"} ·{" "}
                {soleProfile.stages.length} stages
              </span>
            ) : (
              <span className="font-mono text-2xs text-iris">{profiles.size} selected</span>
            )}
          </div>
          <AxisGroup
            options={profileOpts.map((p) => ({ value: p.value, label: p.value }))}
            selected={profiles}
            onToggle={(v) => toggleAxis(setProfiles, v)}
          />
          {soleProfile && (
            <p className="mt-1.5 text-2xs leading-relaxed text-txt-faint">{soleProfile.description}</p>
          )}
        </div>

        {includesHardening && (
          <div className="mt-4 rounded-md border border-iris/30 bg-elevated/40 p-3">
            <div className="mb-2 flex items-start justify-between gap-3">
              <div>
                <div className="font-mono text-2xs text-txt">hardening round limit</div>
                <p className="mt-0.5 text-2xs leading-relaxed text-txt-faint">
                  Stops early when the exploiter finds no new bypass.
                </p>
              </div>
              <span className="chip text-iris">hardening</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setMaxRounds((n) => Math.max(roundLimits.min, n - 1))}
                disabled={maxRounds <= roundLimits.min}
                className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt disabled:opacity-30"
              >
                −
              </button>
              <span className="w-8 text-center font-mono text-sm tabular-nums text-txt">{maxRounds}</span>
              <button
                type="button"
                onClick={() => setMaxRounds((n) => Math.min(roundLimits.max, n + 1))}
                disabled={maxRounds >= roundLimits.max}
                className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt disabled:opacity-30"
              >
                +
              </button>
              <span className="ml-1 font-mono text-2xs text-txt-faint">
                {roundLimits.min}–{roundLimits.max} allowed
              </span>
            </div>
          </div>
        )}

        <div className="mt-4 rounded-md border border-hairline bg-elevated/40 p-3">
          <div className="mb-2">
            <div className="font-mono text-2xs text-txt">retry budgets</div>
            <p className="mt-0.5 text-2xs leading-relaxed text-txt-faint">
              A failing objective check goes back to the agent that owns it instead of
              rejecting the run. 1 = one-shot gates.
            </p>
          </div>
          <div className="space-y-2">
            <Stepper
              label="patch attempts"
              hint="POV-after · regressions · each hardening round"
              value={maxCorrections}
              min={correctionLimits.min}
              max={correctionLimits.max}
              onChange={setMaxCorrections}
            />
            <Stepper
              label="exploit attempts"
              hint={
                includesExploiter
                  ? "POV must reproduce before patching"
                  : "no exploiter in the selected profile(s)"
              }
              value={maxExploits}
              min={exploitLimits.min}
              max={exploitLimits.max}
              onChange={setMaxExploits}
              disabled={!includesExploiter}
            />
          </div>
        </div>

        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="font-mono text-2xs text-txt-faint">model</span>
            {models.size > 1 && <span className="font-mono text-2xs text-iris">{models.size} selected</span>}
          </div>
          <AxisGroup
            options={modelOpts.map((m) => ({ value: m.value, label: m.label }))}
            selected={models}
            onToggle={(v) => toggleAxis(setModels, v)}
          />
        </div>

        <div className="mt-4">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="font-mono text-2xs text-txt-faint">run label</span>
            <span className="font-mono text-2xs text-txt-faint">optional · groups & filters runs</span>
          </div>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={60}
            placeholder="e.g. v1, v2, new-prompt"
            className="focusable w-full rounded border border-hairline bg-ink px-2.5 py-1.5 font-mono text-xs text-txt placeholder:text-txt-faint"
          />
        </div>

        {totalRuns > 1 && (
          <div className="mt-4">
            <div className="mb-1.5 font-mono text-2xs text-txt-faint">max concurrent runs</div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setConcurrency((c) => Math.max(1, c - 1))}
                className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt"
              >
                −
              </button>
              <span className="w-8 text-center font-mono text-sm tabular-nums text-txt">{concurrency}</span>
              <button
                type="button"
                onClick={() => setConcurrency((c) => Math.min(8, c + 1))}
                className="focusable h-7 w-7 rounded-md border border-hairline font-mono text-sm text-txt-dim hover:text-txt"
              >
                +
              </button>
              <span className="ml-2 font-mono text-2xs text-txt-faint">run at a time · {totalRuns} queued</span>
            </div>
          </div>
        )}

        <div className="mt-4 space-y-1.5 border-t border-hairline pt-4">
          <Toggle
            label="Dry run"
            hint="context only · no docker · no spend"
            on={dryRun}
            onChange={setDryRun}
          />
          <Toggle
            label="Skip Docker build"
            hint="reuse cached image"
            on={skipDocker}
            onChange={setSkipDocker}
            disabled={dryRun}
          />
          <Toggle label="Re-run" hint="force even if already run" on={rerun} onChange={setRerun} />
        </div>

        <div className="mt-auto pt-5">
          {count > 0 ? (
            <div className="mb-3 rounded-md border border-hairline bg-ink2/50 px-3 py-2 font-mono text-2xs text-txt-dim">
              {count === 1 ? (
                <>
                  <span className="text-txt">{selectedTargets[0].cve_id}</span> · {selectedTargets[0].project_slug}
                </>
              ) : (
                <span className="text-txt">{count} findings selected</span>
              )}
              <div className="mt-1 space-y-0.5 text-txt-faint">
                <div className="text-iris">{[...profiles].join(" · ")}</div>
                {includesHardening && <div>up to {maxRounds} hardening rounds</div>}
                <div>
                  ≤ {maxCorrections} patch attempt{maxCorrections === 1 ? "" : "s"} per gate
                  {includesExploiter && ` · ≤ ${maxExploits} exploit attempt${maxExploits === 1 ? "" : "s"}`}
                </div>
                <div>
                  {[...models].map(modelLabel).join(" · ")} · {[...efforts].join(" · ")}
                </div>
                {label.trim() && <div className="text-txt">{label.trim()}</div>}
              </div>
              <div className="mt-1.5 border-t border-hairline/60 pt-1.5 text-txt">
                {runnable.length} finding{runnable.length === 1 ? "" : "s"} × {combos} config
                {combos === 1 ? "" : "s"} = <span className="text-iris">{totalRuns} run{totalRuns === 1 ? "" : "s"}</span>
                {totalRuns > 1 && <span className="text-txt-faint"> · {concurrency} at a time</span>}
              </div>
            </div>
          ) : (
            <div className="mb-3 font-mono text-2xs text-txt-faint">
              select one or more findings to arm the pipeline.
            </div>
          )}

          {missingSources.length > 0 && (
            <div className="mb-3 rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-2xs text-warn">
              {missingSources.length} selected finding{missingSources.length === 1 ? "" : "s"} lack local sources and
              will be skipped. <b>Clone source</b> on the finding to fetch it, or enable <b>Dry run</b> to include them.
            </div>
          )}
          {err && <div className="mb-3 rounded-md border border-fail/40 px-3 py-2 font-mono text-2xs text-fail">{err}</div>}

          <button
            type="button"
            onClick={go}
            disabled={totalRuns === 0 || busy}
            className={`focusable w-full rounded-md px-4 py-2.5 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
              dryRun
                ? "bg-elevated text-txt hover:bg-hairline-strong"
                : "bg-iris text-ink hover:bg-iris/90"
            }`}
          >
            {busy
              ? "launching…"
              : totalRuns > 1
              ? `${dryRun ? "Queue dry" : "Queue"} ${totalRuns} runs`
              : dryRun
              ? "Launch dry run"
              : "Launch run"}
          </button>
          <p className="mt-2 text-center font-mono text-2xs text-txt-faint">
            {totalRuns > 1
              ? `queued — ${concurrency} run at a time.`
              : dryRun
              ? "writes metadata + context, then stops."
              : "invokes the Docker build and Claude agents — real spend."}
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Live monitor
// ---------------------------------------------------------------------------
function StageTimeline({
  stages,
  runningKey,
  runningElapsed,
}: {
  stages: Stage[];
  runningKey: string | null;
  runningElapsed: number | null;
}) {
  return (
    <ol className="space-y-0">
      {stages.map((s) => {
        const tone = statusTone(s.status);
        const isRunning = s.key === runningKey;
        const glyph =
          s.status === "pass" ? "✓" : s.status === "fail" ? "✕" : s.status === "skipped" ? "–" : isRunning ? "▶" : "·";
        return (
          <li key={s.key} className="flex items-center gap-3 py-1.5">
            <span
              className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border font-mono text-2xs ${tone.text} ${tone.ring} ${
                isRunning ? "animate-pulse2" : ""
              }`}
            >
              {glyph}
            </span>
            <span className={`flex-1 font-mono text-xs ${isRunning ? "text-txt" : "text-txt-dim"}`}>{s.label}</span>
            {s.kind === "agent" && <span className="text-[9px] uppercase tracking-widest text-iris/50">agent</span>}
            {isRunning && runningElapsed != null && (
              <span className="font-mono text-2xs text-warn">{secs(runningElapsed)}</span>
            )}
            {!isRunning && s.detail && s.status !== "pending" && (
              <span className="max-w-[10rem] truncate font-mono text-2xs text-txt-faint">{s.detail}</span>
            )}
          </li>
        );
      })}
    </ol>
  );
}

function AgentCard({ a }: { a: AgentSummary }) {
  const ok = a.ok;
  const match = /^(exploiter|patcher)_harden_r(\d+)$/.exec(a.name);
  const label = match ? `${match[1]} · round ${match[2]}` : a.name;
  return (
    <div className={`rounded-md border px-3 py-2 ${ok ? "border-hairline" : "border-fail/40"}`}>
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs text-txt">{label}</span>
        <span className={`font-mono text-2xs ${ok ? "text-pass" : "text-fail"}`}>
          {a.status_field ?? (ok ? "ok" : a.parse_error ?? "error")}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-2xs text-txt-faint">
        {a.meta.num_turns != null && <span>{a.meta.num_turns} turns</span>}
        {a.meta.duration_ms != null && <span>{duration(a.meta.duration_ms)}</span>}
        {a.meta.cost_usd != null && <span>${a.meta.cost_usd.toFixed(3)}</span>}
        {a.meta.model && <span className="truncate">{a.meta.model}</span>}
      </div>
    </div>
  );
}

interface MonitorHint {
  cve_id?: string;
  project_slug?: string;
  run_id?: string | null;
}

function phaseInfo(phase: string): { label: string; tone: string; dot: string } {
  if (phase.startsWith("tool:")) return { label: phase.slice(5), tone: "text-info", dot: "bg-info" };
  if (phase === "thinking") return { label: "thinking", tone: "text-iris", dot: "bg-iris" };
  if (phase === "responding") return { label: "responding", tone: "text-pass", dot: "bg-pass" };
  if (phase === "done") return { label: "done", tone: "text-txt-faint", dot: "bg-txt-faint" };
  return { label: phase, tone: "text-txt-dim", dot: "bg-warn" };
}

function Caret() {
  return <span className="ml-0.5 inline-block h-3 w-[3px] animate-pulse2 bg-iris align-middle" />;
}

/** The "watch it think" pane: the in-flight agent's live reasoning / response,
 *  streamed token-by-token from stream.jsonl. This is the deepened live signal
 *  the original brief asked for — the pipeline showing its own process. */
function AgentActivityPane({ act, live }: { act: AgentActivity; live: boolean }) {
  const p = phaseInfo(act.phase);
  const beating = live && !act.done;
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-hairline px-4 py-2.5">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${p.dot} ${beating ? "animate-pulse2" : ""}`} />
          <span className="font-mono text-2xs uppercase tracking-wide text-txt-dim">{act.agent}</span>
          <span className={`font-mono text-2xs ${p.tone}`}>· {p.label}</span>
        </div>
        <div className="flex items-center gap-3 font-mono text-2xs text-txt-faint">
          <span>{act.turns} turns</span>
          {act.tool_count > 0 && <span>{act.tool_count} tools</span>}
          {act.output_tokens != null && <span>{act.output_tokens} tok</span>}
        </div>
      </div>
      <div className="space-y-3 p-4">
        {act.thinking_tail && (
          <div>
            <div className="eyebrow mb-1">thinking</div>
            <p className="max-h-40 overflow-y-auto whitespace-pre-wrap font-mono text-2xs leading-relaxed text-txt-faint">
              …{act.thinking_tail}
              {beating && act.phase === "thinking" && <Caret />}
            </p>
          </div>
        )}
        {act.text_tail && (
          <div>
            <div className="eyebrow mb-1">response</div>
            <p className="max-h-40 overflow-y-auto whitespace-pre-wrap font-mono text-2xs leading-relaxed text-txt-dim">
              …{act.text_tail}
              {beating && act.phase === "responding" && <Caret />}
            </p>
          </div>
        )}
        {act.recent_tools.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-2xs text-txt-faint">tools</span>
            {act.recent_tools.map((t, i) => (
              <span key={i} className="chip text-info">
                {t}
              </span>
            ))}
          </div>
        )}
        {!act.thinking_tail && !act.text_tail && (
          <p className="font-mono text-2xs text-txt-faint">
            {act.agent} is starting…{beating && <Caret />}
          </p>
        )}
      </div>
    </div>
  );
}

function LiveMonitor({
  launchId,
  hint,
  onReset,
}: {
  launchId: string;
  hint: MonitorHint;
  onReset: () => void;
}) {
  const [snap, setSnap] = useState<LiveSnapshot | null>(null);
  const [activity, setActivity] = useState<AgentActivity | null>(null);
  const [log, setLog] = useState("");
  const [live, setLive] = useState(true);
  const [connError, setConnError] = useState<string | null>(null);
  const snapAtRef = useRef<number>(Date.now());
  const gotHelloRef = useRef(false);
  const doneRef = useRef(false);

  useClock(live); // re-render each second for the elapsed timers

  useEffect(() => {
    setSnap(null);
    setActivity(null);
    setLog("");
    setLive(true);
    setConnError(null);
    doneRef.current = false;
    gotHelloRef.current = false;

    const es = new EventSource(api.liveStreamUrl(launchId));

    es.addEventListener("hello", () => {
      gotHelloRef.current = true;
    });
    es.addEventListener("log", (ev) => {
      const { text } = JSON.parse((ev as MessageEvent).data);
      setLog((prev) => prev + text);
    });
    es.addEventListener("state", (ev) => {
      const s = JSON.parse((ev as MessageEvent).data) as LiveSnapshot;
      setSnap(s);
      setActivity(s.agent_activity ?? null); // clears between agents / at terminal
      snapAtRef.current = Date.now();
    });
    es.addEventListener("agent", (ev) => {
      // High-frequency token stream for the in-flight agent (own frame).
      setActivity(JSON.parse((ev as MessageEvent).data));
    });
    es.addEventListener("done", (ev) => {
      setSnap(JSON.parse((ev as MessageEvent).data));
      setActivity(null);
      snapAtRef.current = Date.now();
      doneRef.current = true;
      setLive(false);
      es.close();
    });
    es.onerror = () => {
      if (doneRef.current) return;
      // Closed before we ever connected → launch no longer live (server restart).
      if (!gotHelloRef.current) {
        setConnError("This launch is no longer being tracked (the server may have restarted).");
        setLive(false);
        es.close();
      }
    };

    return () => es.close();
  }, [launchId]);

  async function stop() {
    try {
      await api.liveStop(launchId);
    } catch {
      /* already gone */
    }
  }

  const status = snap?.status ?? "running";
  const alive = live && (snap?.alive ?? true);
  const startedMs = snap ? new Date(snap.started_at).getTime() : snapAtRef.current;
  const totalElapsed = (Date.now() - startedMs) / 1000;
  const runningElapsed =
    snap?.running_stage_elapsed != null
      ? snap.running_stage_elapsed + (alive ? (Date.now() - snapAtRef.current) / 1000 : 0)
      : null;
  const runId = snap?.run_id ?? hint.run_id ?? null;
  const cve = snap?.options.cve_id ?? hint.cve_id;
  const project = snap?.options.project_slug ?? hint.project_slug;
  // Work handed back to an agent so far: the rail can look stalled during a
  // retry (the stage's first-pass agent already "finished"), so surface it.
  const retries = snap?.retries ?? null;
  const retryCount =
    (retries?.patch_corrections.length ?? 0) +
    (retries?.exploit_retries.length ?? 0) +
    (retries?.api_error_retries?.reduce((n, r) => n + r.attempts, 0) ?? 0);

  return (
    <div className="space-y-5">
      {/* header */}
      <div className="panel flex flex-wrap items-center justify-between gap-4 p-5">
        <div className="min-w-0">
          <div className="flex items-center gap-3">
            <h2 className="font-display text-xl font-bold text-txt">{cve ?? "run"}</h2>
            <StatusPill status={status} />
            {alive && <span className="chip animate-pulse2 text-warn">live</span>}
            {snap?.options.dry_run && <span className="chip">dry run</span>}
            {/* Keyed off the rail, not the profile name: any arm whose stage list
                contains the hardening loop runs rounds, not just "hardening". */}
            {snap?.stages.some((s) => s.key === "harden") && (
              <span className="chip text-iris">≤ {snap.options.max_rounds ?? 4} rounds</span>
            )}
            {retryCount > 0 && (
              <span className="chip text-warn">
                {retryCount} retr{retryCount === 1 ? "y" : "ies"}
              </span>
            )}
            {snap?.options.label && <span className="chip text-txt-dim">{snap.options.label}</span>}
          </div>
          {project && <div className="mt-1 font-mono text-2xs text-txt-dim">{project}</div>}
        </div>
        <div className="flex items-center gap-5">
          <div className="text-right">
            <div className="eyebrow">elapsed</div>
            <div className="font-mono text-lg tabular-nums text-txt">{secs(totalElapsed)}</div>
          </div>
          {alive ? (
            <button
              type="button"
              onClick={stop}
              className="focusable rounded-md border border-fail/40 px-3 py-1.5 font-mono text-2xs text-fail hover:bg-fail/10"
            >
              stop
            </button>
          ) : (
            <button
              type="button"
              onClick={onReset}
              className="focusable rounded-md border border-hairline px-3 py-1.5 font-mono text-2xs text-txt-dim hover:border-iris/50 hover:text-txt"
            >
              new run
            </button>
          )}
        </div>
      </div>

      {connError && (
        <div className="panel border-warn/40 p-4 text-xs text-warn">
          {connError}
          {runId && (
            <>
              {" "}
              <Link to={`/runs/${runId}`} className="text-iris hover:underline">
                view the run →
              </Link>
            </>
          )}
        </div>
      )}

      {/* rail */}
      {snap && snap.stages.length > 0 && (
        <div className="panel px-5 py-4">
          <div className="mb-3 flex items-center justify-between">
            <span className="eyebrow">pipeline</span>
            {snap.running_stage_label && alive && (
              <span className="font-mono text-2xs text-warn">
                {snap.running_stage_label} · {runningElapsed != null ? secs(runningElapsed) : "…"}
              </span>
            )}
          </div>
          <StageRail stages={snap.stages} activeKey={snap.running_stage ?? undefined} />
        </div>
      )}

      <div className="grid gap-5 lg:grid-cols-[1fr_1.2fr]">
        {/* timeline + agents */}
        <div className="space-y-5">
          {snap && (
            <div className="panel p-5">
              <div className="eyebrow mb-2">stages</div>
              <StageTimeline
                stages={snap.stages}
                runningKey={snap.running_stage}
                runningElapsed={runningElapsed}
              />
            </div>
          )}
          {snap && snap.agents.length > 0 && (
            <div className="panel p-5">
              <div className="eyebrow mb-3">agents</div>
              <div className="space-y-2">
                {snap.agents.map((a) => (
                  <AgentCard key={a.name} a={a} />
                ))}
              </div>
            </div>
          )}
          {snap?.hardening && <HardeningPanel summary={snap.hardening} compact />}
          {retries && <RetriesPanel summary={retries} />}
        </div>

        {/* console */}
        <div className="space-y-5">
          {activity && !snap?.terminal && <AgentActivityPane act={activity} live={alive} />}
          <LiveConsole text={log} live={alive} />
          {snap?.terminal && (
            <div className="panel p-5">
              <div className="flex items-center gap-2">
                <StatusPill status={status} />
                <span className="text-sm text-txt-dim">{snap.reason || "run complete."}</span>
              </div>
              {runId && (
                <Link
                  to={`/runs/${runId}`}
                  className="focusable mt-3 inline-flex items-center gap-1 rounded-md bg-elevated px-3 py-1.5 text-xs text-iris hover:bg-hairline-strong"
                >
                  View full run →
                </Link>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent launches
// ---------------------------------------------------------------------------
function launchStateTone(state: string): string {
  if (state === "running") return "text-warn";
  if (state === "queued") return "text-info";
  if (state === "stopped" || state === "error") return "text-fail";
  if (state === "interrupted") return "text-warn"; // cut off mid-run (e.g. a crash)
  if (state === "done") return "text-txt-faint";
  return "text-txt-dim";
}

/** The launch queue / history — polls so batch progress (queued → running →
 *  done) updates live, and lets you stop a queued or running launch. */
function RecentLaunches({ onOpen, refreshKey }: { onOpen: (r: LaunchRecord) => void; refreshKey: number }) {
  const [launches, setLaunches] = useState<LaunchRecord[]>([]);
  const [sched, setSched] = useState<SchedulerStatus | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [ctrlBusy, setCtrlBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const [data, s] = await Promise.all([api.liveLaunches(), api.scheduler().catch(() => null)]);
        if (!alive) return;
        setLaunches(data);
        if (s) setSched(s);
      } catch {
        /* keep last snapshot on a transient error */
      }
    };
    load();
    const t = setInterval(load, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [refreshKey]);

  if (launches.length === 0) return null;

  async function stop(id: string) {
    setBusy(id);
    try {
      await api.liveStop(id);
      setLaunches((prev) => prev.map((r) => (r.launch_id === id ? { ...r, state: "stopped", is_running: false } : r)));
    } catch {
      /* ignore */
    } finally {
      setBusy(null);
    }
  }

  async function runControl(fn: () => Promise<unknown>) {
    setCtrlBusy(true);
    try {
      await fn();
      const [data, s] = await Promise.all([api.liveLaunches(), api.scheduler().catch(() => null)]);
      setLaunches(data);
      if (s) setSched(s);
    } catch {
      /* ignore — next poll reconciles */
    } finally {
      setCtrlBusy(false);
    }
  }

  const running = sched?.running ?? launches.filter((r) => (r.state ?? (r.is_running ? "running" : "done")) === "running").length;
  const queued = sched?.queued ?? launches.filter((r) => r.state === "queued").length;
  const paused = sched?.paused ?? false;
  const hasActive = running > 0 || queued > 0;

  return (
    <div className="mt-10">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <span className="eyebrow">launch queue</span>
        <div className="flex items-center gap-3">
          <span className="font-mono text-2xs text-txt-faint">
            {running} running · {queued} queued
            {paused && <span className="text-warn"> · paused</span>} · {launches.length} total
          </span>
          {queued > 0 &&
            (paused ? (
              <button
                type="button"
                onClick={() => runControl(api.resumeQueue)}
                disabled={ctrlBusy}
                className="focusable rounded-md border border-iris/50 px-2 py-1 font-mono text-2xs text-iris hover:bg-iris/10 disabled:opacity-40"
              >
                resume queue
              </button>
            ) : (
              <button
                type="button"
                onClick={() => runControl(api.pauseQueue)}
                disabled={ctrlBusy}
                className="focusable rounded-md border border-hairline px-2 py-1 font-mono text-2xs text-txt-dim hover:text-txt disabled:opacity-40"
              >
                pause queue
              </button>
            ))}
          {hasActive && (
            <button
              type="button"
              onClick={() => runControl(api.stopAll)}
              disabled={ctrlBusy}
              className="focusable rounded-md border border-fail/40 px-2 py-1 font-mono text-2xs text-fail hover:bg-fail/10 disabled:opacity-40"
            >
              {ctrlBusy ? "…" : "stop all"}
            </button>
          )}
        </div>
      </div>

      {paused && queued > 0 && (
        <div className="mb-3 rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-2xs text-warn">
          The queue is paused — {queued} run{queued === 1 ? "" : "s"} are held and won’t start on their own. This is the
          safe default after a backend restart. <b>Resume queue</b> to continue, or <b>stop all</b> to cancel them.
        </div>
      )}
      <div className="panel max-h-[32rem] divide-y divide-hairline/60 overflow-y-auto">
        {launches.map((r) => {
          const st = r.state ?? (r.is_running ? "running" : "done");
          const active = st === "running" || st === "queued";
          return (
            <div key={r.launch_id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-elevated/50">
              <button
                type="button"
                onClick={() => onOpen(r)}
                className="focusable flex min-w-0 flex-1 items-center gap-2.5 text-left"
              >
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${active ? "animate-pulse2 bg-warn" : "bg-txt-faint/40"}`} />
                <span className="font-mono text-xs text-txt">{r.cve_id ?? r.alert_file}</span>
                <span className={`chip ${launchStateTone(st)}`}>{st}</span>
                {r.options?.dry_run && <span className="chip">dry</span>}
                {r.options?.profile && <span className="chip">{r.options.profile}</span>}
                {r.options?.profile === "hardening" && (
                  <span className="chip text-iris">≤ {r.options.max_rounds ?? 4} rounds</span>
                )}
                {r.options?.label && <span className="chip text-txt-dim">{r.options.label}</span>}
                <span className="ml-auto truncate font-mono text-2xs text-txt-faint">{r.run_id ?? r.launch_id}</span>
              </button>
              {active && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    stop(r.launch_id);
                  }}
                  disabled={busy === r.launch_id}
                  className="focusable shrink-0 rounded-md border border-fail/40 px-2 py-1 font-mono text-2xs text-fail hover:bg-fail/10 disabled:opacity-40"
                >
                  {busy === r.launch_id ? "…" : "stop"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export function Live() {
  const [active, setActive] = useState<{ launchId: string; hint: MonitorHint } | null>(null);
  const [refresh, setRefresh] = useState(0);

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-8">
        <div className="eyebrow">live pipeline · exploit · patch · verify</div>
        <h1 className="mt-2 font-display text-4xl font-bold tracking-tight text-txt">Live run</h1>
        <p className="mt-2 max-w-2xl text-sm text-txt-dim">
          Arm the remediation pipeline against a finding and watch each stage light up as it happens — the worktree,
          the Docker build, and the exploiter, patcher and verifier agents, streamed from the run directory in real
          time.
        </p>
      </header>

      {active ? (
        <LiveMonitor
          launchId={active.launchId}
          hint={active.hint}
          onReset={() => setActive(null)}
        />
      ) : (
        <>
          <LaunchPanel
            onLaunched={(launchId, target) =>
              setActive({ launchId, hint: { cve_id: target.cve_id, project_slug: target.project_slug } })
            }
            onBatched={() => setRefresh((n) => n + 1)}
          />
          <RecentLaunches
            refreshKey={refresh}
            onOpen={(r) =>
              setActive({
                launchId: r.launch_id,
                hint: { cve_id: r.cve_id ?? undefined, project_slug: r.project_slug ?? undefined, run_id: r.run_id },
              })
            }
          />
        </>
      )}
    </div>
  );
}
