import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { PUBLISHED, api } from "../api";
import { useAsync } from "../lib/useAsync";
import { cost, duration, statusTone, tokens } from "../lib/format";
import type { LoopRepairResult } from "../types";
import { StatusPill } from "../components/StatusPill";
import { DiffViewer } from "../components/DiffViewer";
import { LoopRepairFixpovReplayControl } from "../components/LoopRepairFixpovReplayControl";
import { LoopRepairRespovReplayControl } from "../components/LoopRepairRespovReplayControl";
import { FixPovEvalPanel } from "../components/FixPovEvalPanel";
import { ResidualEvalPanel } from "../components/ResidualEvalPanel";

type SubTab = "description" | "patch" | "reference" | "pov" | "povreplay" | "logs" | "usage";

export function LoopRepairDetail() {
  const { key = "" } = useParams();
  const [refreshKey, setRefreshKey] = useState(0);
  const { data, error, loading } = useAsync<LoopRepairResult>(() => api.loopRepairResult(key), [key, refreshKey]);
  const [tab, setTab] = useState<SubTab>("description");
  const onReplayComplete = () => setRefreshKey((k) => k + 1);

  if (loading)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10 font-mono text-xs text-txt-faint animate-pulse2">
        loading result…
      </div>
    );
  if (error || !data)
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <Link to="/other-projects" className="text-iris hover:underline">
          ← other projects
        </Link>
        <div className="panel mt-4 border-fail/40 p-4 font-mono text-xs text-fail">{error ?? "not found"}</div>
      </div>
    );

  const mapped = data.status === "patched" ? "pass" : "fail";
  const tone = statusTone(mapped);

  const tabs: { key: SubTab; label: string; badge?: string }[] = [
    { key: "description", label: "Description" },
    { key: "patch", label: "Patch" },
    { key: "reference", label: "Reference fix", badge: data.has_reference_fix ? undefined : "none" },
    { key: "pov", label: "PoV / crash input" },
    { key: "povreplay", label: "PoV replay" },
    { key: "logs", label: "Logs", badge: `${data.logs_available.length}` },
    { key: "usage", label: "Usage & cost" },
  ];

  return (
    <div className="mx-auto max-w-6xl px-6 py-8">
      <Link to="/other-projects" className="focusable font-mono text-2xs text-txt-faint hover:text-iris">
        ← other projects
      </Link>

      <header className="mt-3 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="font-display text-2xl font-bold text-txt">{data.cve}</h1>
            <StatusPill status={data.status} />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="chip">{data.project}</span>
            {data.vul_id !== data.cve && (
              <span className="chip text-txt-dim" title="scenario id on disk">
                {data.vul_id}
              </span>
            )}
            {data.verification?.model && <span className="chip">{data.verification.model}</span>}
          </div>
        </div>
        <div className="flex gap-5 font-mono text-2xs text-txt-dim">
          <Metric label="cost" value={cost(data.cost_usd)} />
          <Metric label="tokens" value={tokens(data.total_tokens)} />
          <Metric label="time" value={data.elapsed_seconds != null ? duration(data.elapsed_seconds * 1000) : "—"} />
        </div>
      </header>

      <div className={`mt-4 rounded-md border bg-panel px-4 py-2.5 text-sm ${tone.ring}`}>
        <span className={`font-mono text-2xs uppercase tracking-wide ${tone.text}`}>{data.status}</span>
        <span className="ml-3 text-txt-dim">{data.message || "no notes recorded for this CVE"}</span>
      </div>

      <nav className="mt-6 flex gap-1 border-b border-hairline">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={`focusable -mb-px flex items-center gap-2 border-b-2 px-4 py-2.5 text-sm transition-colors ${
              tab === t.key ? "border-iris text-txt" : "border-transparent text-txt-dim hover:text-txt"
            }`}
          >
            {t.label}
            {t.badge && <span className="chip">{t.badge}</span>}
          </button>
        ))}
      </nav>

      <div className="mt-5">
        {tab === "description" && <DescriptionTab data={data} />}
        {tab === "patch" && (
          <DiffTab loopKey={key} kind="patch" available={data.has_patch} emptyLabel="no patch was generated" />
        )}
        {tab === "reference" && (
          <DiffTab
            loopKey={key}
            kind="reference"
            available={data.has_reference_fix}
            emptyLabel="this scenario ships no reference fix"
          />
        )}
        {tab === "pov" && <PovTab loopKey={key} data={data} />}
        {tab === "povreplay" && (
          <PovReplayTab loopKey={key} data={data} onReplayComplete={onReplayComplete} />
        )}
        {tab === "logs" && <LogsTab loopKey={key} available={data.logs_available} />}
        {tab === "usage" && <UsageTab data={data} />}
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-right">
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 text-sm text-txt">{value}</div>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="panel p-6 text-center font-mono text-2xs text-txt-faint">{children}</div>;
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 break-words font-mono text-xs text-txt">{value ?? "—"}</div>
    </div>
  );
}

function DescriptionTab({ data }: { data: LoopRepairResult }) {
  const v = data.verification;
  const build = data.bug?.build as Record<string, unknown> | undefined;
  return (
    <div className="space-y-6">
      <section className="panel space-y-4 p-5">
        <div className="eyebrow">what happened</div>
        <p className="text-sm text-txt-dim">{data.message || "No notes recorded — this CVE resolved without needing any diagnosis."}</p>
        {v?.manual_override_note && (
          <div className="rounded-md border border-iris/40 bg-iris/5 p-3 text-xs text-txt-dim">
            <div className="mb-1 font-mono text-2xs uppercase tracking-wide text-iris">manual correction</div>
            {v.manual_override_note}
          </div>
        )}
      </section>

      <section className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        <div className="panel space-y-3 p-5">
          <div className="eyebrow">verification</div>
          <Field label="patch found" value={data.patch_found ? "yes" : "no"} />
          <Field label="patches evaluated" value={data.num_patches_evaluated ?? "—"} />
          <Field label="repairs found" value={data.num_repairs_found ?? "—"} />
          <Field label="patch compiles" value={v?.patch_compiles == null ? "—" : v.patch_compiles ? "yes" : "no"} />
          {v?.tests && (
            <Field
              label="tests"
              value={`${v.tests.passed ?? 0}/${v.tests.executed ?? 0} passed${
                v.tests.failed ? ` (${v.tests.failed} failed)` : ""
              }`}
            />
          )}
          {v?.patch_location && <Field label="patch location" value={v.patch_location} />}
        </div>
        <div className="panel space-y-3 p-5">
          <div className="eyebrow">scenario</div>
          <Field label="binary" value={data.bug?.binary} />
          <Field label="source directory" value={data.bug?.["source-directory"]} />
          {build && (
            <Field
              label="build command"
              value={typeof build.commands === "object" && build.commands ? (build.commands as Record<string, unknown>).build as string : undefined}
            />
          )}
        </div>
      </section>
    </div>
  );
}

function DiffTab({
  loopKey,
  kind,
  available,
  emptyLabel,
}: {
  loopKey: string;
  kind: "patch" | "reference";
  available: boolean;
  emptyLabel: string;
}) {
  const { data, error, loading } = useAsync<string>(
    () => (available ? api.loopRepairDiff(loopKey, kind) : Promise.resolve("")),
    [loopKey, kind, available],
  );
  if (!available) return <Empty>{emptyLabel}</Empty>;
  return (
    <div className="panel overflow-hidden py-2">
      {loading && <div className="p-4 font-mono text-2xs text-txt-faint animate-pulse2">loading diff…</div>}
      {error && <div className="p-4 font-mono text-2xs text-fail">{error}</div>}
      {data != null && !loading && <DiffViewer diff={data} emptyLabel={emptyLabel} />}
    </div>
  );
}

function PovTab({ loopKey, data }: { loopKey: string; data: LoopRepairResult }) {
  const crash = data.bug?.crash;
  return (
    <div className="space-y-6">
      <section className="panel space-y-3 p-5">
        <div className="eyebrow">crash definition</div>
        {!crash && <div className="font-mono text-2xs text-txt-faint">no crash metadata recorded</div>}
        {crash && (
          <>
            <Field label="command" value={crash.command} />
            <Field label="input" value={crash.input} />
            <Field label="expected signal" value={crash.bad_output} />
            <Field label="expected exit code" value={crash["expected-exit-code"]} />
          </>
        )}
      </section>

      <section className="space-y-3">
        <div className="eyebrow">crash-triggering input file{data.pov_input_files.length === 1 ? "" : "s"}</div>
        {data.pov_input_files.length === 0 && <Empty>no PoV input file was captured for this CVE</Empty>}
        {data.pov_input_files.length > 0 && (
          <div className="panel divide-y divide-hairline">
            {data.pov_input_files.map((f) => (
              <div key={f} className="flex items-center justify-between px-4 py-2.5">
                <span className="font-mono text-xs text-txt">{f}</span>
                {!PUBLISHED && (
                  <a
                    href={api.loopRepairPovInputUrl(loopKey, f)}
                    download
                    className="focusable rounded-md border border-iris/50 px-2.5 py-1 font-mono text-2xs text-iris hover:bg-iris/10"
                  >
                    download
                  </a>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function PovReplayTab({
  loopKey,
  data,
  onReplayComplete,
}: {
  loopKey: string;
  data: LoopRepairResult;
  onReplayComplete: () => void;
}) {
  return (
    <div className="space-y-8">
      <div className="space-y-3">
        <LoopRepairFixpovReplayControl cveKey={loopKey} onComplete={onReplayComplete} />
        {data.fix_pov_eval && <FixPovEvalPanel gte={data.fix_pov_eval} />}
      </div>
      <div className="space-y-3">
        <LoopRepairRespovReplayControl cveKey={loopKey} onComplete={onReplayComplete} />
        {data.residual_eval && <ResidualEvalPanel res={data.residual_eval} />}
      </div>
    </div>
  );
}

function LogFile({ loopKey, name }: { loopKey: string; name: string }) {
  const [open, setOpen] = useState(false);
  const [log, setLog] = useState<string | null>(null);

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && log == null) api.loopRepairLog(loopKey, name).then(setLog).catch((e) => setLog(String(e)));
  }

  return (
    <div className="panel overflow-hidden">
      <button
        type="button"
        onClick={toggle}
        className="focusable flex w-full items-center gap-3 px-4 py-2.5 text-left card-hover"
      >
        <span className="font-mono text-xs text-txt">{name}</span>
        <span className={`ml-auto transition-transform font-mono text-2xs text-txt-faint ${open ? "rotate-90" : ""}`}>
          ›
        </span>
      </button>
      {open && (
        <div className="max-h-96 overflow-auto border-t border-hairline bg-ink2/40">
          <pre className="whitespace-pre-wrap break-words p-3 font-mono text-2xs leading-relaxed text-txt-dim">
            {log ?? "loading…"}
          </pre>
        </div>
      )}
    </div>
  );
}

function LogsTab({ loopKey, available }: { loopKey: string; available: string[] }) {
  if (available.length === 0) return <Empty>no logs captured for this CVE</Empty>;
  return (
    <div className="space-y-2">
      {available.map((name) => (
        <LogFile key={name} loopKey={loopKey} name={name} />
      ))}
    </div>
  );
}

function UsageTab({ data }: { data: LoopRepairResult }) {
  return (
    <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
      <div className="panel space-y-3 p-5">
        <div className="eyebrow">tokens</div>
        <Field label="prompt" value={data.prompt_tokens ?? "—"} />
        <Field label="completion" value={data.completion_tokens ?? "—"} />
        <Field label="total" value={data.total_tokens ?? "—"} />
      </div>
      <div className="panel space-y-3 p-5">
        <div className="eyebrow">cost &amp; time</div>
        <Field label="cost" value={cost(data.cost_usd)} />
        <Field label="elapsed" value={data.elapsed_seconds != null ? duration(data.elapsed_seconds * 1000) : "—"} />
      </div>
      <div className="panel space-y-3 p-5">
        <div className="eyebrow">search</div>
        <Field label="patches evaluated" value={data.num_patches_evaluated ?? "—"} />
        <Field label="repairs found" value={data.num_repairs_found ?? "—"} />
      </div>
    </div>
  );
}
