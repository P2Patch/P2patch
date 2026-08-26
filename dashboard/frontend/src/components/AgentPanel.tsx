import { useState } from "react";
import type { AgentIO, AgentSummary, AgentTokens } from "../types";
import { api } from "../api";
import { cost, duration, tokens } from "../lib/format";
import { JsonView } from "./JsonView";

type Tab = "output" | "input" | "meta" | "stderr";

function agentLabel(name: string): string {
  const match = /^(exploiter|patcher)_harden_r(\d+)$/.exec(name);
  return match ? `${match[1]} · hardening round ${match[2]}` : name;
}

function MetaGrid({ agent }: { agent: AgentSummary }) {
  const m = agent.meta;
  const t: Partial<AgentTokens> = m.tokens ?? {};
  const costLabel = m.cost_source === "openrouter_generation_api" ? "cost · billed" : "cost";
  const cells: [string, string][] = [
    ["model", m.model ?? "—"],
    ["turns", `${m.num_turns ?? "—"}`],
    ["duration", duration(m.duration_ms)],
    [costLabel, cost(m.cost_usd)],
    ["stop reason", m.stop_reason ?? "—"],
    ["exit code", `${agent.exit_code ?? "—"}`],
    ["tokens in", tokens(t.input)],
    ["tokens out", tokens(t.output)],
    ["cache read", tokens(t.cache_read)],
  ];
  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-hairline bg-hairline sm:grid-cols-3">
      {cells.map(([k, v]) => (
        <div key={k} className="bg-panel px-3 py-2">
          <div className="eyebrow">{k}</div>
          <div className="mt-0.5 truncate font-mono text-xs text-txt">{v}</div>
        </div>
      ))}
    </div>
  );
}

export function AgentPanel({ runId, agent }: { runId: string; agent: AgentSummary }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<Tab>("output");
  const [io, setIo] = useState<AgentIO | null>(null);
  const [ioErr, setIoErr] = useState<string | null>(null);

  function expand() {
    const next = !open;
    setOpen(next);
    if (next && !io) {
      api
        .agent(runId, agent.name)
        .then(setIo)
        .catch((e) => setIoErr(String(e.message ?? e)));
    }
  }

  const tone = agent.ok ? "border-pass/30" : "border-fail/30";
  const tabs: Tab[] = ["output", "input", "meta", "stderr"];

  return (
    <div className={`panel overflow-hidden ${open ? tone : ""}`}>
      <button
        type="button"
        onClick={expand}
        className="focusable flex w-full items-center gap-3 px-4 py-3 text-left card-hover"
      >
        <span className={`h-2 w-2 shrink-0 rounded-full ${agent.ok ? "bg-pass" : "bg-fail"}`} />
        <span className="font-display text-sm font-semibold capitalize text-txt">{agentLabel(agent.name)}</span>
        {agent.status_field && (
          <span className="chip">{agent.status_field}</span>
        )}
        <span className="ml-auto flex items-center gap-3 font-mono text-2xs text-txt-dim">
          <span>{agent.meta.num_turns ?? "—"} turns</span>
          <span>{duration(agent.meta.duration_ms)}</span>
          <span className="text-txt">{cost(agent.meta.cost_usd)}</span>
          <span className={`transition-transform ${open ? "rotate-90" : ""}`}>›</span>
        </span>
      </button>

      {open && (
        <div className="border-t border-hairline">
          <div className="flex gap-1 border-b border-hairline bg-ink2 px-2">
            {tabs.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`focusable -mb-px border-b-2 px-3 py-2 font-mono text-2xs uppercase tracking-wide transition-colors ${
                  tab === t
                    ? "border-iris text-txt"
                    : "border-transparent text-txt-faint hover:text-txt-dim"
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          <div className="max-h-[28rem] overflow-auto bg-ink2/40">
            {tab === "output" && <JsonView value={agent.parsed_output} />}
            {tab === "meta" && (
              <div className="p-4">
                <MetaGrid agent={agent} />
              </div>
            )}
            {tab === "input" && (
              <IoText text={io?.input_md} err={ioErr} loaded={!!io} empty="no input recorded" />
            )}
            {tab === "stderr" && (
              <IoText text={io?.raw_stderr} err={ioErr} loaded={!!io} empty="stderr was empty" />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function IoText({
  text,
  err,
  loaded,
  empty,
}: {
  text: string | null | undefined;
  err: string | null;
  loaded: boolean;
  empty: string;
}) {
  if (err) return <div className="p-4 font-mono text-2xs text-fail">{err}</div>;
  if (!loaded) return <div className="p-4 font-mono text-2xs text-txt-faint animate-pulse2">loading…</div>;
  if (!text || !text.trim()) return <div className="p-4 font-mono text-2xs text-txt-faint">{empty}</div>;
  return <pre className="whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed text-txt-dim">{text}</pre>;
}
