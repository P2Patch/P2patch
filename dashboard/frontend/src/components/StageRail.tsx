import type { Stage } from "../types";
import { statusTone } from "../lib/format";

// The signature element: the pipeline rendered as a wired signal chain.
// exploit -> pov -> patch -> pov -> regression -> verify, each a lamp whose
// color is the stage's real outcome. Agents (the LLM stages) get an iris ring.

function boundaryColor(a: Stage | undefined, b: Stage | undefined): string {
  if (!a || !b) return "bg-hairline";
  if (b.status === "fail") return "bg-fail/60";
  if (a.status === "pass" && b.status === "pass") return "bg-pass/50";
  return "bg-hairline";
}

function Lamp({ stage, active }: { stage: Stage; active: boolean }) {
  const tone = statusTone(stage.status);
  const isAgent = stage.kind === "agent";
  const running = stage.status === "running";
  const pulsing = running || stage.status === "pending";
  const ringed = active || running; // the in-flight stage always wears the iris ring
  const shell = isAgent ? "h-6 w-6" : "h-5 w-5";
  const core = isAgent ? "h-3 w-3" : "h-2.5 w-2.5";

  if (stage.status === "skipped") {
    return (
      <span
        className={`relative z-10 flex items-center justify-center rounded-full border border-dashed border-hairline-strong bg-ink ${shell}`}
      >
        <span className={`rounded-full bg-txt-faint/30 ${core}`} />
      </span>
    );
  }
  return (
    <span
      className={`relative z-10 flex items-center justify-center rounded-full bg-ink shadow-lamp ${shell} ${
        ringed ? "ring-2 ring-iris ring-offset-2 ring-offset-ink" : ""
      }`}
    >
      {running && <span className="absolute inset-0 animate-ping rounded-full bg-iris/20" />}
      {isAgent && <span className="absolute inset-0 rounded-full border border-iris/40" />}
      <span className={`rounded-full ${tone.dot} ${core} ${pulsing ? "animate-pulse2" : ""}`} />
    </span>
  );
}

interface Props {
  stages: Stage[];
  activeKey?: string;
  onSelect?: (key: string) => void;
}

export function StageRail({ stages, activeKey, onSelect }: Props) {
  return (
    <div className="flex items-start overflow-x-auto pb-1">
      {stages.map((stage, i) => {
        const first = i === 0;
        const last = i === stages.length - 1;
        const incoming = boundaryColor(stages[i - 1], stage);
        const outgoing = boundaryColor(stage, stages[i + 1]);
        const active = activeKey === stage.key;
        return (
          <button
            key={stage.key}
            type="button"
            onClick={() => onSelect?.(stage.key)}
            title={stage.detail ?? undefined}
            className="focusable group flex min-w-[76px] flex-1 flex-col items-center rounded-md py-1"
          >
            <div className="relative flex h-8 w-full items-center justify-center">
              {!first && <span className={`absolute left-0 top-1/2 h-px w-1/2 -translate-y-1/2 ${incoming}`} />}
              {!last && <span className={`absolute right-0 top-1/2 h-px w-1/2 -translate-y-1/2 ${outgoing}`} />}
              <Lamp stage={stage} active={active} />
            </div>
            <div
              className={`mt-1 px-1 text-center font-mono text-2xs leading-tight transition-colors ${
                active ? "text-txt" : "text-txt-dim group-hover:text-txt"
              }`}
            >
              {stage.label}
            </div>
            {stage.kind === "agent" && (
              <div className="mt-0.5 text-[9px] uppercase tracking-widest text-iris/60">agent</div>
            )}
          </button>
        );
      })}
    </div>
  );
}
