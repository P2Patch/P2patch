import { statusTone } from "../lib/format";

export function StatusPill({ status, size = "md" }: { status: string; size?: "sm" | "md" }) {
  const tone = statusTone(status);
  const pad = size === "sm" ? "px-2 py-0.5 text-2xs" : "px-2.5 py-1 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border bg-elevated font-mono uppercase tracking-wide ${tone.text} ${tone.ring} ${pad}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} />
      {status}
    </span>
  );
}
