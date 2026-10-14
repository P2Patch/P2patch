export function cost(n: number | null | undefined): string {
  if (n == null) return "—";
  return `$${n.toFixed(2)}`;
}

export function tokens(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return `${n}`;
}

export function duration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(0)}s`;
  const m = Math.floor(s / 60);
  const r = Math.round(s % 60);
  return `${m}m ${r}s`;
}

export function relTime(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const now = Date.now();
  const diff = Math.max(0, now - then);
  const day = 86_400_000;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < day) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 7 * day) return `${Math.floor(diff / day)}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function absTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function cweShort(id: string | null | undefined): string {
  if (!id) return "—";
  return id.replace(/^CWE-0*/i, "CWE-");
}

// Status -> tailwind text/bg/border token trio.
export function statusTone(status: string): { text: string; dot: string; ring: string } {
  switch (status) {
    case "accepted":
    case "pass":
      return { text: "text-pass", dot: "bg-pass", ring: "border-pass/40" };
    case "rejected":
    case "fail":
      return { text: "text-fail", dot: "bg-fail", ring: "border-fail/40" };
    case "pending":
    case "running":
      return { text: "text-warn", dot: "bg-warn", ring: "border-warn/40" };
    case "skipped":
      return { text: "text-txt-faint", dot: "bg-txt-faint", ring: "border-hairline" };
    default:
      return { text: "text-txt-dim", dot: "bg-txt-dim", ring: "border-hairline" };
  }
}
