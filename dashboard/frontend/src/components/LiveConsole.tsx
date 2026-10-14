import { useEffect, useRef } from "react";

/** A terminal-style pane that streams the orchestrator's stdout, auto-scrolling
 *  to the tail unless the operator has scrolled up to read history. */
export function LiveConsole({ text, live }: { text: string; live: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);

  useEffect(() => {
    const el = ref.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [text]);

  function onScroll() {
    const el = ref.current;
    if (!el) return;
    pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
  }

  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-hairline bg-ink2 px-3 py-1.5">
        <span className="eyebrow">orchestrator</span>
        <span className="flex items-center gap-1.5 font-mono text-2xs text-txt-faint">
          <span className={`h-1.5 w-1.5 rounded-full ${live ? "animate-pulse2 bg-warn" : "bg-txt-faint"}`} />
          {live ? "streaming" : "ended"}
        </span>
      </div>
      <div
        ref={ref}
        onScroll={onScroll}
        className="max-h-72 overflow-auto bg-ink px-3 py-2.5 font-mono text-2xs leading-relaxed text-txt-dim"
      >
        {text ? (
          <pre className="whitespace-pre-wrap break-words">{text}</pre>
        ) : (
          <span className="text-txt-faint">waiting for output…</span>
        )}
      </div>
    </div>
  );
}
