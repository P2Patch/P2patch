interface Props {
  diff: string;
  emptyLabel?: string;
}

// Renders a unified git diff with per-line tinting. Kept dependency-free.
export function DiffViewer({ diff, emptyLabel = "empty diff" }: Props) {
  if (!diff || !diff.trim()) {
    return <div className="p-4 font-mono text-2xs text-txt-faint">{emptyLabel}</div>;
  }
  const lines = diff.replace(/\n$/, "").split("\n");
  return (
    <div className="overflow-x-auto font-mono text-xs leading-[1.5]">
      {lines.map((line, i) => {
        let cls = "text-txt-dim";
        let bg = "";
        if (line.startsWith("+++") || line.startsWith("---")) {
          cls = "text-txt-faint";
        } else if (line.startsWith("diff ") || line.startsWith("index ")) {
          cls = "text-iris/70";
        } else if (line.startsWith("@@")) {
          cls = "text-info";
          bg = "bg-info/5";
        } else if (line.startsWith("+")) {
          cls = "text-[#8FD3A6]";
          bg = "bg-pass/[0.08]";
        } else if (line.startsWith("-")) {
          cls = "text-[#E9928E]";
          bg = "bg-fail/[0.08]";
        }
        return (
          <div key={i} className={`whitespace-pre px-4 ${bg} ${cls}`}>
            {line || " "}
          </div>
        );
      })}
    </div>
  );
}
