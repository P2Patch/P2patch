function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Lightweight JSON syntax highlighting — keys in iris, strings green-ish,
// numbers amber, keywords blue. No dependency.
function highlight(json: string): string {
  const escaped = escapeHtml(json);
  return escaped.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(\.\d+)?([eE][+-]?\d+)?)/g,
    (match) => {
      let cls = "text-warn"; // number
      if (/^"/.test(match)) {
        cls = /:$/.test(match) ? "text-iris" : "text-[#8FCf9f]";
      } else if (/true|false/.test(match)) {
        cls = "text-info";
      } else if (/null/.test(match)) {
        cls = "text-txt-faint";
      }
      return `<span class="${cls}">${match}</span>`;
    },
  );
}

export function JsonView({ value, className = "" }: { value: unknown; className?: string }) {
  if (value == null) {
    return <div className="p-4 font-mono text-2xs text-txt-faint">no output</div>;
  }
  const text = JSON.stringify(value, null, 2);
  return (
    <pre
      className={`overflow-x-auto whitespace-pre-wrap break-words p-4 font-mono text-xs leading-relaxed text-txt ${className}`}
      dangerouslySetInnerHTML={{ __html: highlight(text) }}
    />
  );
}
