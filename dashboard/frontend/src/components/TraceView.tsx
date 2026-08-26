import type { AlertTrace } from "../types";

// The finder's static taint trace: source flows to sink. First node = source,
// last = sink (the dangerous operation the POV must reach).
export function TraceView({ trace }: { trace: AlertTrace }) {
  const vulns = trace.vulnerabilities ?? [];
  if (vulns.length === 0) {
    return <div className="font-mono text-2xs text-txt-faint">no trace recorded</div>;
  }
  return (
    <div className="space-y-5">
      {vulns.map((v, vi) => {
        const traces = v.traces ?? [];
        // Show the first (representative) trace path; note if there are more.
        const path = traces[0] ?? [];
        return (
          <div key={vi} className="space-y-2">
            {vulns.length > 1 && <div className="eyebrow">vulnerability {vi + 1}</div>}
            <ol className="space-y-0">
              {path.map((step, i) => {
                const isSource = i === 0;
                const isSink = i === path.length - 1;
                const file = step.uri.split("/").pop();
                return (
                  <li key={i} className="relative flex gap-3 pl-1">
                    <div className="flex flex-col items-center">
                      <span
                        className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                          isSink ? "bg-fail" : isSource ? "bg-info" : "bg-txt-faint"
                        }`}
                      />
                      {!isSink && <span className="my-0.5 w-px flex-1 bg-hairline-strong" />}
                    </div>
                    <div className="pb-3">
                      <div className="font-mono text-xs text-txt">{step.message}</div>
                      <div className="font-mono text-2xs text-txt-faint">
                        {file}:{step.line}
                        {isSource && <span className="ml-2 text-info">source</span>}
                        {isSink && <span className="ml-2 text-fail">sink</span>}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
            {traces.length > 1 && (
              <div className="text-2xs text-txt-faint">+ {traces.length - 1} more path(s) to the same sink</div>
            )}
          </div>
        );
      })}
    </div>
  );
}
