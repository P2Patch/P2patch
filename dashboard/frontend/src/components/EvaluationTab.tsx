import { useState } from "react";
import type { ExploitEval, PatchEval } from "../types";
import { AnalysisPanel, Note } from "./AnalysisPanel";
import { PatchScorecard } from "./PatchScorecard";
import { ExploitScorecard } from "./ExploitScorecard";

export function EvaluationTab({ runId, hasGroundTruth }: { runId: string; hasGroundTruth: boolean }) {
  const [kind, setKind] = useState<"patch" | "exploit">("patch");

  if (!hasGroundTruth) {
    return <Note>Evaluation needs the CVE mapping — none was found for this run.</Note>;
  }

  return (
    <div className="space-y-5">
      <div className="inline-flex rounded-md border border-hairline bg-ink2 p-0.5">
        {(["patch", "exploit"] as const).map((k) => (
          <button
            key={k}
            type="button"
            onClick={() => setKind(k)}
            className={`focusable rounded px-4 py-1.5 text-sm transition-colors ${
              kind === k ? "bg-elevated text-txt" : "text-txt-dim hover:text-txt"
            }`}
          >
            {k === "patch" ? "Patch quality" : "Exploit quality"}
          </button>
        ))}
      </div>

      {kind === "patch" ? (
        <AnalysisPanel<PatchEval>
          key="patch"
          runId={runId}
          agent="patch-eval"
          runLabel="Run patch evaluation"
          runningLabel="Evaluating patch — the judge is reading both diffs. This takes ~1–3 minutes."
          intro="A reference-anchored judge scores our patch against the official fix across 8 dimensions (root cause, completeness, developer intent, mitigation soundness…), gated on POV + regressions."
          ensemble={{
            samples: 3,
            label: "Ensemble ×3",
            note: "Runs the judge 3× in parallel and reports the median with a confidence band — stabilizes the score against run-to-run LLM variance. Similar wall-time, ~3× the cost.",
          }}
          render={(r) => <PatchScorecard ev={r} />}
        />
      ) : (
        <AnalysisPanel<ExploitEval>
          key="exploit"
          runId={runId}
          agent="exploit-eval"
          runLabel="Run exploit evaluation"
          runningLabel="Evaluating POV — the judge is reading the exploit and logs. This takes ~1–3 minutes."
          intro="A judge scores our POV's quality across 8 dimensions (does it reach the real sink, demonstrate real impact, and stop working once patched?), using a conjunctive / differential oracle."
          ensemble={{
            samples: 3,
            label: "Ensemble ×3",
            note: "Runs the judge 3× in parallel and reports the median with a confidence band — stabilizes the score against run-to-run LLM variance. Similar wall-time, ~3× the cost.",
          }}
          render={(r) => <ExploitScorecard ev={r} />}
        />
      )}
    </div>
  );
}
