"use client";

import React from "react";

interface ReasoningCardProps {
  action?: string;
  tool?: string | null;
  plannerType?: string;
  model?: string | null;
  latencyMs?: number;
  rationale?: string;
  steps?: string[];
  thoughts?: string | null;
  overrideReason?: string | null;
  llmProposal?: Record<string, any> | null;
  arbitration?: Record<string, any> | null;
}

const PLANNER_STYLE: Record<string, string> = {
  LLM: "bg-violet-50 text-violet-700 border-violet-200",
  HYBRID: "bg-sky-50 text-sky-700 border-sky-200",
  RULE: "bg-slate-50 text-slate-700 border-slate-200",
};

/** One planner decision: what was chosen, the reasoning chain, and (for LLM steps) the model's own thoughts. */
export const ReasoningCard: React.FC<ReasoningCardProps> = ({
  action,
  tool,
  plannerType = "RULE",
  model,
  latencyMs,
  rationale,
  steps = [],
  thoughts,
  overrideReason,
  llmProposal,
  arbitration,
}) => (
  <div className="rounded-lg border border-[#e7e9ee] bg-[#fcfcfd] p-3 space-y-2">
    <div className="flex items-center gap-2 flex-wrap">
      <span className="text-[13px] font-semibold text-[#111318]">
        {action === "RUN_TOOL" ? `Run ${tool}` : `Stop`}
      </span>
      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${PLANNER_STYLE[plannerType] || PLANNER_STYLE.RULE}`}>
        {plannerType} planner
      </span>
      {model && <span className="text-[10px] font-mono text-[#737986]">{model}</span>}
      {!!latencyMs && <span className="text-[10px] font-mono text-[#737986]">{(latencyMs / 1000).toFixed(1)}s</span>}
      {arbitration?.mode && (
        <span className="text-[10px] font-mono text-[#737986]">arbitration: {String(arbitration.mode).toLowerCase()}</span>
      )}
    </div>

    {overrideReason && (
      <div className="text-[11px] rounded border border-amber-300 bg-amber-50 text-amber-800 px-2 py-1">
        <b>LLM not followed:</b> {overrideReason}
        {llmProposal && (
          <span className="block text-amber-700/80 mt-0.5">
            It proposed {llmProposal.decision}
            {llmProposal.tool ? ` ${llmProposal.tool}` : ""}
            {llmProposal.rationale_summary ? `: “${llmProposal.rationale_summary}”` : ""}
          </span>
        )}
      </div>
    )}

    {steps.length > 0 ? (
      <ol className="list-decimal pl-5 space-y-0.5 text-[11.5px] text-[#2b2f36] leading-relaxed">
        {steps.map((s, i) => (
          <li key={i}>{s}</li>
        ))}
      </ol>
    ) : (
      rationale && <p className="text-[11.5px] text-[#2b2f36]">{rationale}</p>
    )}

    {thoughts && (
      <details className="group">
        <summary className="cursor-pointer select-none text-[11px] font-semibold text-violet-700">
          💭 Model thought chain ({thoughts.length.toLocaleString()} chars)
        </summary>
        <pre className="mt-1.5 max-h-72 overflow-y-auto whitespace-pre-wrap rounded border border-violet-100 bg-violet-50/40 p-2 text-[11px] leading-relaxed text-[#3b3355] font-sans">
          {thoughts}
        </pre>
      </details>
    )}
  </div>
);
