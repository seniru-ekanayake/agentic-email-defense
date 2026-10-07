"use client";

import React, { useMemo } from "react";
import { AgentLifecycleEvent } from "@/lib/api/types";
import { PixelAgents, moodFromEvent } from "@/components/PixelAgents";
import { ReasoningCard } from "@/components/ReasoningCard";

export interface StreamEvent {
  event_type: string;
  stage: string;
  message: string;
  timestamp: string;
  data?: Record<string, any>;
}

type AnyEvent = StreamEvent | AgentLifecycleEvent;

interface AgentLiveStreamVisualizerProps {
  events: AnyEvent[];
  isStreaming: boolean;
  onClear?: () => void;
}

// Map the event types emitted by the backend to the investigation phases
const mapEventToStage = (event: AnyEvent): string => {
  if ("stage" in event && event.stage) return event.stage;
  switch (event.event_type) {
    case "agent.started":
      return "START";
    case "agent.thinking":
      return "THINK";
    case "agent.planner.selected":
      return "DECIDE";
    case "agent.tool.executed":
      return "TOOLS";
    case "agent.evidence.created":
      return "EVIDENCE";
    case "agent.proposal.created":
      return "APPROVAL";
    case "agent.completed":
    case "agent.failed":
      return "DONE";
    default:
      return "THINK";
  }
};

const STAGES = [
  { key: "START", label: "Parse email", short: "PARSE" },
  { key: "THINK", label: "Think", short: "THINK" },
  { key: "DECIDE", label: "Decide", short: "DECIDE" },
  { key: "TOOLS", label: "Run tool", short: "TOOL" },
  { key: "EVIDENCE", label: "Record evidence", short: "EVIDENCE" },
  { key: "APPROVAL", label: "Propose response", short: "APPROVAL" },
  { key: "DONE", label: "Verdict", short: "VERDICT" },
];

const TAGS: Record<string, [string, string]> = {
  "agent.started": ["START", "bg-blue-500/10 text-blue-600 border-blue-500/30"],
  "agent.thinking": ["THINKING", "bg-violet-500/10 text-violet-600 border-violet-500/30"],
  "agent.planner.selected": ["DECISION", "bg-indigo-500/10 text-indigo-600 border-indigo-500/30"],
  "agent.tool.executed": ["TOOL", "bg-purple-500/10 text-purple-600 border-purple-500/30"],
  "agent.evidence.created": ["EVIDENCE", "bg-rose-500/10 text-rose-600 border-rose-500/30"],
  "agent.proposal.created": ["PROPOSAL", "bg-amber-500/10 text-amber-600 border-amber-500/30"],
  "agent.completed": ["COMPLETE", "bg-emerald-500/10 text-emerald-600 border-emerald-500/30"],
  "agent.failed": ["FAILED", "bg-rose-500/10 text-rose-600 border-rose-500/30"],
};

const Tag: React.FC<{ type: string }> = ({ type }) => {
  const [label, cls] = TAGS[type] || ["EVENT", "bg-slate-500/10 text-slate-600 border-slate-300"];
  return <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${cls}`}>{label}</span>;
};

export const AgentLiveStreamVisualizer: React.FC<AgentLiveStreamVisualizerProps> = ({ events, isStreaming, onClear }) => {
  const last = events[events.length - 1];
  const activeStage = last ? mapEventToStage(last) : "IDLE";
  const mood = moodFromEvent(last?.event_type, isStreaming);
  const moodDetail = useMemo(() => {
    if (!last) return undefined;
    const d: Record<string, any> = ("data" in last && last.data) || {};
    if (last.event_type === "agent.thinking" && d.open_questions?.length) return `open: ${d.open_questions.join(", ")}`;
    if (last.event_type === "agent.tool.executed" && "tool" in last && last.tool) return String(last.tool);
    return undefined;
  }, [last]);

  return (
    <div className="bg-white border border-[#e7e9ee] rounded-xl overflow-hidden shadow-sm">
      <div className="px-5 py-3.5 border-b border-[#e7e9ee] flex items-center justify-between bg-[#fafbfc]">
        <h3 className="text-xs font-bold tracking-wider text-[#111318] font-mono flex items-center gap-2 uppercase">
          Investigation events
          {isStreaming ? (
            <span className="text-[10px] text-[#1d5eea] font-bold px-2 py-0.5 bg-[#f0f4ff] rounded border border-[#1d5eea]/40">LIVE</span>
          ) : (
            <span className="text-[10px] text-[#737986] font-normal">{events.length ? "REPLAY" : "STANDBY"}</span>
          )}
        </h3>
        {onClear && (
          <button
            onClick={onClear}
            className="text-[11px] font-mono text-[#737986] hover:text-[#111318] px-2.5 py-1 rounded bg-white border border-[#e7e9ee] hover:bg-[#f5f6f8] transition"
          >
            CLEAR
          </button>
        )}
      </div>

      <div className="p-3 border-b border-[#e7e9ee] bg-[#fbfcfe]">
        <PixelAgents mood={mood} detail={moodDetail} />
      </div>

      <div className="p-3 bg-[#f8fafc] border-b border-[#e7e9ee]">
        <div className="grid grid-cols-3 md:grid-cols-7 gap-2">
          {STAGES.map((st) => {
            const isCurrent = activeStage === st.key && isStreaming;
            const isPassed = events.some((e) => mapEventToStage(e) === st.key);
            return (
              <div
                key={st.key}
                className={`px-3 py-2 rounded-lg border font-mono ${
                  isCurrent
                    ? "bg-[#f0f4ff] border-[#1d5eea] text-[#1d5eea] font-bold shadow-sm"
                    : isPassed
                    ? "bg-[#eaf8f1] border-[#16945b]/40 text-[#16945b]"
                    : "bg-white border-[#e7e9ee] text-[#a0a5af]"
                }`}
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span>{st.short}</span>
                  {isPassed && !isCurrent && <span className="font-bold">✓</span>}
                  {isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-[#1d5eea] animate-ping" />}
                </div>
                <div className="text-[11px] font-semibold truncate mt-0.5">{st.label}</div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="p-4 max-h-[560px] overflow-y-auto text-xs space-y-3 bg-white">
        {events.length === 0 ? (
          <div className="text-[#a0a5af] py-8 text-center font-mono">Upload an .eml to watch the agents investigate.</div>
        ) : (
          events.map((ev, idx) => {
            const data: Record<string, any> = ("data" in ev && ev.data) || {};
            return (
              <div key={idx} className="flex items-start gap-3 border-b border-[#f5f6f8] pb-3 last:border-none">
                <span className="text-[10px] text-[#a0a5af] whitespace-nowrap pt-0.5 font-mono">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
                <div className="flex-1 min-w-0 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Tag type={ev.event_type} />
                    {"tool" in ev && ev.tool && (
                      <span className="text-[10px] text-purple-600 font-mono bg-purple-50 px-1.5 rounded border border-purple-200">{ev.tool}</span>
                    )}
                  </div>
                  {ev.event_type === "agent.planner.selected" ? (
                    <ReasoningCard
                      action={data.action}
                      tool={data.tool}
                      plannerType={data.planner_type}
                      model={data.model}
                      latencyMs={data.latency_ms}
                      rationale={data.rationale}
                      steps={data.reasoning_steps}
                      thoughts={data.reasoning_trace}
                      overrideReason={data.override_reason}
                      llmProposal={data.llm_proposal}
                      arbitration={data.arbitration}
                    />
                  ) : (
                    <>
                      <p className="text-[#111318] leading-relaxed">{ev.message}</p>
                      {Object.keys(data).length > 0 && (
                        <details className="text-[10px] text-[#505660]">
                          <summary className="cursor-pointer select-none text-[#737986]">details</summary>
                          <pre className="mt-1 bg-[#f8fafc] p-2 rounded border border-[#e7e9ee] overflow-x-auto font-mono">
                            {JSON.stringify(data, null, 2)}
                          </pre>
                        </details>
                      )}
                    </>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
