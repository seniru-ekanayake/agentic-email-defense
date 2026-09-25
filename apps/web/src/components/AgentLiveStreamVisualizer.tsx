"use client";

import React, { useState, useEffect } from "react";

export interface StreamEvent {
  event_type: "stage_start" | "thought" | "skill_activated" | "evidence" | "proposal" | "complete";
  stage: string;
  message: string;
  timestamp: string;
  data?: Record<string, any>;
}

interface AgentLiveStreamVisualizerProps {
  events: StreamEvent[];
  isStreaming: boolean;
  onClear?: () => void;
}

export const AgentLiveStreamVisualizer: React.FC<AgentLiveStreamVisualizerProps> = ({
  events,
  isStreaming,
  onClear,
}) => {
  const [activeStage, setActiveStage] = useState<string>("IDLE");

  useEffect(() => {
    if (events.length > 0) {
      const lastEvent = events[events.length - 1];
      setActiveStage(lastEvent.stage || "COMPLETE");
    }
  }, [events]);

  const stages = [
    { key: "INGESTION", label: "1. Ingest & Privacy" },
    { key: "ANALYSIS", label: "2. Parser & Sandbox" },
    { key: "VULN_RESEARCH", label: "3. Threat Intel" },
    { key: "EXPOSURE", label: "4. Attack Surface" },
    { key: "INVESTIGATION", label: "5. Investigation" },
    { key: "RESPONSE", label: "6. Policy Response" },
  ];

  const getEventBadge = (type: string) => {
    switch (type) {
      case "skill_activated":
        return <span className="bg-purple-900/80 text-purple-300 text-xs px-2 py-0.5 rounded border border-purple-500 font-mono">SKILL ACTIVATED</span>;
      case "evidence":
        return <span className="bg-red-900/80 text-red-300 text-xs px-2 py-0.5 rounded border border-red-500 font-mono">IOC DETECTED</span>;
      case "proposal":
        return <span className="bg-amber-900/80 text-amber-300 text-xs px-2 py-0.5 rounded border border-amber-500 font-mono">ACTION PROPOSAL</span>;
      case "stage_start":
        return <span className="bg-blue-900/80 text-blue-300 text-xs px-2 py-0.5 rounded border border-blue-500 font-mono">STAGE</span>;
      case "complete":
        return <span className="bg-emerald-900/80 text-emerald-300 text-xs px-2 py-0.5 rounded border border-emerald-500 font-mono">COMPLETE</span>;
      default:
        return <span className="bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded font-mono">REASONING</span>;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-700/80 rounded-xl overflow-hidden shadow-2xl backdrop-blur-md">
      {/* Header */}
      <div className="bg-slate-800/80 border-b border-slate-700 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${isStreaming ? "bg-emerald-500 animate-pulse" : "bg-slate-500"}`} />
          <h3 className="text-sm font-semibold text-white font-mono flex items-center gap-2">
            AGENTIC REASONING STREAM (SSE)
            {isStreaming && <span className="text-xs text-emerald-400 font-normal">● LIVE TELEMETRY</span>}
          </h3>
        </div>
        {onClear && (
          <button
            onClick={onClear}
            className="text-xs text-slate-400 hover:text-slate-200 px-2 py-1 rounded bg-slate-700/50 hover:bg-slate-700 transition"
          >
            Clear Stream
          </button>
        )}
      </div>

      {/* Stage Flow Indicator */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-1 bg-slate-950/60 p-2 border-b border-slate-800 text-xs">
        {stages.map((st) => {
          const isCurrent = activeStage === st.key;
          const isPassed = events.some((e) => e.stage === st.key);
          return (
            <div
              key={st.key}
              className={`px-2 py-1.5 rounded text-center font-mono transition-all ${
                isCurrent
                  ? "bg-blue-600/30 text-blue-300 border border-blue-500 font-bold shadow-sm shadow-blue-500/20"
                  : isPassed
                  ? "bg-emerald-950/40 text-emerald-400 border border-emerald-800/50"
                  : "bg-slate-900/40 text-slate-500 border border-slate-800/40"
              }`}
            >
              {st.label}
            </div>
          );
        })}
      </div>

      {/* Terminal Log Output */}
      <div className="p-4 max-h-80 overflow-y-auto font-mono text-xs space-y-2 bg-slate-950/90 divide-y divide-slate-900">
        {events.length === 0 ? (
          <div className="text-slate-500 py-6 text-center italic">
            Waiting for email ingestion trigger... All agent nodes standing by.
          </div>
        ) : (
          events.map((ev, idx) => (
            <div key={idx} className="pt-2 flex items-start space-x-3">
              <span className="text-slate-500 text-[10px] whitespace-nowrap pt-0.5">
                {new Date(ev.timestamp).toLocaleTimeString()}
              </span>
              <div className="flex-1 space-y-1">
                <div className="flex items-center space-x-2">
                  {getEventBadge(ev.event_type)}
                  <span className="text-slate-400 font-semibold">[{ev.stage}]</span>
                </div>
                <p className="text-slate-200 text-xs leading-relaxed">{ev.message}</p>
                {ev.data && Object.keys(ev.data).length > 0 && (
                  <pre className="text-[11px] text-slate-400 bg-slate-900/80 p-1.5 rounded overflow-x-auto border border-slate-800/60">
                    {JSON.stringify(ev.data, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
