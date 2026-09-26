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
    { key: "INGESTION", label: "Ingest & Privacy", step: "01" },
    { key: "ANALYSIS", label: "Parser & Sandbox", step: "02" },
    { key: "VULN_RESEARCH", label: "Threat Intel", step: "03" },
    { key: "EXPOSURE", label: "Attack Surface", step: "04" },
    { key: "INVESTIGATION", label: "Investigation", step: "05" },
    { key: "RESPONSE", label: "Policy Response", step: "06" },
  ];

  const getEventBadge = (type: string) => {
    switch (type) {
      case "skill_activated":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/60 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            SKILL ACTIVATED
          </span>
        );
      case "evidence":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border border-rose-200 dark:border-rose-800/60 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            IOC DETECTED
          </span>
        );
      case "proposal":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border border-amber-200 dark:border-amber-800/60 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            ACTION PROPOSAL
          </span>
        );
      case "stage_start":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-800/60 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
            </svg>
            NODE PIPELINE
          </span>
        );
      case "complete":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/60 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
            </svg>
            COMPLETE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 font-mono">
            <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            REASONING
          </span>
        );
    }
  };

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden shadow-sm transition-all">
      {/* Header */}
      <div className="px-5 py-4 border-b border-border flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/40">
        <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center">
            <div className={`w-2.5 h-2.5 rounded-full ${isStreaming ? "bg-emerald-500 animate-pulse" : "bg-slate-400"}`} />
            {isStreaming && (
              <span className="absolute w-4 h-4 rounded-full bg-emerald-500/30 animate-ping" />
            )}
          </div>
          <div>
            <h3 className="text-xs font-semibold tracking-tight text-foreground font-mono flex items-center gap-2">
              AGENTIC REASONING STREAM
              {isStreaming ? (
                <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-mono font-medium uppercase px-1.5 py-0.5 bg-emerald-50 dark:bg-emerald-950/60 rounded border border-emerald-200 dark:border-emerald-800/40">
                  Live Telemetry
                </span>
              ) : (
                <span className="text-[10px] text-slate-500 dark:text-slate-400 font-mono font-normal">
                  Standby
                </span>
              )}
            </h3>
          </div>
        </div>
        {onClear && (
          <button
            onClick={onClear}
            className="text-xs text-muted hover:text-foreground px-2.5 py-1 rounded-lg border border-border hover:bg-hover-bg transition"
          >
            Clear Log
          </button>
        )}
      </div>

      {/* Modern Stage Stepper */}
      <div className="p-3 bg-slate-50/30 dark:bg-slate-950/40 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
          {stages.map((st) => {
            const isCurrent = activeStage === st.key;
            const isPassed = events.some((e) => e.stage === st.key);
            return (
              <div
                key={st.key}
                className={`px-3 py-2 rounded-xl text-left transition-all border ${
                  isCurrent
                    ? "bg-blue-50/80 dark:bg-blue-950/40 border-blue-500/80 text-blue-700 dark:text-blue-300 shadow-sm"
                    : isPassed
                    ? "bg-emerald-50/50 dark:bg-emerald-950/20 border-emerald-300/60 dark:border-emerald-800/40 text-emerald-700 dark:text-emerald-400"
                    : "bg-white dark:bg-slate-900/40 border-border text-slate-400 dark:text-slate-500"
                }`}
              >
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-[9px] font-mono font-medium opacity-60">{st.step}</span>
                  {isPassed && (
                    <svg className="w-3 h-3 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                  {isCurrent && (
                    <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-ping" />
                  )}
                </div>
                <div className="text-[11px] font-medium tracking-tight truncate">{st.label}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal Log Stream */}
      <div className="p-4 max-h-72 overflow-y-auto font-mono text-xs space-y-3 bg-white dark:bg-slate-950/60">
        {events.length === 0 ? (
          <div className="text-slate-400 dark:text-slate-500 py-8 text-center text-xs">
            <svg className="w-8 h-8 mx-auto mb-2 opacity-40 stroke-current" fill="none" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            Awaiting ingestion trigger... LangGraph pipeline standing by.
          </div>
        ) : (
          events.map((ev, idx) => (
            <div key={idx} className="flex items-start space-x-3 group">
              <span className="text-[10px] text-slate-400 dark:text-slate-500 whitespace-nowrap pt-0.5 font-mono">
                {new Date(ev.timestamp).toLocaleTimeString()}
              </span>
              <div className="flex-1 space-y-1.5">
                <div className="flex items-center space-x-2">
                  {getEventBadge(ev.event_type)}
                  <span className="text-xs font-semibold text-slate-600 dark:text-slate-400">
                    [{ev.stage}]
                  </span>
                </div>
                <p className="text-foreground text-xs leading-relaxed font-sans">{ev.message}</p>
                {ev.data && Object.keys(ev.data).length > 0 && (
                  <pre className="text-[10px] text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/80 p-2 rounded-lg overflow-x-auto border border-border">
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
