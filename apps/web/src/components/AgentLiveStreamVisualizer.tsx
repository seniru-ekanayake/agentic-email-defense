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
    { key: "INGESTION", label: "01 Ingest & Privacy", short: "INGEST" },
    { key: "ANALYSIS", label: "02 Sandbox & Parse", short: "SANDBOX" },
    { key: "VULN_RESEARCH", label: "03 Threat Intel", short: "INTEL" },
    { key: "EXPOSURE", label: "04 Attack Surface", short: "SURFACE" },
    { key: "INVESTIGATION", label: "05 Dedup & Graph", short: "GRAPH" },
    { key: "RESPONSE", label: "06 Policy Response", short: "POLICY" },
  ];

  const getEventTag = (type: string) => {
    switch (type) {
      case "skill_activated":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">
            SKILL_TRIGGER
          </span>
        );
      case "evidence":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(255,0,85,0.2)]">
            IOC_CONFIRMED
          </span>
        );
      case "proposal":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            ACTION_PROPOSAL
          </span>
        );
      case "stage_start":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            PIPELINE_NODE
          </span>
        );
      case "complete":
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            TRIAGE_COMPLETE
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-700">
            REASONING
          </span>
        );
    }
  };

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden shadow-tactical-card transition-all">
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-border flex items-center justify-between bg-card-secondary">
        <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center">
            <div className={`w-2.5 h-2.5 rounded-full ${isStreaming ? "bg-neon-cyan shadow-[0_0_10px_#00e5ff] animate-pulse" : "bg-muted"}`} />
            {isStreaming && (
              <span className="absolute w-4 h-4 rounded-full bg-neon-cyan/30 animate-ping" />
            )}
          </div>
          <div>
            <h3 className="text-xs font-bold tracking-wider text-foreground font-mono flex items-center gap-2 uppercase">
              LANGGRAPH REASONING STREAM
              {isStreaming ? (
                <span className="text-[10px] text-neon-cyan font-mono font-bold uppercase px-2 py-0.5 bg-neon-cyan/10 rounded border border-neon-cyan/40">
                  LIVE SSE TELEMETRY
                </span>
              ) : (
                <span className="text-[10px] text-muted font-mono font-normal">
                  STANDBY
                </span>
              )}
            </h3>
          </div>
        </div>
        {onClear && (
          <button
            onClick={onClear}
            className="text-[11px] font-mono text-muted hover:text-foreground px-2.5 py-1 rounded bg-card border border-border hover:bg-hover-bg transition cursor-pointer"
          >
            CLEAR LOGS
          </button>
        )}
      </div>

      {/* Modern High-Density Stepper */}
      <div className="p-3 bg-background/60 border-b border-border">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
          {stages.map((st) => {
            const isCurrent = activeStage === st.key;
            const isPassed = events.some((e) => e.stage === st.key);
            return (
              <div
                key={st.key}
                className={`px-3 py-2 rounded-xl text-left transition-all border font-mono ${
                  isCurrent
                    ? "bg-neon-cyan/10 border-neon-cyan text-neon-cyan font-bold shadow-[0_0_12px_rgba(0,229,255,0.25)]"
                    : isPassed
                    ? "bg-neon-emerald/5 border-neon-emerald/40 text-neon-emerald"
                    : "bg-card border-border text-muted opacity-60"
                }`}
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span>{st.short}</span>
                  {isPassed && <span className="text-neon-emerald font-bold">✓</span>}
                  {isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-neon-cyan animate-ping" />}
                </div>
                <div className="text-[11px] font-semibold tracking-tight truncate mt-0.5">{st.label}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal Log Stream with Typewriter Blinking Cursor */}
      <div className="p-4 max-h-72 overflow-y-auto font-mono text-xs space-y-2.5 bg-card-secondary custom-scroll">
        {events.length === 0 ? (
          <div className="text-muted py-8 text-center text-xs font-mono">
            <svg className="w-6 h-6 mx-auto mb-2 opacity-30 stroke-current" fill="none" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            $ awaiting_ingestion_trigger --mode=realtime --privacy=scrubbed
          </div>
        ) : (
          events.map((ev, idx) => (
            <div key={idx} className="flex items-start space-x-3">
              <span className="text-[10px] text-muted whitespace-nowrap pt-0.5 font-mono opacity-60">
                {new Date(ev.timestamp).toLocaleTimeString()}
              </span>
              <div className="flex-1 space-y-1">
                <div className="flex items-center space-x-2">
                  {getEventTag(ev.event_type)}
                  <span className="text-[11px] font-bold text-muted uppercase">
                    [{ev.stage}]
                  </span>
                </div>
                <p className="text-foreground text-xs leading-relaxed font-sans">
                  {ev.message}
                  {isStreaming && idx === events.length - 1 && (
                    <span className="cursor-block ml-1.5 shadow-[0_0_6px_#00e5ff]" />
                  )}
                </p>
                {ev.data && Object.keys(ev.data).length > 0 && (
                  <pre className="text-[10px] text-muted bg-background/80 p-2 rounded-lg border border-border overflow-x-auto font-mono">
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
