"use client";

import React, { useState, useEffect } from "react";
import { AgentLifecycleEvent } from "@/lib/api/types";

export interface StreamEvent {
  event_type: string;
  stage: string;
  message: string;
  timestamp: string;
  data?: Record<string, any>;
}

interface AgentLiveStreamVisualizerProps {
  events: (StreamEvent | AgentLifecycleEvent)[];
  isStreaming: boolean;
  onClear?: () => void;
  onStartScenario?: () => void;
}

export const AgentLiveStreamVisualizer: React.FC<AgentLiveStreamVisualizerProps> = ({
  events,
  isStreaming,
  onClear,
}) => {
  const [activeStage, setActiveStage] = useState<string>("IDLE");

  // Map backend event types or stages to standard 6 pipeline stages
  const mapEventToStage = (event: StreamEvent | AgentLifecycleEvent): string => {
    if ('stage' in event && event.stage) return event.stage;
    const type = event.event_type || '';
    if (type.includes('start') || type.includes('ingest')) return 'INGESTION';
    if (type.includes('tool') || type.includes('mime')) return 'ANALYSIS';
    if (type.includes('intel') || type.includes('threat') || type.includes('cve')) return 'VULN_RESEARCH';
    if (type.includes('exposure') || type.includes('surface')) return 'EXPOSURE';
    if (type.includes('evidence') || type.includes('hypothesis') || type.includes('graph')) return 'INVESTIGATION';
    if (type.includes('proposal') || type.includes('response') || type.includes('completed')) return 'RESPONSE';
    return 'ANALYSIS';
  };

  useEffect(() => {
    if (events.length > 0) {
      const lastEvent = events[events.length - 1];
      setActiveStage(mapEventToStage(lastEvent));
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
    if (type.includes('proposal') || type === 'agent.proposal.created') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-500 border border-amber-500/30">
          ACTION_PROPOSAL
        </span>
      );
    }
    if (type.includes('evidence') || type === 'agent.evidence.created') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-500 border border-rose-500/30">
          IOC_CONFIRMED
        </span>
      );
    }
    if (type.includes('tool') || type === 'agent.tool.executed') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-500 border border-purple-500/30">
          TOOL_EXECUTION
        </span>
      );
    }
    if (type.includes('completed') || type === 'agent.completed') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-600 border border-emerald-500/30">
          TRIAGE_COMPLETE
        </span>
      );
    }
    if (type.includes('step') || type.includes('started')) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/10 text-blue-600 border border-blue-500/30">
          PIPELINE_STEP
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/10 text-slate-600 border border-slate-300">
        REASONING
      </span>
    );
  };

  return (
    <div className="bg-white border border-[#e7e9ee] rounded-xl overflow-hidden shadow-sm transition-all">
      {/* Header */}
      <div className="px-5 py-3.5 border-b border-[#e7e9ee] flex items-center justify-between bg-[#fafbfc]">
        <div className="flex items-center space-x-3">
          <div className="relative flex items-center justify-center">
            <div className={`w-2.5 h-2.5 rounded-full ${isStreaming ? "bg-[#1d5eea] animate-pulse" : "bg-[#a0a5af]"}`} />
            {isStreaming && (
              <span className="absolute w-4 h-4 rounded-full bg-[#1d5eea]/30 animate-ping" />
            )}
          </div>
          <div>
            <h3 className="text-xs font-bold tracking-wider text-[#111318] font-mono flex items-center gap-2 uppercase">
              LANGGRAPH REASONING STREAM
              {isStreaming ? (
                <span className="text-[10px] text-[#1d5eea] font-mono font-bold uppercase px-2 py-0.5 bg-[#f0f4ff] rounded border border-[#1d5eea]/40">
                  LIVE SSE TELEMETRY
                </span>
              ) : (
                <span className="text-[10px] text-[#737986] font-mono font-normal">
                  STANDBY
                </span>
              )}
            </h3>
          </div>
        </div>
        {onClear && (
          <button
            onClick={onClear}
            className="text-[11px] font-mono text-[#737986] hover:text-[#111318] px-2.5 py-1 rounded bg-white border border-[#e7e9ee] hover:bg-[#f5f6f8] transition cursor-pointer"
          >
            CLEAR LOGS
          </button>
        )}
      </div>

      {/* Modern High-Density Stepper */}
      <div className="p-3 bg-[#f8fafc] border-b border-[#e7e9ee]">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
          {stages.map((st) => {
            const isCurrent = activeStage === st.key;
            const isPassed = events.some((e) => mapEventToStage(e) === st.key);
            return (
              <div
                key={st.key}
                className={`px-3 py-2 rounded-lg text-left transition-all border font-mono ${
                  isCurrent
                    ? "bg-[#f0f4ff] border-[#1d5eea] text-[#1d5eea] font-bold shadow-sm"
                    : isPassed
                    ? "bg-[#eaf8f1] border-[#16945b]/40 text-[#16945b]"
                    : "bg-white border-[#e7e9ee] text-[#a0a5af]"
                }`}
              >
                <div className="flex items-center justify-between text-[10px]">
                  <span>{st.short}</span>
                  {isPassed && <span className="text-[#16945b] font-bold">✓</span>}
                  {isCurrent && <span className="w-1.5 h-1.5 rounded-full bg-[#1d5eea] animate-ping" />}
                </div>
                <div className="text-[11px] font-semibold tracking-tight truncate mt-0.5">{st.label}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal Log Stream */}
      <div className="p-4 max-h-80 overflow-y-auto font-mono text-xs space-y-2.5 bg-[#ffffff] custom-scroll">
        {events.length === 0 ? (
          <div className="text-[#a0a5af] py-8 text-center text-xs font-mono">
            <svg className="w-6 h-6 mx-auto mb-2 opacity-40 stroke-current" fill="none" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
            </svg>
            $ awaiting_live_event_stream --endpoint=/api/v1/investigations/events
          </div>
        ) : (
          events.map((ev, idx) => {
            const stage = mapEventToStage(ev);
            const rawData = 'data' in ev ? ev.data : undefined;
            return (
              <div key={idx} className="flex items-start space-x-3 border-b border-[#f5f6f8] pb-2 last:border-none">
                <span className="text-[10px] text-[#a0a5af] whitespace-nowrap pt-0.5 font-mono">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center space-x-2">
                    {getEventTag(ev.event_type)}
                    <span className="text-[10px] font-bold text-[#737986] uppercase font-mono">
                      [{stage}]
                    </span>
                    {'tool' in ev && ev.tool && (
                      <span className="text-[10px] text-purple-600 font-mono bg-purple-50 px-1.5 py-0.2 rounded border border-purple-200">
                        tool:{ev.tool}
                      </span>
                    )}
                  </div>
                  <p className="text-[#111318] text-xs leading-relaxed font-sans">
                    {ev.message}
                  </p>
                  {rawData && Object.keys(rawData).length > 0 && (
                    <pre className="text-[10px] text-[#505660] bg-[#f8fafc] p-2 rounded border border-[#e7e9ee] overflow-x-auto font-mono">
                      {JSON.stringify(rawData, null, 2)}
                    </pre>
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
