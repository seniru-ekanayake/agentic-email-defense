"use client";

import React from "react";

export type AgentMood = "idle" | "thinking" | "working" | "evidence" | "proposing" | "done" | "failed";

/** Maps the latest investigation event to what the pixel crew is doing. */
export function moodFromEvent(eventType?: string, streaming?: boolean): AgentMood {
  switch (eventType) {
    case "agent.started":
    case "agent.thinking":
    case "agent.planner.selected":
      return "thinking";
    case "agent.tool.executed":
      return "working";
    case "agent.evidence.created":
      return "evidence";
    case "agent.proposal.created":
      return "proposing";
    case "agent.completed":
      return "done";
    case "agent.failed":
      return "failed";
    default:
      return streaming ? "thinking" : "idle";
  }
}

// 10x10 sprites. Palette keys: K outline, S skin, H hat/hair, B body, L legs, E eye, A accent.
const PLANNER = [
  "...HHHH...",
  "..HHHHHH..",
  "..KSSSSK..",
  "..SESSES..",
  "..KSSSSK..",
  "...BBBB...",
  "..BBAABB..",
  "..BBBBBB..",
  "...L..L...",
  "...K..K...",
];
const SCOUT_A = [
  "...AAAA...",
  "..AAAAAA..",
  "..KSSSSK..",
  "..SESSES..",
  "..KSSSSK..",
  "...BBBB...",
  ".SBBBBBBS.",
  "..BBBBBB..",
  "..L....L..",
  ".K......K.",
];
const SCOUT_B = [
  "...AAAA...",
  "..AAAAAA..",
  "..KSSSSK..",
  "..SESSES..",
  "..KSSSSK..",
  "...BBBB...",
  ".SBBBBBBS.",
  "..BBBBBB..",
  "...LLLL...",
  "...K..K...",
];
const ARCHIVIST = [
  "..HHHHHH..",
  ".HHHHHHHH.",
  "..KSSSSK..",
  "..SESSES..",
  "..KSSSSK..",
  "...BBBB...",
  "..BBBBBB..",
  "..BBBBBB..",
  "...L..L...",
  "...K..K...",
];

const PALETTES: Record<string, Record<string, string>> = {
  planner: { K: "#1f2937", S: "#f5d0a9", H: "#6d28d9", B: "#7c3aed", L: "#374151", E: "#111827", A: "#facc15" },
  scout: { K: "#1f2937", S: "#f5d0a9", H: "#0f766e", B: "#0d9488", L: "#374151", E: "#111827", A: "#14b8a6" },
  archivist: { K: "#1f2937", S: "#f1c7a0", H: "#b45309", B: "#d97706", L: "#374151", E: "#111827", A: "#fbbf24" },
};

const Sprite: React.FC<{ rows: string[]; palette: Record<string, string>; className?: string }> = ({ rows, palette, className }) => (
  <svg viewBox="0 0 10 10" width="40" height="40" shapeRendering="crispEdges" className={className} aria-hidden="true">
    {rows.flatMap((row, y) =>
      row.split("").map((ch, x) =>
        ch === "." ? null : <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill={palette[ch]} />
      )
    )}
  </svg>
);

const LABELS: Record<AgentMood, string> = {
  idle: "Waiting for an email",
  thinking: "Planner is weighing the evidence…",
  working: "Scout is running a tool…",
  evidence: "Archivist is filing new evidence…",
  proposing: "Proposing a response for approval…",
  done: "Investigation complete",
  failed: "Investigation failed",
};

interface PixelAgentsProps {
  mood: AgentMood;
  detail?: string;
  compact?: boolean;
}

export const PixelAgents: React.FC<PixelAgentsProps> = ({ mood, detail, compact }) => {
  const active = mood !== "idle" && mood !== "done" && mood !== "failed";
  return (
    <div
      className={`pixel-stage relative overflow-hidden rounded-lg border border-[#e7e9ee] bg-gradient-to-b from-[#eef4ff] to-[#f8fafc] ${compact ? "h-[86px]" : "h-[112px]"}`}
      data-mood={mood}
      role="status"
      aria-live="polite"
    >
      {/* floor */}
      <div className="absolute bottom-0 left-0 right-0 h-[18px] bg-[repeating-linear-gradient(90deg,#dbe4f3_0_8px,#e6edf8_8px_16px)]" />

      {/* Planner + thought bubble */}
      <div className="absolute bottom-[14px] left-[8%] pixel-planner">
        {mood === "thinking" && (
          <div className="pixel-bubble absolute -top-8 left-6 rounded-md border-2 border-[#1f2937] bg-white px-1.5 text-[11px] font-mono leading-5 text-[#1f2937]">
            <span className="pixel-dots">…</span>
          </div>
        )}
        <Sprite rows={PLANNER} palette={PALETTES.planner} className={mood === "thinking" ? "pixel-ponder" : "pixel-breathe"} />
      </div>

      {/* Scout walks to the tool bench */}
      <div className={`absolute bottom-[14px] left-[30%] ${mood === "working" ? "pixel-walk" : ""}`}>
        <div className={mood === "working" ? "pixel-frames" : "pixel-breathe"}>
          <Sprite rows={SCOUT_A} palette={PALETTES.scout} className="frame-a" />
          <Sprite rows={SCOUT_B} palette={PALETTES.scout} className="frame-b" />
        </div>
      </div>
      <div className={`absolute bottom-[14px] right-[30%] text-lg ${mood === "working" ? "pixel-spark" : "opacity-60"}`} aria-hidden="true">
        🛠️
      </div>

      {/* Archivist carries evidence to the cabinet */}
      <div className={`absolute bottom-[14px] right-[8%] ${mood === "evidence" ? "pixel-carry" : ""}`}>
        {mood === "evidence" && <div className="pixel-doc absolute -top-3 left-3 h-3 w-2.5 border border-[#1f2937] bg-white" />}
        <Sprite rows={ARCHIVIST} palette={PALETTES.archivist} className={mood === "done" ? "pixel-jump" : "pixel-breathe"} />
      </div>

      {(mood === "done" || mood === "proposing") && (
        <div className="absolute top-2 left-1/2 -translate-x-1/2 text-base pixel-pop" aria-hidden="true">
          {mood === "done" ? "✨" : "📨"}
        </div>
      )}

      <div className="absolute left-3 top-2 flex items-center gap-2 text-[11px] font-mono text-[#374151]">
        <span className={`inline-block h-2 w-2 rounded-full ${active ? "bg-[#1d5eea] animate-pulse" : mood === "failed" ? "bg-rose-500" : "bg-[#16945b]"}`} />
        <span className="font-bold">{LABELS[mood]}</span>
        {detail && <span className="text-[#737986] truncate max-w-[340px]">{detail}</span>}
      </div>
    </div>
  );
};
