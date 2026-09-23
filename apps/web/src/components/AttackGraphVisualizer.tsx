'use client';

import React from 'react';

interface Node {
  id: string;
  label: string;
  name: string;
}

interface Edge {
  source: string;
  target: string;
  relation: string;
}

interface AttackGraphProps {
  nodes?: Node[];
  edges?: Edge[];
}

export function AttackGraphVisualizer({ nodes = [], edges = [] }: AttackGraphProps) {
  // Default mock graph if none provided
  const defaultNodes: Node[] = [
    { id: 'actor', label: 'ThreatActor', name: 'Storm-0978' },
    { id: 'camp', label: 'Campaign', name: 'Q3 Spearphish' },
    { id: 'email', label: 'Email', name: 'Compensation EML' },
    { id: 'cve', label: 'CVE', name: 'CVE-2023-35636' },
    { id: 'asset', label: 'Asset', name: 'owa.corp.internal' },
    { id: 'ident', label: 'Identity', name: 'cfo@corp' },
    { id: 'sess', label: 'Session', name: 'OWA Session' },
  ];

  const defaultEdges: Edge[] = [
    { source: 'actor', target: 'camp', relation: 'ORCHESTRATES' },
    { source: 'camp', target: 'email', relation: 'DELIVERS' },
    { source: 'email', target: 'cve', relation: 'EXPLOITS' },
    { source: 'email', target: 'asset', relation: 'AFFECTS' },
    { source: 'email', target: 'ident', relation: 'TARGETS' },
    { source: 'ident', target: 'sess', relation: 'OWNS' },
    { source: 'cve', target: 'sess', relation: 'TRIGGERS' },
  ];

  const displayNodes = nodes.length > 0 ? nodes : defaultNodes;
  const displayEdges = edges.length > 0 ? edges : defaultEdges;

  // Node positions in layout
  const positions: Record<string, { x: number; y: number; color: string }> = {
    ThreatActor: { x: 80, y: 150, color: '#ef4444' },
    Campaign: { x: 220, y: 150, color: '#f97316' },
    Email: { x: 360, y: 150, color: '#eab308' },
    CVE: { x: 500, y: 80, color: '#dc2626' },
    Asset: { x: 500, y: 220, color: '#38bdf8' },
    Identity: { x: 640, y: 150, color: '#a855f7' },
    Session: { x: 780, y: 150, color: '#ec4899' },
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-bold text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            Attack Graph Explorer (Neo4j Topology)
          </h3>
          <p className="text-xs text-slate-400">Interactive attack traversal: Threat Actor → Vulnerability → Session Takeover</p>
        </div>
        <div className="flex gap-2">
          <span className="px-2 py-1 text-[10px] rounded bg-red-950/60 text-red-400 border border-red-800">Critical Path</span>
          <span className="px-2 py-1 text-[10px] rounded bg-cyan-950/60 text-cyan-400 border border-cyan-800">VIEW Exploitation</span>
        </div>
      </div>

      <div className="w-full h-80 bg-slate-950/80 rounded-lg border border-slate-800/80 flex items-center justify-center p-2 relative">
        <svg className="w-full h-full" viewBox="0 0 900 300">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b" />
            </marker>
            <marker id="arrow-red" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
            </marker>
          </defs>

          {/* Render Connections */}
          <line x1="80" y1="150" x2="220" y2="150" stroke="#64748b" strokeWidth="2" strokeDasharray="4" markerEnd="url(#arrow)" />
          <line x1="220" y1="150" x2="360" y2="150" stroke="#64748b" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="360" y1="150" x2="500" y2="80" stroke="#ef4444" strokeWidth="2.5" markerEnd="url(#arrow-red)" />
          <line x1="360" y1="150" x2="500" y2="220" stroke="#38bdf8" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="360" y1="150" x2="640" y2="150" stroke="#a855f7" strokeWidth="2" markerEnd="url(#arrow)" />
          <line x1="500" y1="80" x2="780" y2="150" stroke="#ef4444" strokeWidth="2.5" strokeDasharray="3" markerEnd="url(#arrow-red)" />
          <line x1="640" y1="150" x2="780" y2="150" stroke="#ec4899" strokeWidth="2" markerEnd="url(#arrow)" />

          {/* Render Nodes */}
          {displayNodes.map((node, i) => {
            const pos = positions[node.label] || { x: 100 + i * 110, y: 150, color: '#38bdf8' };
            return (
              <g key={node.id} className="cursor-pointer group">
                <circle cx={pos.x} cy={pos.y} r="22" fill="#0f172a" stroke={pos.color} strokeWidth="3" className="group-hover:stroke-white transition-all shadow-lg" />
                <text x={pos.x} y={pos.y + 4} textAnchor="middle" fill="#f8fafc" fontSize="10" fontWeight="bold">
                  {node.label.substring(0, 3).toUpperCase()}
                </text>
                <text x={pos.x} y={pos.y + 36} textAnchor="middle" fill="#cbd5e1" fontSize="10" className="font-mono">
                  {node.name.length > 14 ? node.name.substring(0, 12) + '...' : node.name}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="grid grid-cols-4 gap-2 mt-4 text-[11px] text-slate-400">
        <div className="bg-slate-950 p-2 rounded border border-slate-800">
          <span className="text-slate-500 block">Initial Vector:</span>
          <span className="text-amber-400 font-medium">search-ms Moniker Link</span>
        </div>
        <div className="bg-slate-950 p-2 rounded border border-slate-800">
          <span className="text-slate-500 block">Interaction Req:</span>
          <span className="text-red-400 font-bold">VIEW (Preview Pane)</span>
        </div>
        <div className="bg-slate-950 p-2 rounded border border-slate-800">
          <span className="text-slate-500 block">Exposed Software:</span>
          <span className="text-cyan-400 font-medium">Exchange OWA 15.1</span>
        </div>
        <div className="bg-slate-950 p-2 rounded border border-slate-800">
          <span className="text-slate-500 block">Impact:</span>
          <span className="text-purple-400 font-medium">NTLM Hash Relay / Session</span>
        </div>
      </div>
    </div>
  );
}
