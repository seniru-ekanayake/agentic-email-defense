'use client';

import React from 'react';
import { ComprehensiveIncidentRecord, AttackChainStep } from '@/lib/api/types';

interface AttackGraphVisualizerProps {
  incident?: ComprehensiveIncidentRecord | null;
  onSelectAttackChain?: (step: AttackChainStep) => void;
}

interface DisplayNode {
  id: string;
  title: string;
  subtext: string;
  type: string;
  x: number;
  y: number;
  color: string;
  neonColor: string;
}

export function AttackGraphVisualizer({ incident, onSelectAttackChain }: AttackGraphVisualizerProps) {
  // If incident provides attack chain, dynamically build nodes from real attack chain
  const nodes: DisplayNode[] = React.useMemo(() => {
    if (incident?.attack_chain && incident.attack_chain.length > 0) {
      const count = incident.attack_chain.length;
      const stepWidth = Math.min(180, Math.floor(700 / Math.max(count, 1)));
      const startX = 70;

      const colors = ['#e11d48', '#2563eb', '#d97706', '#9333ea', '#059669', '#0891b2'];

      return incident.attack_chain.map((step, idx) => {
        const title = step.stage || step.node || `Step ${idx + 1}`;
        const subtext = step.technique || step.description || step.type || 'Chain Node';
        const color = colors[idx % colors.length];

        return {
          id: `step-${idx}`,
          title: title.length > 18 ? title.substring(0, 16) + '...' : title,
          subtext: subtext.length > 22 ? subtext.substring(0, 20) + '...' : subtext,
          type: step.stage || 'chain',
          x: startX + idx * stepWidth,
          y: 90,
          color,
          neonColor: color,
        };
      });
    }

    // If incident has graph_context nodes, extract up to 5 key nodes
    if (incident?.graph_context?.nodes && incident.graph_context.nodes.length > 0) {
      const topNodes = incident.graph_context.nodes.slice(0, 5);
      const stepWidth = 150;
      const startX = 80;
      const colors = ['#e11d48', '#2563eb', '#d97706', '#9333ea', '#059669'];

      return topNodes.map((n, idx) => ({
        id: n.id,
        title: n.label || n.name || 'Graph Node',
        subtext: n.id.length > 20 ? n.id.substring(0, 18) + '...' : n.id,
        type: n.label || 'node',
        x: startX + idx * stepWidth,
        y: 90,
        color: colors[idx % colors.length],
        neonColor: colors[idx % colors.length],
      }));
    }

    // Fallback display if no incident selected
    return [
      { id: '1', title: 'Sender', subtext: incident?.sender || 'Inbound Mail', type: 'sender', x: 80, y: 90, color: '#e11d48', neonColor: '#e11d48' },
      { id: '2', title: 'Transport', subtext: 'RFC 2822 / SMTP', type: 'transport', x: 260, y: 90, color: '#2563eb', neonColor: '#2563eb' },
      { id: '3', title: 'Exploit Vector', subtext: incident?.cve || incident?.threat_category || 'Exploit', type: 'exploit', x: 440, y: 90, color: '#d97706', neonColor: '#d97706' },
      { id: '4', title: 'Recipient', subtext: incident?.target_identity || incident?.recipient || 'Mailbox', type: 'target', x: 620, y: 90, color: '#9333ea', neonColor: '#9333ea' },
    ];
  }, [incident]);

  const totalHops = nodes.length;

  return (
    <div className="bg-white border border-[#e7e9ee] rounded-xl p-6 shadow-sm space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#1d5eea] animate-pulse" />
            <h3 className="text-sm font-bold tracking-wider text-[#111318] font-mono uppercase">
              ATTACK GRAPH TOPOLOGY & CAUSAL CHAIN
            </h3>
          </div>
          <p className="text-xs text-[#737986] mt-0.5 font-light">
            {incident
              ? `Reconstructed for Incident ${incident.incident_id}: ${incident.title}`
              : 'Select an incident from the ledger to project live topological attack chain'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-600 border border-rose-200">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
            {totalHops} HOPS IN CHAIN
          </span>
          {incident?.interaction_required && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-600 border border-blue-200">
              {incident.interaction_required}
            </span>
          )}
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="w-full bg-[#f8fafc] rounded-xl border border-[#e7e9ee] p-4 overflow-x-auto">
        <svg className="w-full min-w-[760px] h-48" viewBox="0 0 880 180" fill="none">
          {/* Underlay Connection Lines */}
          {nodes.map((n, idx) => {
            if (idx === nodes.length - 1) return null;
            const nextNode = nodes[idx + 1];
            return (
              <line
                key={`line-${idx}`}
                x1={n.x + 25}
                y1={90}
                x2={nextNode.x - 25}
                y2={90}
                stroke="#cbd5e1"
                strokeWidth="2"
                strokeDasharray="4 4"
              />
            );
          })}

          {/* Geometric Rect Nodes */}
          {nodes.map((item, idx) => (
            <g
              key={item.id}
              transform={`translate(${item.x}, 90)`}
              className="cursor-pointer group"
              onClick={() => {
                if (incident?.attack_chain?.[idx] && onSelectAttackChain) {
                  onSelectAttackChain(incident.attack_chain[idx]);
                }
              }}
            >
              {/* Outer Border */}
              <rect
                x="-24"
                y="-24"
                width="48"
                height="48"
                rx="8"
                fill="#ffffff"
                stroke={item.color}
                strokeWidth="2"
                className="transition-transform group-hover:scale-105"
              />
              <circle cx="0" cy="0" r="10" fill={item.color} opacity="0.15" />
              <text y="4" textAnchor="middle" className="text-[10px] font-mono font-bold fill-slate-700">
                {idx + 1}
              </text>
              <text y="38" textAnchor="middle" className="text-[11px] font-bold fill-[#111318] font-sans">
                {item.title}
              </text>
              <text y="52" textAnchor="middle" className="text-[9px] font-mono fill-[#737986]">
                {item.subtext}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* Vector Forensic Details Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        <div className="bg-[#f8fafc] p-3 rounded-xl border border-[#e7e9ee]">
          <span className="text-[#737986] text-[10px] block">TARGET CVE / VECTOR</span>
          <span className="text-amber-600 font-semibold text-xs mt-0.5 block truncate">
            {incident?.cve || incident?.threat_category || 'N/A'}
          </span>
        </div>
        <div className="bg-[#f8fafc] p-3 rounded-xl border border-[#e7e9ee]">
          <span className="text-[#737986] text-[10px] block">INTERACTION REQUIRED</span>
          <span className="text-rose-600 font-bold text-xs mt-0.5 block truncate">
            {incident?.interaction_required || 'AUTOMATIC / NONE'}
          </span>
        </div>
        <div className="bg-[#f8fafc] p-3 rounded-xl border border-[#e7e9ee]">
          <span className="text-[#737986] text-[10px] block">MAIL PLATFORM</span>
          <span className="text-blue-600 font-semibold text-xs mt-0.5 block truncate">
            {incident?.mail_platform || 'Universal Gateway'}
          </span>
        </div>
        <div className="bg-[#f8fafc] p-3 rounded-xl border border-[#e7e9ee]">
          <span className="text-[#737986] text-[10px] block">TARGET IDENTITY</span>
          <span className="text-purple-600 font-semibold text-xs mt-0.5 block truncate">
            {incident?.target_identity || incident?.recipient || 'N/A'}
          </span>
        </div>
      </div>
    </div>
  );
}
