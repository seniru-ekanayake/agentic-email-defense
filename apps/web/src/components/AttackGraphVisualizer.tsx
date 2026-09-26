'use client';

import React from 'react';

interface Node {
  id: string;
  label: string;
  name: string;
  subtext?: string;
  type: 'actor' | 'email' | 'exploit' | 'auth' | 'identity' | 'server';
}

interface AttackGraphProps {
  nodes?: Node[];
}

export function AttackGraphVisualizer({}: AttackGraphProps) {
  const attackPath = [
    {
      id: 'actor',
      title: 'Threat Actor',
      subtext: '198.51.100.42 (Storm-0978)',
      type: 'actor',
      x: 80,
      y: 110,
      color: '#f43f5e',
      icon: (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      ),
    },
    {
      id: 'email',
      title: 'Moniker EML',
      subtext: 'search-ms:query=payroll',
      type: 'email',
      x: 260,
      y: 110,
      color: '#3b82f6',
      icon: (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
      ),
    },
    {
      id: 'exploit',
      title: 'Outlook Client',
      subtext: 'CVE-2024-21413 (CVSS 9.8)',
      type: 'exploit',
      x: 440,
      y: 110,
      color: '#ef4444',
      icon: (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
      ),
    },
    {
      id: 'auth',
      title: 'Forced Auth',
      subtext: 'SMB Port 445 NTLM Hash',
      type: 'auth',
      x: 620,
      y: 110,
      color: '#f59e0b',
      icon: (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
      ),
    },
    {
      id: 'identity',
      title: 'CFO Identity',
      subtext: 'cfo@enterprise-corp.internal',
      type: 'identity',
      x: 800,
      y: 110,
      color: '#8b5cf6',
      icon: (
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
      ),
    },
  ];

  return (
    <div className="bg-card border border-border rounded-2xl p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-accent-cyan animate-pulse" />
            <h3 className="text-sm font-semibold tracking-tight text-foreground font-mono">
              ATTACK GRAPH TOPOLOGY (Neo4j Cypher Traversal)
            </h3>
          </div>
          <p className="text-xs text-muted mt-0.5">
            Automated shortest-path calculation: Perimeter Ingress to Domain Credential Hijacking
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-medium bg-rose-50 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Critical Path (5 Hops)
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono font-medium bg-cyan-50 dark:bg-cyan-950/50 text-cyan-700 dark:text-cyan-300 border border-cyan-200 dark:border-cyan-800/50">
            Zero-Click / View
          </span>
        </div>
      </div>

      {/* SVG Vector Canvas */}
      <div className="w-full bg-slate-50/50 dark:bg-slate-950/60 rounded-xl border border-border p-4 overflow-x-auto">
        <svg className="w-full min-w-[760px] h-52" viewBox="0 0 880 200" fill="none">
          <defs>
            <linearGradient id="edge-grad-1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" />
              <stop offset="100%" stopColor="#3b82f6" />
            </linearGradient>
            <linearGradient id="edge-grad-2" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
            <linearGradient id="edge-grad-3" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#ef4444" />
              <stop offset="100%" stopColor="#f59e0b" />
            </linearGradient>
            <linearGradient id="edge-grad-4" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>

          {/* Connection Lines with Smooth Curves */}
          <path d="M 115 100 L 225 100" stroke="url(#edge-grad-1)" strokeWidth="2" strokeDasharray="4 4" />
          <path d="M 295 100 L 405 100" stroke="url(#edge-grad-2)" strokeWidth="2.5" />
          <path d="M 475 100 L 585 100" stroke="url(#edge-grad-3)" strokeWidth="2.5" />
          <path d="M 655 100 L 765 100" stroke="url(#edge-grad-4)" strokeWidth="2" strokeDasharray="4 4" />

          {/* Edge Label Chips */}
          <text x="170" y="88" fill="#64748b" fontSize="9" fontFamily="monospace" textAnchor="middle">SMTP TRANSPORT</text>
          <text x="350" y="88" fill="#ef4444" fontSize="9" fontFamily="monospace" textAnchor="middle" fontWeight="bold">CVE-2024-21413</text>
          <text x="530" y="88" fill="#f59e0b" fontSize="9" fontFamily="monospace" textAnchor="middle" fontWeight="bold">FORCED NTLM</text>
          <text x="710" y="88" fill="#8b5cf6" fontSize="9" fontFamily="monospace" textAnchor="middle">HASH RELAY</text>

          {/* Nodes */}
          {attackPath.map((item) => (
            <g key={item.id} transform={`translate(${item.x}, 100)`} className="cursor-pointer group">
              <circle
                r="24"
                className="fill-white dark:fill-slate-900 transition-all group-hover:scale-105"
                stroke={item.color}
                strokeWidth="2.5"
              />
              <g transform="translate(-8, -8)" stroke={item.color} className="w-4 h-4">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24">
                  {item.icon}
                </svg>
              </g>
              <text y="42" textAnchor="middle" className="text-[11px] font-semibold fill-foreground tracking-tight font-sans">
                {item.title}
              </text>
              <text y="56" textAnchor="middle" className="text-[9px] font-mono fill-muted">
                {item.subtext.length > 20 ? item.subtext.substring(0, 18) + '...' : item.subtext}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 text-xs font-mono">
        <div className="bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">Trigger Vector</span>
          <span className="text-amber-600 dark:text-amber-400 font-semibold text-xs mt-0.5 block">search-ms Moniker Link</span>
        </div>
        <div className="bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">Interaction State</span>
          <span className="text-rose-600 dark:text-rose-400 font-bold text-xs mt-0.5 block">Zero-Click / Preview</span>
        </div>
        <div className="bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">Target Host</span>
          <span className="text-blue-600 dark:text-blue-400 font-semibold text-xs mt-0.5 block">mail.enterprise-corp.internal</span>
        </div>
        <div className="bg-slate-50 dark:bg-slate-950/40 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">Blast Radius</span>
          <span className="text-purple-600 dark:text-purple-400 font-semibold text-xs mt-0.5 block">VIP Executive / CFO Mailbox</span>
        </div>
      </div>
    </div>
  );
}
