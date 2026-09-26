'use client';

import React from 'react';

interface Node {
  id: string;
  title: string;
  subtext: string;
  type: string;
  x: number;
  y: number;
  color: string;
  neonColor: string;
}

export function AttackGraphVisualizer() {
  const attackPath: Node[] = [
    {
      id: 'actor',
      title: 'Threat Actor',
      subtext: '198.51.100.42 (Storm-0978)',
      type: 'actor',
      x: 80,
      y: 90,
      color: '#ff0055',
      neonColor: '#ff0055',
    },
    {
      id: 'email',
      title: 'Moniker EML',
      subtext: 'search-ms:query=payroll',
      type: 'email',
      x: 260,
      y: 90,
      color: '#00e5ff',
      neonColor: '#00e5ff',
    },
    {
      id: 'exploit',
      title: 'Outlook Client',
      subtext: 'CVE-2024-21413 (CVSS 9.8)',
      type: 'exploit',
      x: 440,
      y: 90,
      color: '#ff0055',
      neonColor: '#ff0055',
    },
    {
      id: 'auth',
      title: 'Forced Auth',
      subtext: 'SMB Port 445 NetNTLMv2',
      type: 'auth',
      x: 620,
      y: 90,
      color: '#ffaa00',
      neonColor: '#ffaa00',
    },
    {
      id: 'identity',
      title: 'CFO Identity',
      subtext: 'cfo@enterprise-corp.internal',
      type: 'identity',
      x: 800,
      y: 90,
      color: '#b026ff',
      neonColor: '#b026ff',
    },
  ];

  return (
    <div className="bg-card border border-border rounded-2xl p-6 shadow-tactical-card space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-neon-cyan shadow-[0_0_8px_#00e5ff] animate-pulse" />
            <h3 className="text-sm font-bold tracking-wider text-foreground font-mono uppercase">
              ATTACK GRAPH TOPOLOGY (Cypher / Neo4j 5.x)
            </h3>
          </div>
          <p className="text-xs text-muted mt-0.5 font-light">
            Shortest-path shortestPath((actor)-[*1..5]->(identity)) traversed in 18ms
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_10px_rgba(255,0,85,0.2)]">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
            CRITICAL EXPLOIT CHAIN (5 HOPS)
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            ZERO-CLICK / VIEW
          </span>
        </div>
      </div>

      {/* SVG Canvas with Neon Packet Flow Animation */}
      <div className="w-full bg-card-secondary rounded-xl border border-border p-4 overflow-x-auto">
        <svg className="w-full min-w-[760px] h-48" viewBox="0 0 880 180" fill="none">
          <defs>
            <filter id="neon-glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="neon-glow-rose" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="2.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {/* Underlay Connection Lines */}
          <path d="M 115 90 L 225 90" stroke="rgba(255,255,255,0.06)" strokeWidth="1.5" />
          <path d="M 295 90 L 405 90" stroke="rgba(255,255,255,0.06)" strokeWidth="1.5" />
          <path d="M 475 90 L 585 90" stroke="rgba(255,255,255,0.06)" strokeWidth="1.5" />
          <path d="M 655 90 L 765 90" stroke="rgba(255,255,255,0.06)" strokeWidth="1.5" />

          {/* Animated Flowing Laser Packet Streams */}
          <path d="M 115 90 L 225 90" stroke="#00e5ff" strokeWidth="2" className="packet-stream" filter="url(#neon-glow-cyan)" />
          <path d="M 295 90 L 405 90" stroke="#ff0055" strokeWidth="2.5" className="packet-stream" filter="url(#neon-glow-rose)" />
          <path d="M 475 90 L 585 90" stroke="#ffaa00" strokeWidth="2.5" className="packet-stream" />
          <path d="M 655 90 L 765 90" stroke="#b026ff" strokeWidth="2" className="packet-stream" />

          {/* Protocol Tags */}
          <text x="170" y="78" fill="#8493ad" fontSize="9" fontFamily="JetBrains Mono" textAnchor="middle">SMTP TRANSPORT</text>
          <text x="350" y="78" fill="#ff0055" fontSize="9" fontFamily="JetBrains Mono" textAnchor="middle" fontWeight="bold">CVE-2024-21413</text>
          <text x="530" y="78" fill="#ffaa00" fontSize="9" fontFamily="JetBrains Mono" textAnchor="middle" fontWeight="bold">FORCED NTLM</text>
          <text x="710" y="78" fill="#b026ff" fontSize="9" fontFamily="JetBrains Mono" textAnchor="middle">HASH RELAY</text>

          {/* Sharp Geometric Rect Nodes */}
          {attackPath.map((item) => (
            <g key={item.id} transform={`translate(${item.x}, 90)`} className="cursor-pointer group">
              {/* Outer Glow Halo */}
              <rect
                x="-24"
                y="-24"
                width="48"
                height="48"
                rx="8"
                fill="none"
                stroke={item.neonColor}
                strokeWidth="1"
                opacity="0.3"
                className="group-hover:opacity-100 transition-opacity"
              />
              {/* Inner Solid Card */}
              <rect
                x="-22"
                y="-22"
                width="44"
                height="44"
                rx="6"
                className="fill-card border border-border"
                stroke={item.color}
                strokeWidth="1.8"
              />
              <text y="38" textAnchor="middle" className="text-[11px] font-bold fill-foreground font-poppins">
                {item.title}
              </text>
              <text y="52" textAnchor="middle" className="text-[9px] font-mono fill-muted">
                {item.subtext.length > 18 ? item.subtext.substring(0, 16) + '...' : item.subtext}
              </text>
            </g>
          ))}
        </svg>
      </div>

      {/* Vector Forensic Details Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
        <div className="bg-background/80 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">ATTACK TRIGGER</span>
          <span className="text-neon-amber font-semibold text-xs mt-0.5 block">search-ms Moniker URI</span>
        </div>
        <div className="bg-background/80 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">INTERACTION LEVEL</span>
          <span className="text-neon-rose font-bold text-xs mt-0.5 block">Zero-Click / Preview</span>
        </div>
        <div className="bg-background/80 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">PERIMETER TARGET</span>
          <span className="text-neon-cyan font-semibold text-xs mt-0.5 block">mail.enterprise-corp.internal</span>
        </div>
        <div className="bg-background/80 p-3 rounded-xl border border-border">
          <span className="text-muted text-[10px] block">BLAST RADIUS</span>
          <span className="text-neon-purple font-semibold text-xs mt-0.5 block">VIP Executive / CFO Mailbox</span>
        </div>
      </div>
    </div>
  );
}
