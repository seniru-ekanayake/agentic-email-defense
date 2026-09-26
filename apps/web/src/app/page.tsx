'use client';

import React, { useState, useEffect } from 'react';
import { AgentLiveStreamVisualizer, StreamEvent } from '@/components/AgentLiveStreamVisualizer';
import { AttackGraphVisualizer } from '@/components/AttackGraphVisualizer';
import { IncidentDetailModal } from '@/components/IncidentDetailModal';
import { HumanApprovalModal, PendingActionProposal } from '@/components/HumanApprovalModal';
import { ExposureView } from '@/components/ExposureView';

export default function DashboardPage() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [activeNav, setActiveNav] = useState<'overview' | 'stream' | 'incidents' | 'graph' | 'surface'>('overview');
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // SSE Stream Simulation State
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

  // Synchronize theme with html element
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const pendingProposal: PendingActionProposal = {
    token: 'APP-8E2F9A',
    tool_name: 'quarantine_email_and_revoke_session',
    risk_level: 'HIGH',
    parameters: {
      mailbox: 'cfo@enterprise-corp.internal',
      message_id: '<20240926.exploit.moniker@corporate-updates.net>',
      revoke_active_sessions: true,
      block_source_ip: '198.51.100.42',
    },
    justification: 'Zero-click Moniker exploit link targeting VIP CFO mailbox. Forced NTLM hash relay detected on outbound port 445.',
    target_cve: 'CVE-2024-21413 (CVSS 9.8)',
    target_identity: 'cfo@enterprise-corp.internal',
  };

  const incidents = [
    {
      incident_id: 'INC-849201',
      tenant_id: 'tenant-enterprise-demo',
      title: 'Outlook Moniker Link Forced NTLM Relay',
      severity: 'CRITICAL',
      overall_risk_score: 96.8,
      confidence: 0.98,
      status: 'CONTAINMENT_PROPOSED',
      target_identity: 'cfo@enterprise-corp.internal',
      mail_platform: 'Microsoft Exchange / OWA 15.1',
      exposure_status: 'Internet-Facing',
      interaction_required: 'ZERO-CLICK (VIEW)',
      cve: 'CVE-2024-21413',
      attack_chain: [
        { stage: 'INITIAL_ACCESS', technique: 'Spearphishing Link (T1566.002)', description: 'Attacker delivers crafted EML from spoofed domain: corporate-updates.net' },
        { stage: 'MIME_TRANSPORT', technique: 'M365 Webhook Ingest', description: 'Message arrives at perimeter; payload contains search-ms moniker handler.' },
        { stage: 'RENDERING_PARSER', technique: 'Moniker URI Parsing', description: 'Outlook preview triggers CVE-2024-21413 bypass in rendering pipeline.' },
        { stage: 'FORCED_AUTH', technique: 'Forced Authentication (T1187)', description: 'Client initiates outbound SMB callout to \\\\198.51.100.42\\share leaking NetNTLMv2.' },
        { stage: 'IDENTITY_RELAY', technique: 'Credential Relay', description: 'High-privilege executive identity cfo@enterprise-corp.internal targeted for takeover.' },
        { stage: 'LATERAL_RISK', technique: 'Session Hijacking', description: 'Threat actor attempts domain service authentication via relayed hash.' }
      ],
      evidence_summary: [
        'SPF/DMARC alignment failure for corporate-updates.net.',
        'Extracted URI moniker link: file:///\\\\198.51.100.42\\share\\payroll.docx!zero',
        'Outbound SMB connection attempt observed to external IP 198.51.100.42.',
        'Target identity classified as Tier-0 VIP CFO with administrative privileges.',
        'Internet-facing Exchange OWA 15.1.2507.17 identified on corporate perimeter.'
      ],
      recommended_actions: [
        { action: 'quarantine_email', reasoning: 'Quarantine malicious EML across all recipient mailboxes.', requires_approval: true },
        { action: 'revoke_session', reasoning: 'Revoke active Entra ID / Exchange sessions to neutralize relayed tokens.', requires_approval: true },
        { action: 'block_firewall_ip', reasoning: 'Block outbound SMB connections to attacker IP 198.51.100.42.', requires_approval: false }
      ],
      pending_approvals: [
        { tool_name: 'quarantine_email_and_revoke_session', approval_token: 'APP-8E2F9A', risk_level: 'HIGH' }
      ]
    }
  ];

  const handleRunSimulation = () => {
    setIsStreaming(true);
    setEvents([]);

    const streamScenario: StreamEvent[] = [
      {
        event_type: 'stage_start',
        stage: 'INGESTION',
        message: 'M365 Graph Webhook received RFC 2822 raw payload from attacker@corporate-updates.net. Tenant privacy scrubbing active.',
        timestamp: new Date().toISOString(),
        data: { message_id: '<20240926.exploit.moniker@corporate-updates.net>', recipient: 'cfo@enterprise-corp.internal' },
      },
      {
        event_type: 'evidence',
        stage: 'ANALYSIS',
        message: 'MIME Parser detected Moniker exploit link: file:///\\\\198.51.100.42\\share\\payroll.docx!zero. Sandboxed rendering observed forced SMB auth attempt.',
        timestamp: new Date().toISOString(),
        data: { handler: 'search-ms', target_smb: '198.51.100.42:445' },
      },
      {
        event_type: 'skill_activated',
        stage: 'VULN_RESEARCH',
        message: 'Dynamic Skill "moniker_exploit_triage" matched CVE-2024-21413 (CVSS 9.8 Critical). URLhaus / AbuseIPDB confirmed malicious IP 198.51.100.42 reputation score 100%.',
        timestamp: new Date().toISOString(),
        data: { cve: 'CVE-2024-21413', cvss: 9.8, cisa_kev: true },
      },
      {
        event_type: 'evidence',
        stage: 'EXPOSURE',
        message: 'Correlated victim identity cfo@enterprise-corp.internal against internet-facing Exchange OWA server 15.1.2507.17. High blast radius confirmed.',
        timestamp: new Date().toISOString(),
        data: { exposure_score: 96.8, asset: 'owa.enterprise-corp.internal' },
      },
      {
        event_type: 'thought',
        stage: 'INVESTIGATION',
        message: 'Campaign deduplication aggregated 500 identical emails into Campaign Incident CMP-2024-NTLM-01. Attack graph mapped shortest path to domain admin hash relay.',
        timestamp: new Date().toISOString(),
        data: { campaign_id: 'CMP-2024-NTLM-01', rollup_count: 500, shortest_path_hops: 5 },
      },
      {
        event_type: 'proposal',
        stage: 'RESPONSE',
        message: 'Response policy gate triggered: Containment proposed (quarantine & session revoke). Generated approval token APP-8E2F9A.',
        timestamp: new Date().toISOString(),
        data: { approval_token: 'APP-8E2F9A', autonomy_level: 1, action: 'quarantine_email_and_revoke_session' },
      },
      {
        event_type: 'complete',
        stage: 'COMPLETE',
        message: 'LangGraph triage completed in 1.42s. Awaiting SOC Analyst authorization.',
        timestamp: new Date().toISOString(),
      },
    ];

    streamScenario.forEach((ev, idx) => {
      setTimeout(() => {
        setEvents((prev) => [...prev, ev]);
        if (idx === streamScenario.length - 1) {
          setIsStreaming(false);
          setApprovalModalOpen(true);
        }
      }, (idx + 1) * 700);
    });
  };

  return (
    <div className="min-h-screen bg-background text-foreground flex antialiased tactical-mesh font-poppins selection:bg-neon-cyan/20 selection:text-neon-cyan">
      
      {/* 1. Left Minimalist Sidebar */}
      <aside className="w-64 bg-sidebar border-r border-border flex flex-col justify-between p-5 shrink-0 transition-all shadow-tactical-card z-20">
        <div className="space-y-6">
          {/* Brand Logo & Identifier */}
          <div className="flex items-center space-x-3 px-1 py-1">
            <div className="w-10 h-10 rounded-xl bg-white/5 border border-border/80 flex items-center justify-center p-1 shrink-0 overflow-hidden shadow-glow-cyan">
              <img src="/logo.png" alt="FisherMail" className="w-full h-full object-contain" />
            </div>
            <div>
              <div className="text-sm font-black tracking-wider text-foreground font-poppins flex items-center gap-1.5">
                FISHERMAIL
                <span className="w-1.5 h-1.5 rounded-full bg-neon-cyan animate-ping inline-block" />
              </div>
              <div className="text-[10px] text-muted font-mono uppercase tracking-widest font-semibold">
                SOC AGENT v0.7.0
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1">
            <button
              onClick={() => setActiveNav('overview')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer font-mono ${
                activeNav === 'overview'
                  ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/40 font-bold shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                  : 'text-muted hover:text-foreground hover:bg-hover-bg font-normal'
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
              </svg>
              <span>01_MISSION_CONTROL</span>
            </button>

            <button
              onClick={() => setActiveNav('stream')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer font-mono ${
                activeNav === 'stream'
                  ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/40 font-bold shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                  : 'text-muted hover:text-foreground hover:bg-hover-bg font-normal'
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              <span>02_LIVE_TELEMETRY</span>
            </button>

            <button
              onClick={() => setActiveNav('incidents')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer font-mono ${
                activeNav === 'incidents'
                  ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/40 font-bold shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                  : 'text-muted hover:text-foreground hover:bg-hover-bg font-normal'
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <span>03_TRIAGE_MATRIX</span>
            </button>

            <button
              onClick={() => setActiveNav('graph')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer font-mono ${
                activeNav === 'graph'
                  ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/40 font-bold shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                  : 'text-muted hover:text-foreground hover:bg-hover-bg font-normal'
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 12l3-3 3 3 4-4M8 21l4-4 4 4M3 4h18M4 4h16v12a1 1 0 01-1 1H5a1 1 0 01-1-1V4z" />
              </svg>
              <span>04_ATTACK_GRAPH</span>
            </button>

            <button
              onClick={() => setActiveNav('surface')}
              className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all cursor-pointer font-mono ${
                activeNav === 'surface'
                  ? 'bg-neon-cyan/10 text-neon-cyan border border-neon-cyan/40 font-bold shadow-[0_0_12px_rgba(0,229,255,0.2)]'
                  : 'text-muted hover:text-foreground hover:bg-hover-bg font-normal'
              }`}
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
              <span>05_EXPOSURE_RADAR</span>
            </button>
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="space-y-4 pt-4 border-t border-border">
          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            className="w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-xs font-medium bg-card border border-border text-muted hover:text-foreground transition shadow-sm cursor-pointer"
          >
            <div className="flex items-center gap-2.5">
              {theme === 'dark' ? (
                <svg className="w-4 h-4 text-neon-amber" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-4 h-4 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
              <span className="font-semibold text-foreground font-poppins">{theme === 'dark' ? 'Tactical Dark' : 'Swiss Light'}</span>
            </div>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-background border border-border font-bold">
              {theme}
            </span>
          </button>

          {/* Analyst Badge */}
          <div className="flex items-center space-x-3 px-1 py-1">
            <div className="w-8 h-8 rounded-xl bg-card border border-border flex items-center justify-center text-xs font-mono font-bold text-foreground">
              SE
            </div>
            <div className="flex-1 truncate text-left">
              <div className="text-xs font-bold text-foreground font-poppins truncate">Seniru Ekanayake</div>
              <div className="text-[10px] text-muted font-mono truncate">Lead SOC Engineer</div>
            </div>
            <span className="w-2 h-2 rounded-full bg-neon-emerald shadow-[0_0_8px_#00ff88]" />
          </div>
        </div>
      </aside>

      {/* 2. Main Work Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        
        {/* Top Header */}
        <header className="h-16 px-8 border-b border-border bg-sidebar/90 backdrop-blur-xl flex items-center justify-between sticky top-0 z-30 shrink-0">
          <div className="flex items-center gap-3 w-96">
            <div className="relative w-full">
              <svg className="w-4 h-4 text-muted absolute left-3.5 top-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search incidents, CVEs, identities..."
                className="w-full bg-background border border-border rounded-xl pl-10 pr-12 py-1.5 text-xs text-foreground placeholder:text-muted focus:outline-none focus:border-neon-cyan transition font-mono"
              />
              <span className="absolute right-3 top-2 text-[10px] font-mono text-muted bg-card px-1.5 py-0.5 rounded border border-border">
                ⌘K
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleRunSimulation}
              disabled={isStreaming}
              className="px-4 py-2 bg-gradient-to-r from-blue-600 to-neon-cyan hover:from-blue-500 hover:to-cyan-300 text-black rounded-xl text-xs font-extrabold shadow-glow-cyan transition-all active:scale-95 flex items-center gap-2 font-mono disabled:opacity-50 cursor-pointer uppercase"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              <span>{isStreaming ? 'STREAMING LANGGRAPH...' : 'EXECUTE MASTER TRIAGE'}</span>
            </button>

            <button
              onClick={() => setApprovalModalOpen(true)}
              className="px-4 py-2 bg-amber-500/10 text-neon-amber border border-amber-500/40 rounded-xl text-xs font-bold transition flex items-center gap-2 font-mono cursor-pointer uppercase"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <span>PENDING AUTHORIZATION (1)</span>
            </button>
          </div>
        </header>

        {/* Content Body */}
        <main className="p-8 space-y-7 max-w-7xl mx-auto w-full">
          
          {/* Header Title Section */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-2xl font-black text-foreground tracking-tight font-poppins">
                Autonomous Security Operations Cockpit
              </h1>
              <p className="text-xs text-muted font-light mt-0.5">
                AI-Native email parsing sandbox, live threat intelligence & shortest-path lateral attack graph
              </p>
            </div>
            
            {/* View Filter Pill */}
            <div className="flex bg-card p-1 rounded-xl border border-border shadow-sm text-xs font-mono self-start">
              <button
                onClick={() => setActiveNav('overview')}
                className={`px-3.5 py-1.5 rounded-lg transition cursor-pointer font-bold ${
                  activeNav === 'overview'
                    ? 'bg-neon-cyan text-black shadow-glow-cyan'
                    : 'text-muted hover:text-foreground'
                }`}
              >
                OVERVIEW
              </button>
              <button
                onClick={() => setActiveNav('stream')}
                className={`px-3.5 py-1.5 rounded-lg transition cursor-pointer font-bold ${
                  activeNav === 'stream'
                    ? 'bg-neon-cyan text-black shadow-glow-cyan'
                    : 'text-muted hover:text-foreground'
                }`}
              >
                TELEMETRY
              </button>
              <button
                onClick={() => setActiveNav('graph')}
                className={`px-3.5 py-1.5 rounded-lg transition cursor-pointer font-bold ${
                  activeNav === 'graph'
                    ? 'bg-neon-cyan text-black shadow-glow-cyan'
                    : 'text-muted hover:text-foreground'
                }`}
              >
                GRAPH
              </button>
              <button
                onClick={() => setActiveNav('surface')}
                className={`px-3.5 py-1.5 rounded-lg transition cursor-pointer font-bold ${
                  activeNav === 'surface'
                    ? 'bg-neon-cyan text-black shadow-glow-cyan'
                    : 'text-muted hover:text-foreground'
                }`}
              >
                EXPOSURE
              </button>
            </div>
          </div>

          {/* 4 Tactical Metric Cards with Rotating Radar Border on Critical Tile */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            
            {/* Card 1: Critical Threat Tile with Rotating Radar Glow */}
            <div className="bg-card border border-border p-5 rounded-2xl shadow-tactical-card space-y-3 relative overflow-hidden radar-border-glow">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase font-mono text-muted tracking-widest">
                  ATTACK SURFACE SCORE
                </span>
                <div className="text-neon-rose drop-shadow-[0_0_8px_rgba(255,0,85,0.6)]">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black font-poppins tracking-tight text-neon-rose">
                  88.4<span className="text-xs font-normal text-muted">/100</span>
                </div>
                <span className="text-[9px] font-mono font-bold text-neon-rose bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/30 uppercase">
                  +12.4% alert
                </span>
              </div>
              <div className="h-7 w-full pt-1">
                <svg className="w-full h-full" viewBox="0 0 120 28" fill="none">
                  <path d="M0 20 Q 30 25, 60 12 T 120 4" stroke="#ff0055" strokeWidth="2" strokeLinecap="round" fill="none" />
                  <path d="M0 20 Q 30 25, 60 12 T 120 4 L 120 28 L 0 28 Z" fill="#ff0055" opacity="0.12" />
                </svg>
              </div>
              <p className="text-[11px] text-muted font-light">Internet-Facing OWA 15.1 Detected</p>
            </div>

            {/* Card 2 */}
            <div className="bg-card border border-border p-5 rounded-2xl shadow-tactical-card space-y-3 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase font-mono text-muted tracking-widest">
                  CAMPAIGN INCIDENTS
                </span>
                <div className="text-neon-amber">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-3xl font-black font-poppins tracking-tight text-neon-amber">
                  500<span className="text-xs font-normal text-muted"> Mails</span>
                </div>
                <span className="text-[9px] font-mono font-bold text-neon-amber bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30 uppercase">
                  Dedup Rollup
                </span>
              </div>
              <div className="h-7 w-full pt-1">
                <svg className="w-full h-full" viewBox="0 0 120 28" fill="none">
                  <path d="M0 14 Q 35 2, 70 18 T 120 8" stroke="#ffaa00" strokeWidth="2" strokeLinecap="round" fill="none" />
                  <path d="M0 14 Q 35 2, 70 18 T 120 8 L 120 28 L 0 28 Z" fill="#ffaa00" opacity="0.12" />
                </svg>
              </div>
              <p className="text-[11px] text-muted font-light">Collapsed to CMP-2024-NTLM-01</p>
            </div>

            {/* Card 3 */}
            <div className="bg-card border border-border p-5 rounded-2xl shadow-tactical-card space-y-3 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase font-mono text-muted tracking-widest">
                  TARGET THREAT VECTOR
                </span>
                <div className="text-neon-cyan">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-2xl font-black font-poppins tracking-tight text-neon-cyan">
                  CVE-2024-21413
                </div>
                <span className="text-[9px] font-mono font-bold text-neon-cyan bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30 uppercase">
                  CVSS 9.8
                </span>
              </div>
              <div className="h-7 w-full pt-1">
                <svg className="w-full h-full" viewBox="0 0 120 28" fill="none">
                  <path d="M0 24 Q 40 8, 80 16 T 120 2" stroke="#00e5ff" strokeWidth="2" strokeLinecap="round" fill="none" />
                  <path d="M0 24 Q 40 8, 80 16 T 120 2 L 120 28 L 0 28 Z" fill="#00e5ff" opacity="0.12" />
                </svg>
              </div>
              <p className="text-[11px] text-muted font-light">Zero-Click Moniker URI Link</p>
            </div>

            {/* Card 4 */}
            <div className="bg-card border border-border p-5 rounded-2xl shadow-tactical-card space-y-3 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase font-mono text-muted tracking-widest">
                  AUTONOMOUS GOVERNANCE
                </span>
                <div className="text-neon-emerald">
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                </div>
              </div>
              <div className="flex items-baseline justify-between">
                <div className="text-2xl font-black font-poppins tracking-tight text-neon-emerald">
                  Level 1 Policy
                </div>
                <span className="text-[9px] font-mono font-bold text-neon-emerald bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30 uppercase">
                  HITL Gate
                </span>
              </div>
              <div className="h-7 w-full pt-1">
                <svg className="w-full h-full" viewBox="0 0 120 28" fill="none">
                  <path d="M0 6 Q 40 18, 80 4 T 120 12" stroke="#00ff88" strokeWidth="2" strokeLinecap="round" fill="none" />
                  <path d="M0 6 Q 40 18, 80 4 T 120 12 L 120 28 L 0 28 Z" fill="#00ff88" opacity="0.12" />
                </svg>
              </div>
              <p className="text-[11px] text-muted font-light">Human Authorization Enforced</p>
            </div>

          </div>

          {/* Navigation Views */}
          {(activeNav === 'overview' || activeNav === 'stream') && (
            <AgentLiveStreamVisualizer
              events={events}
              isStreaming={isStreaming}
              onClear={() => setEvents([])}
            />
          )}

          {(activeNav === 'overview' || activeNav === 'incidents') && (
            <div className="bg-card border border-border rounded-2xl p-6 shadow-tactical-card space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold tracking-wider text-foreground font-mono uppercase">
                    ACTIVE EXPLOITATION INCIDENTS
                  </h3>
                  <p className="text-xs text-muted font-light mt-0.5">
                    Real-time correlation of incoming email, rendering parser anomalies & session compromise
                  </p>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-foreground">
                  <thead className="bg-card-secondary text-muted uppercase font-mono text-[10px] border-b border-border">
                    <tr>
                      <th className="p-3.5">Severity</th>
                      <th className="p-3.5">Incident Title</th>
                      <th className="p-3.5">Target Identity</th>
                      <th className="p-3.5">Mail Platform</th>
                      <th className="p-3.5">Interaction State</th>
                      <th className="p-3.5">Confidence</th>
                      <th className="p-3.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border font-poppins">
                    {incidents.map((inc) => (
                      <tr key={inc.incident_id} className="hover:bg-hover-bg transition-colors">
                        <td className="p-3.5">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(255,0,85,0.2)]">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                            {inc.severity}
                          </span>
                        </td>
                        <td className="p-3.5 font-semibold text-foreground">
                          {inc.title}
                          <span className="block text-[10px] text-neon-cyan font-mono mt-0.5 font-normal">{inc.cve}</span>
                        </td>
                        <td className="p-3.5 font-mono text-foreground font-medium">{inc.target_identity}</td>
                        <td className="p-3.5 text-muted font-light">{inc.mail_platform}</td>
                        <td className="p-3.5 font-bold text-neon-rose font-mono text-[11px]">{inc.interaction_required}</td>
                        <td className="p-3.5 font-mono text-neon-emerald font-bold">
                          {(inc.confidence * 100).toFixed(0)}%
                        </td>
                        <td className="p-3.5 text-right">
                          <button
                            onClick={() => setSelectedIncident(inc)}
                            className="px-3.5 py-1.5 bg-card border border-border hover:bg-hover-bg text-foreground rounded-xl text-xs font-bold transition cursor-pointer font-mono"
                          >
                            INVESTIGATE
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {(activeNav === 'overview' || activeNav === 'graph') && (
            <AttackGraphVisualizer />
          )}

          {(activeNav === 'overview' || activeNav === 'surface') && (
            <ExposureView />
          )}
        </main>
      </div>

      {/* Forensic Detail Slide-over Drawer */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onApprove={(token) => {
            setApprovalModalOpen(true);
          }}
        />
      )}

      {/* Human Approval Gate Modal */}
      <HumanApprovalModal
        proposal={pendingProposal}
        isOpen={approvalModalOpen}
        onClose={() => setApprovalModalOpen(false)}
        onApprove={async (token, comments) => {
          return { success: true, audit_id: 'AUD-948201' };
        }}
        onReject={async (token, reason) => {
          return { success: true };
        }}
      />
    </div>
  );
}
