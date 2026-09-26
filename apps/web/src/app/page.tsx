'use client';

import React, { useState } from 'react';
import { AgentLiveStreamVisualizer, StreamEvent } from '@/components/AgentLiveStreamVisualizer';
import { AttackGraphVisualizer } from '@/components/AttackGraphVisualizer';
import { IncidentDetailModal } from '@/components/IncidentDetailModal';
import { HumanApprovalModal, PendingActionProposal } from '@/components/HumanApprovalModal';
import { ExposureView } from '@/components/ExposureView';

export default function DashboardPage() {
  const [activeNav, setActiveNav] = useState<'overview' | 'mailbox' | 'investigations' | 'agents' | 'policies' | 'reports' | 'settings'>('overview');
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [investigationDrawerOpen, setInvestigationDrawerOpen] = useState(false);

  // SSE Stream Simulation State
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

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

  const investigations = [
    {
      incident_id: 'INC-849201',
      sender: 'accounts@micros0ft-support.com',
      subject: 'Password reset required — action needed',
      verdict: 'Malicious',
      verdict_type: 'critical',
      confidence: '99.8%',
      agents_path: '4 agents',
      time: '2m ago',
      title: 'Outlook Moniker Link Forced NTLM Relay',
      severity: 'CRITICAL',
      overall_risk_score: 96.8,
      target_identity: 'cfo@enterprise-corp.internal',
      mail_platform: 'Microsoft Exchange / OWA 15.1',
      exposure_status: 'KNOWN_EXPLOITABLE',
      interaction_required: 'VIEW (Zero-Click Preview)',
      cve: 'CVE-2024-21413',
      evidence_summary: [
        'Detected search-ms moniker link bypass (CVE-2024-21413) forcing NTLM relay over SMB port 445.',
        'Sender domain micros0ft-support.com failed SPF (-all) and DMARC (p=reject).',
        'Payload contains deceptive URI schema with Unicode Right-to-Left Override (RTLO).',
        'Target mailbox belongs to Tier-0 VIP Identity (Chief Financial Officer).',
      ],
      mitre_techniques: [
        { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1204.001', name: 'Malicious Link', tactic: 'Execution' },
        { id: 'T1187', name: 'Forced Authentication', tactic: 'Credential Access' },
      ],
      attack_chain: [
        { step: 1, node: 'ThreatActor (FIN7)', type: 'actor' },
        { step: 2, node: 'Campaign (Operation Blindside)', type: 'campaign' },
        { step: 3, node: 'EmailMessage (CVE-2024-21413)', type: 'email' },
        { step: 4, node: 'Vulnerability (CVE-2024-21413)', type: 'cve' },
        { step: 5, node: 'Asset (Exchange OWA 15.1)', type: 'asset' },
        { step: 6, node: 'Identity (cfo@enterprise-corp.internal)', type: 'identity' },
      ],
      recommended_actions: [
        { name: 'Quarantine Email', risk: 'MEDIUM', automated: true },
        { name: 'Revoke Active Webmail Session', risk: 'HIGH', automated: false, requires_approval: true },
        { name: 'Block IP on Edge Gateway', risk: 'HIGH', automated: false, requires_approval: true },
      ],
    },
    {
      incident_id: 'INC-849195',
      sender: 'david@partner-payments.co',
      subject: 'Updated invoice #48291',
      verdict: 'Suspicious',
      verdict_type: 'review',
      confidence: '94.1%',
      agents_path: '3 agents',
      time: '11m ago',
      title: 'Polymorphic BEC Wire Fraud Attempt',
      severity: 'HIGH',
      overall_risk_score: 74.2,
      target_identity: 'finance-lead@enterprise-corp.internal',
      mail_platform: 'Google Workspace',
      exposure_status: 'ASSET_EXPOSED',
      interaction_required: 'CLICK',
      cve: 'N/A (Social Engineering)',
      evidence_summary: [
        'Domain partner-payments.co registered 3 days ago via anonymous registrar.',
        'Banking wire instructions altered compared to historical vendor communications.',
        'DKIM signature passed but domain alignment failed.',
      ],
      mitre_techniques: [
        { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
        { id: 'T1589', name: 'Gather Victim Identity Info', tactic: 'Reconnaissance' },
      ],
      attack_chain: [
        { step: 1, node: 'ThreatActor (Unknown BEC)', type: 'actor' },
        { step: 2, node: 'EmailMessage (Invoice #48291)', type: 'email' },
        { step: 3, node: 'Identity (finance-lead@enterprise-corp.internal)', type: 'identity' },
      ],
      recommended_actions: [
        { name: 'Flag External Warning Banner', risk: 'LOW', automated: true },
        { name: 'Place Message in Hold Queue', risk: 'MEDIUM', automated: true },
      ],
    },
    {
      incident_id: 'INC-849182',
      sender: 'hr@acme-corp.com',
      subject: 'Benefits enrollment window',
      verdict: 'Benign',
      verdict_type: 'clean',
      confidence: '99.9%',
      agents_path: '2 agents',
      time: '18m ago',
      title: 'Internal Corporate Communication',
      severity: 'LOW',
      overall_risk_score: 4.1,
      target_identity: 'all-employees@acme-corp.com',
      mail_platform: 'Microsoft 365 Exchange Online',
      exposure_status: 'PROTECTED',
      interaction_required: 'NONE',
      cve: 'None',
      evidence_summary: [
        'Internal email matching registered corporate SPF, DKIM, and DMARC records.',
        'Links point exclusively to approved enterprise HR portal (https://hr.acme-corp.com).',
        'Zero behavioral anomalies or obfuscated scripts observed in DOM analysis.',
      ],
      mitre_techniques: [],
      attack_chain: [],
      recommended_actions: [
        { name: 'Allow Delivery to Inbox', risk: 'LOW', automated: true },
      ],
    },
    {
      incident_id: 'INC-849170',
      sender: 'ceo-office@securemail.cc',
      subject: 'Urgent: confidential transfer',
      verdict: 'Malicious',
      verdict_type: 'critical',
      confidence: '98.7%',
      agents_path: '4 agents',
      time: '24m ago',
      title: 'Executive VIP Impersonation & Wire Divert',
      severity: 'CRITICAL',
      overall_risk_score: 93.5,
      target_identity: 'treasury@enterprise-corp.internal',
      mail_platform: 'Microsoft Exchange On-Prem',
      exposure_status: 'KNOWN_EXPLOITABLE',
      interaction_required: 'MULTI_STEP',
      cve: 'CVE-2023-35636',
      evidence_summary: [
        'Display name spoofing CEO Identity with external disposable domain securemail.cc.',
        'High urgency markers detected in semantic NLP analysis.',
        'Attempts to bypass dual-authorization financial workflows.',
      ],
      mitre_techniques: [
        { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' },
        { id: 'T1656', name: 'Impersonation', tactic: 'Defense Evasion' },
      ],
      attack_chain: [
        { step: 1, node: 'ThreatActor (Scattered Spider)', type: 'actor' },
        { step: 2, node: 'EmailMessage (Confidential Transfer)', type: 'email' },
        { step: 3, node: 'Identity (treasury@enterprise-corp.internal)', type: 'identity' },
      ],
      recommended_actions: [
        { name: 'Quarantine Email', risk: 'MEDIUM', automated: true },
        { name: 'Notify Security Operations Desk', risk: 'LOW', automated: true },
      ],
    },
  ];

  const handleStartStream = () => {
    setIsStreaming(true);
    setEvents([]);
    setInvestigationDrawerOpen(true);

    const streamScenario: StreamEvent[] = [
      {
        event_type: 'stage_start',
        stage: 'INGESTION',
        message: 'Ingesting suspicious inbound RFC 2822 payload (Message-ID: <20240926.exploit.moniker@corporate-updates.net>)...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'thought',
        stage: 'INGESTION',
        message: 'Data privacy evaluation: Payload classified as CONFIDENTIAL. Scrubbing internal credentials and routing to deterministic boundaries.',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'stage_start',
        stage: 'ANALYSIS',
        message: 'MIME Parser & HTML Analyzer inspecting nested attachments and active tags...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'skill_activated',
        stage: 'ANALYSIS',
        message: 'Forensic Skill Activated: "moniker-link-exploit-triage" (Matched file:// search-ms schema pattern).',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'stage_start',
        stage: 'VULN_RESEARCH',
        message: 'Querying CISA KEV & NVD for CVE-2024-21413 and correlating with MITRE ATT&CK T1566.002...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'evidence',
        stage: 'VULN_RESEARCH',
        message: 'Confirmed High-Exploitability Zero-Click MonikerLink Vulnerability (CVSS 9.8). Forced NTLM credential theft via SMB callback.',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'stage_start',
        stage: 'EXPOSURE',
        message: 'Correlating with on-prem Exchange OWA mail server at owa.enterprise-corp.internal...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'thought',
        stage: 'EXPOSURE',
        message: 'Attack Surface Status: KNOWN_EXPLOITABLE (Unpatched Microsoft Outlook / OWA 15.1 build).',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'stage_start',
        stage: 'INVESTIGATION',
        message: 'Reconstructing Neo4j lateral movement attack chain: Threat Actor (FIN7) ➔ Campaign ➔ CFO Mailbox.',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'stage_start',
        stage: 'RESPONSE',
        message: 'Evaluating tenant autonomy policy (Level 1: Human Approved). Proposing containment actions...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'proposal',
        stage: 'RESPONSE',
        message: 'Gated Action Proposal: quarantine_email_and_revoke_session (Token: APP-8E2F9A). Awaiting human slide authorization.',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'complete',
        stage: 'RESPONSE',
        message: 'Autonomous triage completed in 1.42s. Awaiting SOC Analyst authorization.',
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
      }, (idx + 1) * 600);
    });
  };

  return (
    <div className="flex min-h-screen bg-[#f7f8fa] text-[#111318]">
      
      {/* 1. Left Fixed Sidebar */}
      <aside className="w-[236px] bg-white border-r border-[#e7e9ee] p-[22px_14px] fixed inset-y-0 left-0 z-30 flex flex-col justify-between">
        <div>
          {/* Brand */}
          <div className="flex items-center gap-2.5 px-2.5 pb-6">
            <div className="w-[30px] h-[30px] rounded-[9px] bg-[#111318] grid place-items-center text-white text-sm font-extrabold overflow-hidden">
              <img src="/logo.png" alt="F" className="w-full h-full object-contain p-0.5" onError={(e) => { e.currentTarget.style.display = 'none'; }} />
            </div>
            <strong className="text-[16px] tracking-[-0.04em] font-bold">
              Fishing<span className="text-[#9aa0aa] font-normal">Mails</span>
            </strong>
          </div>

          {/* Workspace Nav Section */}
          <div className="text-[10px] uppercase text-[#a0a5af] font-bold px-[11px] pt-[13px] pb-[7px] tracking-[0.1em]">
            Workspace
          </div>
          <nav className="space-y-0.5">
            <button
              onClick={() => setActiveNav('overview')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'overview'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">⌂</span>
              <span>Overview</span>
            </button>

            <button
              onClick={() => setActiveNav('mailbox')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'mailbox'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">✉</span>
              <span>Mailbox</span>
            </button>

            <button
              onClick={() => setActiveNav('investigations')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'investigations'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">◉</span>
              <span>Investigations</span>
            </button>

            <button
              onClick={() => setActiveNav('agents')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'agents'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">✦</span>
              <span>Agents</span>
            </button>

            <button
              onClick={() => setActiveNav('policies')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'policies'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">⊞</span>
              <span>Policies</span>
            </button>

            <button
              onClick={() => setActiveNav('reports')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'reports'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">▤</span>
              <span>Reports</span>
            </button>
          </nav>

          {/* System Nav Section */}
          <div className="text-[10px] uppercase text-[#a0a5af] font-bold px-[11px] pt-[13px] pb-[7px] tracking-[0.1em]">
            System
          </div>
          <nav className="space-y-0.5">
            <button
              onClick={() => setActiveNav('settings')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'settings'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">⚙</span>
              <span>Settings</span>
            </button>
          </nav>
        </div>

        {/* Bottom Workspace Badge */}
        <div className="border-t border-[#e7e9ee] pt-3.5">
          <div className="flex items-center gap-2.5 px-2.5 py-2">
            <div className="w-7 h-7 rounded-full bg-[#e9edf3] grid place-items-center text-[10px] font-bold text-[#111318]">
              AC
            </div>
            <div className="flex-1 truncate text-left">
              <b className="text-xs text-[#111318] block leading-tight">Acme Corp</b>
              <small className="text-[10px] text-[#737986] block leading-tight">Enterprise workspace</small>
            </div>
            <span className="text-[#aaa] text-xs cursor-pointer">⋯</span>
          </div>
        </div>
      </aside>

      {/* 2. Main Content Area */}
      <main className="ml-[236px] w-[calc(100%-236px)] p-[30px_36px_44px] max-w-[1600px]">
        
        {/* Header */}
        <header className="flex items-start justify-between mb-7">
          <div>
            <div className="text-xs text-[#737986] mb-1.5 font-medium">Saturday, September 26, 2026</div>
            <h1 className="text-[27px] font-bold tracking-[-0.04em] m-0 text-[#111318]">Threat Operations</h1>
            <div className="text-[13px] text-[#737986] mt-1.5 font-normal">Autonomous protection across your organization's email surface.</div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setActiveNav('reports')}
              className="border border-[#e7e9ee] bg-white px-3 py-2.5 rounded-lg text-xs font-medium text-[#535963] shadow-[0_1px_1px_rgba(0,0,0,0.02)] hover:bg-[#f7f8fa] transition cursor-pointer"
            >
              Export report
            </button>
            <button
              onClick={handleStartStream}
              className="bg-[#111318] text-white border border-[#111318] px-3 py-2.5 rounded-lg text-xs font-semibold shadow-sm hover:bg-[#252830] transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+ Investigate email</span>
            </button>
          </div>
        </header>

        {/* Conditional Views or Overview Dashboard */}
        {activeNav === 'agents' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold">Autonomous Multi-Agent Telemetry</h2>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AgentLiveStreamVisualizer events={events} isStreaming={isStreaming} onStartScenario={handleStartStream} />
          </div>
        ) : activeNav === 'policies' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold">Autonomous Response Governance & Policies</h2>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <ExposureView />
          </div>
        ) : activeNav === 'reports' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold">Attack Graph & Lateral Movement Pathfinding</h2>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AttackGraphVisualizer onSelectAttackChain={() => {}} />
          </div>
        ) : (
          <>
            {/* Top Metrics Row */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-3.5">
              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Emails analyzed</span>
                  <span>24h</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">2,481</div>
                <div className="text-[11px] text-[#16945b] font-medium">↑ 18.4% vs. yesterday</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Threats detected</span>
                  <span>24h</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">37</div>
                <div className="text-[11px] text-[#16945b] font-medium">↑ 6.2% vs. yesterday</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Active investigations</span>
                  <span>Now</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">12</div>
                <div className="text-[11px] text-[#737986] font-medium">4 awaiting review</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Detection confidence</span>
                  <span>30d</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">99.2%</div>
                <div className="text-[11px] text-[#16945b] font-medium">↑ 0.8% this month</div>
              </div>
            </section>

            {/* Middle Grid: Activity Chart & Agent Status */}
            <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.75fr)_minmax(300px,0.75fr)] gap-3.5 mb-3.5">
              
              {/* Agentic Detection Activity Chart */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div>
                    <div className="text-[13px] font-bold text-[#111318]">Agentic Detection Activity</div>
                    <div className="text-[11px] text-[#737986] mt-1">Continuous autonomous investigation · last 24 hours</div>
                  </div>
                  <div className="inline-flex items-center gap-1.5 text-[10px] text-[#16945b] font-[650] bg-[#eaf8f1] px-2 py-1 rounded-full">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#16945b] animate-pulse"></span>
                    <span>Agents active</span>
                  </div>
                </div>

                <div className="p-[10px_18px_15px]">
                  <div className="h-[205px] relative overflow-hidden">
                    <svg viewBox="0 0 800 210" preserveAspectRatio="none" className="w-full h-full">
                      <g stroke="#eef0f3" strokeWidth="1">
                        <line x1="0" y1="35" x2="800" y2="35" />
                        <line x1="0" y1="82" x2="800" y2="82" />
                        <line x1="0" y1="129" x2="800" y2="129" />
                        <line x1="0" y1="176" x2="800" y2="176" />
                      </g>
                      {/* Active Investigations Solid Blue Path */}
                      <path
                        d="M0 170 C35 166 40 148 72 153 S110 130 142 142 S180 111 214 126 S253 83 286 104 S320 91 352 99 S390 69 425 88 S465 54 500 77 S538 65 570 72 S606 40 640 59 S680 46 710 55 S754 28 800 39"
                        fill="none"
                        stroke="#2563eb"
                        strokeWidth="2.5"
                      />
                      {/* Baseline Dashed Path */}
                      <path
                        d="M0 192 C50 186 80 188 120 178 S180 182 220 166 S285 172 320 157 S385 165 420 145 S470 153 510 138 S570 143 610 126 S675 132 715 110 S765 116 800 94"
                        fill="none"
                        stroke="#b9c2d2"
                        strokeWidth="1.5"
                        strokeDasharray="5 5"
                      />
                      {/* Glowing Current Point */}
                      <circle cx="640" cy="59" r="4.5" fill="#fff" stroke="#2563eb" strokeWidth="2" />
                    </svg>
                  </div>
                  <div className="flex gap-4 text-[10px] text-[#737986] px-1 font-medium items-center">
                    <span className="flex items-center">
                      <span className="w-[7px] h-[7px] rounded-full inline-block mr-1.5 bg-[#2563eb]"></span>
                      Investigations
                    </span>
                    <span className="flex items-center">
                      <span className="w-[7px] h-[7px] rounded-full inline-block mr-1.5 bg-[#b9c2d2]"></span>
                      Baseline
                    </span>
                    <span className="ml-auto text-[#9aa0aa] font-mono">
                      00:00 &nbsp;&nbsp; 06:00 &nbsp;&nbsp; 12:00 &nbsp;&nbsp; 18:00 &nbsp;&nbsp; Now
                    </span>
                  </div>
                </div>
              </div>

              {/* Agent Status Card */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Agent Status</div>
                  <div className="text-[11px] text-[#737986] font-medium">4 / 4 online</div>
                </div>
                <div className="py-1.5 divide-y divide-[#f0f1f3]">
                  <div className="flex items-center gap-3 px-[18px] py-3.5">
                    <div className="w-[30px] h-[30px] rounded-lg bg-[#f4f5f7] grid place-items-center text-[13px] font-bold text-[#111318]">
                      ⌁
                    </div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Recon Agent</b>
                      <span className="text-[10px] text-[#737986]">Headers · URLs · infrastructure</span>
                    </div>
                    <span className="text-[10px] px-2 py-1 rounded-full bg-[#eaf8f1] text-[#16945b] font-[650]">
                      Operational
                    </span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-3.5">
                    <div className="w-[30px] h-[30px] rounded-lg bg-[#f4f5f7] grid place-items-center text-[13px] font-bold text-[#111318]">
                      ◌
                    </div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Intent Agent</b>
                      <span className="text-[10px] text-[#737986]">Context · social engineering</span>
                    </div>
                    <span className="text-[10px] px-2 py-1 rounded-full bg-[#eaf8f1] text-[#16945b] font-[650]">
                      Operational
                    </span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-3.5">
                    <div className="w-[30px] h-[30px] rounded-lg bg-[#f4f5f7] grid place-items-center text-[13px] font-bold text-[#111318]">
                      ◇
                    </div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Threat Intel Agent</b>
                      <span className="text-[10px] text-[#737986]">IOC enrichment · reputation</span>
                    </div>
                    <span className="text-[10px] px-2 py-1 rounded-full bg-[#eaf8f1] text-[#16945b] font-[650]">
                      Operational
                    </span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-3.5">
                    <div className="w-[30px] h-[30px] rounded-lg bg-[#f4f5f7] grid place-items-center text-[13px] font-bold text-[#111318]">
                      ↗
                    </div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Response Agent</b>
                      <span className="text-[10px] text-[#737986]">Containment · remediation</span>
                    </div>
                    <span className="text-[10px] px-2 py-1 rounded-full bg-[#f3f4f6] text-[#727782] font-[650]">
                      Standby
                    </span>
                  </div>
                </div>
              </div>
            </section>

            {/* Bottom Grid: Recent Investigations Table & Threat Queue */}
            <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.75fr)_minmax(300px,0.75fr)] gap-3.5">
              
              {/* Recent Investigations Table */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)] overflow-hidden">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Recent Investigations</div>
                  <button
                    onClick={() => setActiveNav('investigations')}
                    className="border border-[#e7e9ee] bg-white px-2.5 py-1.5 rounded-lg text-xs font-medium text-[#535963] hover:bg-[#f7f8fa] transition cursor-pointer"
                  >
                    View all
                  </button>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr className="bg-[#fafbfc] border-b border-[#e7e9ee]">
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Sender / subject
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Verdict
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Confidence
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Agent path
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Time
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#e7e9ee]">
                      {investigations.map((item, idx) => (
                        <tr
                          key={idx}
                          onClick={() => setSelectedIncident(item)}
                          className="hover:bg-[#f8fafc] transition-colors cursor-pointer"
                        >
                          <td className="p-[13px_17px]">
                            <span className="font-[650] text-[#20232a] text-[11px] block">{item.sender}</span>
                            <small className="block text-[#989da7] font-normal text-[10px] mt-0.5">{item.subject}</small>
                          </td>
                          <td className="p-[13px_17px]">
                            {item.verdict_type === 'critical' ? (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#fff0f0] text-[#d04444]">
                                {item.verdict}
                              </span>
                            ) : item.verdict_type === 'review' ? (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#fff7e7] text-[#b7791f]">
                                {item.verdict}
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#eaf8f1] text-[#16945b]">
                                {item.verdict}
                              </span>
                            )}
                          </td>
                          <td className="p-[13px_17px] text-[11px] font-medium text-[#505660]">{item.confidence}</td>
                          <td className="p-[13px_17px] text-[11px] font-medium text-[#505660]">{item.agents_path}</td>
                          <td className="p-[13px_17px] text-[11px] text-[#737986]">{item.time}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Threat Queue Card */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)] pb-2">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Threat Queue</div>
                  <div className="text-[11px] text-[#737986] font-medium">12 active</div>
                </div>
                <div className="divide-y divide-[#e7e9ee]">
                  <div className="flex items-center gap-3 p-[12px_18px]">
                    <div className="text-[15px] font-bold text-[#111318] w-6">04</div>
                    <div className="flex-1">
                      <b className="text-[11px] text-[#111318] block">Credential harvesting</b>
                      <span className="text-[10px] text-[#737986]">Awaiting response agent</span>
                    </div>
                    <div className="h-1 w-[60px] rounded-full bg-[#e9ebef] overflow-hidden">
                      <div className="h-full bg-[#2563eb]" style={{ width: '86%' }}></div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 p-[12px_18px]">
                    <div className="text-[15px] font-bold text-[#111318] w-6">03</div>
                    <div className="flex-1">
                      <b className="text-[11px] text-[#111318] block">Business email compromise</b>
                      <span className="text-[10px] text-[#737986]">Under investigation</span>
                    </div>
                    <div className="h-1 w-[60px] rounded-full bg-[#e9ebef] overflow-hidden">
                      <div className="h-full bg-[#2563eb]" style={{ width: '64%' }}></div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 p-[12px_18px]">
                    <div className="text-[15px] font-bold text-[#111318] w-6">03</div>
                    <div className="flex-1">
                      <b className="text-[11px] text-[#111318] block">Malicious attachment</b>
                      <span className="text-[10px] text-[#737986]">Awaiting analyst review</span>
                    </div>
                    <div className="h-1 w-[60px] rounded-full bg-[#e9ebef] overflow-hidden">
                      <div className="h-full bg-[#2563eb]" style={{ width: '41%' }}></div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 p-[12px_18px]">
                    <div className="text-[15px] font-bold text-[#111318] w-6">02</div>
                    <div className="flex-1">
                      <b className="text-[11px] text-[#111318] block">Identity impersonation</b>
                      <span className="text-[10px] text-[#737986]">Enrichment in progress</span>
                    </div>
                    <div className="h-1 w-[60px] rounded-full bg-[#e9ebef] overflow-hidden">
                      <div className="h-full bg-[#2563eb]" style={{ width: '28%' }}></div>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </>
        )}
      </main>

      {/* 3. Interactive Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onTriggerContainment={() => {
            setSelectedIncident(null);
            setApprovalModalOpen(true);
          }}
        />
      )}

      {/* 4. Slide-to-Authorize Human Approval Modal */}
      <HumanApprovalModal
        isOpen={approvalModalOpen}
        onClose={() => setApprovalModalOpen(false)}
        proposal={pendingProposal}
        onApprove={() => {
          alert('Action Authorized! Email quarantined and CFO active sessions revoked successfully.');
          setApprovalModalOpen(false);
        }}
      />

      {/* 5. Live Stream Simulation Slide-over Modal */}
      {investigationDrawerOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-white h-full shadow-2xl p-6 overflow-y-auto flex flex-col">
            <div className="flex items-center justify-between pb-4 border-b border-[#e7e9ee] mb-4">
              <div>
                <h3 className="text-base font-bold text-[#111318]">Live Autonomous Investigation</h3>
                <p className="text-xs text-[#737986]">Real-time LangGraph multi-agent reasoning stream</p>
              </div>
              <button
                onClick={() => setInvestigationDrawerOpen(false)}
                className="text-[#737986] hover:text-[#111318] p-1 rounded-lg hover:bg-[#f2f4f7]"
              >
                ✕
              </button>
            </div>
            
            <div className="flex-1">
              <AgentLiveStreamVisualizer events={events} isStreaming={isStreaming} onStartScenario={handleStartStream} />
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
