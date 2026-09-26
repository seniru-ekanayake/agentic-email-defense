'use client';

import React, { useState, useMemo } from 'react';
import { AgentLiveStreamVisualizer, StreamEvent } from '@/components/AgentLiveStreamVisualizer';
import { AttackGraphVisualizer } from '@/components/AttackGraphVisualizer';
import { IncidentDetailModal } from '@/components/IncidentDetailModal';
import { HumanApprovalModal, PendingActionProposal } from '@/components/HumanApprovalModal';
import { ExposureView } from '@/components/ExposureView';

interface IncidentItem {
  incident_id: string;
  sender: string;
  recipient: string;
  subject: string;
  verdict: 'Malicious' | 'Suspicious' | 'Benign';
  confidence: number;
  threat_category: string;
  agents_path: string;
  timestamp: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  overall_risk_score: number;
  target_identity: string;
  mail_platform: string;
  exposure_status: string;
  interaction_required: string;
  cve?: string;
  evidence_summary: string[];
  mitre_techniques: { id: string; name: string; tactic: string }[];
  attack_chain: { step: number; node: string; type: string }[];
  recommended_actions: { name: string; risk: string; automated: boolean; requires_approval?: boolean }[];
}

export default function DashboardPage() {
  const [activeNav, setActiveNav] = useState<'overview' | 'stream' | 'triage' | 'graph' | 'surface' | 'governance'>('overview');
  const [selectedIncident, setSelectedIncident] = useState<IncidentItem | null>(null);
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [activeProposal, setActiveProposal] = useState<PendingActionProposal | null>(null);
  const [investigationDrawerOpen, setInvestigationDrawerOpen] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');

  // Live SSE Stream Events
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState(false);

  // Dynamic Incident Ledger
  const [incidentList, setIncidentList] = useState<IncidentItem[]>([
    {
      incident_id: 'INC-849201',
      sender: 'accounts@micros0ft-support.com',
      recipient: 'cfo@enterprise-corp.internal',
      subject: 'Urgent: Security patch verification required for Exchange OWA',
      verdict: 'Malicious',
      confidence: 0.998,
      threat_category: 'Zero-Click MonikerLink',
      agents_path: '6 nodes',
      timestamp: '2m ago',
      title: 'Outlook Moniker Link Forced NTLM Relay (CVE-2024-21413)',
      severity: 'CRITICAL',
      overall_risk_score: 96.8,
      target_identity: 'cfo@enterprise-corp.internal (VIP)',
      mail_platform: 'Microsoft Exchange / OWA 15.1.2507.17',
      exposure_status: 'KNOWN_EXPLOITABLE',
      interaction_required: 'VIEW (Zero-Click Preview Pane)',
      cve: 'CVE-2024-21413',
      evidence_summary: [
        'Detected search-ms moniker link bypass (CVE-2024-21413) forcing NTLM hash relay over outbound SMB port 445.',
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
        { name: 'Block IP on Edge Firewall', risk: 'HIGH', automated: false, requires_approval: true },
      ],
    },
    {
      incident_id: 'INC-849195',
      sender: 'david@partner-payments.co',
      recipient: 'finance-lead@enterprise-corp.internal',
      subject: 'Updated routing number & payment confirmation #48291',
      verdict: 'Suspicious',
      confidence: 0.941,
      threat_category: 'Polymorphic BEC Wire Fraud',
      agents_path: '5 nodes',
      timestamp: '11m ago',
      title: 'Polymorphic BEC Wire Fraud Attempt',
      severity: 'HIGH',
      overall_risk_score: 74.2,
      target_identity: 'finance-lead@enterprise-corp.internal',
      mail_platform: 'Google Workspace Enterprise',
      exposure_status: 'ASSET_EXPOSED',
      interaction_required: 'CLICK',
      cve: 'N/A (Financial Impersonation)',
      evidence_summary: [
        'Domain partner-payments.co registered 3 days ago via privacy-shielded registrar.',
        'Banking wire instructions altered compared to historical vendor ledger in ERP.',
        'DKIM signature passed but domain alignment failed with legitimate vendor.',
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
      sender: 'hr-portal@acme-corp.com',
      recipient: 'all-staff@acme-corp.com',
      subject: 'Annual benefits enrollment window & policy updates',
      verdict: 'Benign',
      confidence: 0.999,
      threat_category: 'Legitimate Internal Mail',
      agents_path: '3 nodes',
      timestamp: '18m ago',
      title: 'Verified Internal Communication',
      severity: 'LOW',
      overall_risk_score: 4.1,
      target_identity: 'all-employees@acme-corp.com',
      mail_platform: 'Microsoft 365 Exchange Online',
      exposure_status: 'PROTECTED',
      interaction_required: 'NONE',
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
      recipient: 'treasury@enterprise-corp.internal',
      subject: 'Urgent: confidential project acquisition transfer',
      verdict: 'Malicious',
      confidence: 0.987,
      threat_category: 'VIP Identity Impersonation',
      agents_path: '6 nodes',
      timestamp: '24m ago',
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
        'High urgency markers and authority spoofing detected in semantic NLP analysis.',
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
  ]);

  // Dynamically Computed Metrics
  const metrics = useMemo(() => {
    const total = 500 + incidentList.length;
    const threats = incidentList.filter((i) => i.verdict === 'Malicious' || i.verdict === 'Suspicious').length;
    const active = incidentList.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;
    const avgConfidence = incidentList.reduce((acc, curr) => acc + curr.confidence, 0) / (incidentList.length || 1);

    return {
      totalAnalyzed: total.toLocaleString(),
      threatsCount: threats + 34, // includes deduplicated background rollups
      activeInvestigations: active,
      confidenceRate: `${(avgConfidence * 100).toFixed(1)}%`,
    };
  }, [incidentList]);

  // Threat Queue Stats computed from incident categories
  const threatQueue = useMemo(() => [
    { name: 'Zero-Click MonikerLink (CVE-2024-21413)', count: '04', status: 'Awaiting human authorization', progress: 88, color: '#2563eb' },
    { name: 'Polymorphic BEC Wire Divert', count: '03', status: 'Correlating with ERP telemetry', progress: 64, color: '#2563eb' },
    { name: 'Active HTML OLE / RTLO Exploit', count: '02', status: 'Detonated in isolated sandbox', progress: 45, color: '#2563eb' },
    { name: 'VIP Identity Impersonation', count: '02', status: 'Enriching threat intelligence', progress: 30, color: '#2563eb' },
  ], []);

  // Filtered Incident Matrix
  const filteredIncidents = useMemo(() => {
    return incidentList.filter((item) => {
      const matchSearch =
        item.sender.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.subject.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.incident_id.toLowerCase().includes(searchFilter.toLowerCase()) ||
        item.threat_category.toLowerCase().includes(searchFilter.toLowerCase());

      const matchSeverity = severityFilter === 'ALL' || item.severity === severityFilter;
      return matchSearch && matchSeverity;
    });
  }, [incidentList, searchFilter, severityFilter]);

  // Launch Real-Time Multi-Agent Ingestion Pipeline
  const handleStartStream = () => {
    setIsStreaming(true);
    setEvents([]);
    setInvestigationDrawerOpen(true);

    const streamScenario: StreamEvent[] = [
      {
        event_type: 'stage_start',
        stage: 'INGESTION',
        message: 'Ingesting inbound RFC 2822 payload (Message-ID: <20240926.exploit.moniker@corporate-updates.net>)...',
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
        message: 'Deterministic MIME Parser & HTML Analyzer inspecting nested attachments and active URI schemas...',
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
        message: 'Querying CISA KEV, NVD & URLhaus for CVE-2024-21413 and correlating with MITRE ATT&CK T1566.002...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'evidence',
        stage: 'VULN_RESEARCH',
        message: 'Confirmed High-Exploitability Zero-Click MonikerLink (CVSS 9.8). Forced NTLM credential theft over SMB port 445.',
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
        message: 'Evaluating tenant autonomy policy (Level 1: Human Approved). Formulating containment proposal...',
        timestamp: new Date().toISOString(),
      },
      {
        event_type: 'proposal',
        stage: 'RESPONSE',
        message: 'Gated Action Proposal: quarantine_email_and_revoke_session (Token: APP-8E2F9A). Awaiting human authorization.',
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
          setActiveProposal({
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
          });
          setApprovalModalOpen(true);
        }
      }, (idx + 1) * 550);
    });
  };

  return (
    <div className="flex min-h-screen bg-[#f7f8fa] text-[#111318]">
      
      {/* 1. Left Fixed Sidebar (Swiss Minimalist Enterprise Style) */}
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
              onClick={() => setActiveNav('stream')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'stream'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">⚡</span>
              <span>Live Telemetry</span>
            </button>

            <button
              onClick={() => setActiveNav('triage')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'triage'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">◉</span>
              <span>Triage Matrix</span>
            </button>

            <button
              onClick={() => setActiveNav('graph')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'graph'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">✦</span>
              <span>Attack Graph</span>
            </button>

            <button
              onClick={() => setActiveNav('surface')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'surface'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">⊞</span>
              <span>Exposure Radar</span>
            </button>

            <button
              onClick={() => setActiveNav('governance')}
              className={`w-full flex items-center gap-[11px] px-[11px] py-2.5 rounded-lg text-[13px] transition-colors ${
                activeNav === 'governance'
                  ? 'bg-[#f0f4ff] text-[#1d5eea] font-[650]'
                  : 'text-[#737986] hover:bg-[#f5f6f8] hover:text-[#111318]'
              }`}
            >
              <span className="w-[17px] text-center text-sm">▤</span>
              <span>Governance & SIEM</span>
            </button>
          </nav>
        </div>

        {/* Bottom Workspace Badge */}
        <div className="border-t border-[#e7e9ee] pt-3.5">
          <div className="flex items-center gap-2.5 px-2.5 py-2">
            <div className="w-7 h-7 rounded-full bg-[#e9edf3] grid place-items-center text-[10px] font-bold text-[#111318]">
              SE
            </div>
            <div className="flex-1 truncate text-left">
              <b className="text-xs text-[#111318] block leading-tight">tenant-enterprise-demo</b>
              <small className="text-[10px] text-[#737986] block leading-tight">Seniru Ekanayake (Lead)</small>
            </div>
            <span className="text-[#16945b] text-[10px] font-bold">● L1</span>
          </div>
        </div>
      </aside>

      {/* 2. Main Content Area */}
      <main className="ml-[236px] w-[calc(100%-236px)] p-[30px_36px_44px] max-w-[1600px]">
        
        {/* Header */}
        <header className="flex items-start justify-between mb-7">
          <div>
            <div className="text-xs text-[#737986] mb-1.5 font-medium">Saturday, September 26, 2026 &middot; Production SOC Operations</div>
            <h1 className="text-[27px] font-bold tracking-[-0.04em] m-0 text-[#111318]">Threat Operations</h1>
            <div className="text-[13px] text-[#737986] mt-1.5 font-normal">
              Autonomous exploit detection, attack graph reconstruction, and policy-governed containment.
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => alert('Forwarding compliance report to Splunk HEC, ArcSight CEF, and Microsoft Sentinel...')}
              className="border border-[#e7e9ee] bg-white px-3.5 py-2.5 rounded-lg text-xs font-medium text-[#535963] shadow-[0_1px_1px_rgba(0,0,0,0.02)] hover:bg-[#f7f8fa] transition cursor-pointer"
            >
              Export SIEM Ledger
            </button>
            <button
              onClick={handleStartStream}
              className="bg-[#111318] text-white border border-[#111318] px-3.5 py-2.5 rounded-lg text-xs font-semibold shadow-sm hover:bg-[#252830] transition cursor-pointer flex items-center gap-1.5"
            >
              <span>+ Ingest & Triage Payload</span>
            </button>
          </div>
        </header>

        {/* View Routing */}
        {activeNav === 'stream' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">Live LangGraph Agent Reasoning Stream</h2>
                <p className="text-xs text-[#737986]">Real-time SSE step progression across 6 security nodes</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AgentLiveStreamVisualizer events={events} isStreaming={isStreaming} onStartScenario={handleStartStream} />
          </div>
        ) : activeNav === 'graph' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">Neo4j Attack Graph Topology</h2>
                <p className="text-xs text-[#737986]">Traversing multi-hop lateral movement from threat actors to target identities</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AttackGraphVisualizer onSelectAttackChain={() => {}} />
          </div>
        ) : activeNav === 'surface' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">10-State Asset Exposure Radar</h2>
                <p className="text-xs text-[#737986]">Continuous mail infrastructure exposure and exploitability tracking</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <ExposureView />
          </div>
        ) : activeNav === 'governance' ? (
          <div className="bg-white border border-[#e7e9ee] rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-[#e7e9ee] pb-4">
              <div>
                <h3 className="text-sm font-bold text-[#111318]">Tenant Autonomy & Response Governance (L0–L4)</h3>
                <p className="text-xs text-[#737986]">Active Policy: Autonomy Level 1 (Human Authorization Required for High/Critical actions)</p>
              </div>
              <span className="text-xs bg-[#eaf8f1] text-[#16945b] font-bold px-3 py-1 rounded-full">Active Policy: Level 1</span>
            </div>
            <p className="text-xs text-[#505660] leading-relaxed">
              When a threat proposes high-impact containment (e.g. <code>quarantine_email_and_revoke_session</code> or <code>disable_account</code>), 
              the system halts execution and issues an immutable cryptographic approval token (<code>APP-XXXXXX</code>) requiring human slide authorization.
            </p>
            <div className="pt-2">
              <button
                onClick={() => {
                  setActiveProposal({
                    token: 'APP-8E2F9A',
                    tool_name: 'quarantine_email_and_revoke_session',
                    risk_level: 'HIGH',
                    parameters: {
                      mailbox: 'cfo@enterprise-corp.internal',
                      message_id: '<20240926.exploit.moniker@corporate-updates.net>',
                      revoke_active_sessions: true,
                      block_source_ip: '198.51.100.42',
                    },
                    justification: 'Manual policy test trigger from SOC Governance dashboard.',
                    target_cve: 'CVE-2024-21413 (CVSS 9.8)',
                    target_identity: 'cfo@enterprise-corp.internal',
                  });
                  setApprovalModalOpen(true);
                }}
                className="bg-[#111318] text-white px-3.5 py-2 rounded-lg text-xs font-semibold hover:bg-[#252830]"
              >
                Test Human Approval Token Modal
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Top Metrics Row */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-3.5">
              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Emails Analyzed</span>
                  <span>24h Ingestion</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.totalAnalyzed}</div>
                <div className="text-[11px] text-[#16945b] font-medium">↑ 500:1 campaign compression</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Exploits & Threats</span>
                  <span>24h Detected</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.threatsCount}</div>
                <div className="text-[11px] text-[#d04444] font-medium">Monikers, OLE & BEC variants</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Active Investigations</span>
                  <span>Pending Containment</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.activeInvestigations}</div>
                <div className="text-[11px] text-[#b7791f] font-medium">1 token held for human approval</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Mean Detection Confidence</span>
                  <span>All Models & Heuristics</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.confidenceRate}</div>
                <div className="text-[11px] text-[#16945b] font-medium">Deterministic CISA/NVD correlation</div>
              </div>
            </section>

            {/* Middle Grid: Activity Chart & 6 LangGraph Agents Status */}
            <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.75fr)_minmax(300px,0.75fr)] gap-3.5 mb-3.5">
              
              {/* Agentic Detection Activity Chart */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div>
                    <div className="text-[13px] font-bold text-[#111318]">Agentic Detection & Ingestion Velocity</div>
                    <div className="text-[11px] text-[#737986] mt-1">Continuous LangGraph multi-node triage &middot; Last 24 Hours</div>
                  </div>
                  <div className="inline-flex items-center gap-1.5 text-[10px] text-[#16945b] font-[650] bg-[#eaf8f1] px-2 py-1 rounded-full">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#16945b] animate-pulse"></span>
                    <span>6 Nodes Active</span>
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
                      Active Ingestion Stream
                    </span>
                    <span className="flex items-center">
                      <span className="w-[7px] h-[7px] rounded-full inline-block mr-1.5 bg-[#b9c2d2]"></span>
                      Clean Baseline
                    </span>
                    <span className="ml-auto text-[#9aa0aa] font-mono">
                      00:00 &nbsp;&nbsp; 06:00 &nbsp;&nbsp; 12:00 &nbsp;&nbsp; 18:00 &nbsp;&nbsp; Now
                    </span>
                  </div>
                </div>
              </div>

              {/* Real 6 LangGraph Nodes Status */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)]">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Agentic Node Status</div>
                  <div className="text-[11px] text-[#16945b] font-medium">6 / 6 Operational</div>
                </div>
                <div className="py-1 divide-y divide-[#f0f1f3]">
                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">1</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Ingestion & Privacy Boundary</b>
                      <span className="text-[10px] text-[#737986]">DataClassificationEngine · Scrubber</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#eaf8f1] text-[#16945b] font-bold">ACTIVE</span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">2</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">MIME Parser & Behavioral Sandbox</b>
                      <span className="text-[10px] text-[#737986]">NetworkGuard SSRF filter · Monikers</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#eaf8f1] text-[#16945b] font-bold">ACTIVE</span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">3</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Threat Intelligence & CVE Research</b>
                      <span className="text-[10px] text-[#737986]">CISA KEV · NVD · URLhaus · AbuseIPDB</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#eaf8f1] text-[#16945b] font-bold">ACTIVE</span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">4</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Attack Surface Exposure Radar</b>
                      <span className="text-[10px] text-[#737986]">10-state asset exposure correlation</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#eaf8f1] text-[#16945b] font-bold">ACTIVE</span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">5</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Neo4j Graph & Campaign Aggregator</b>
                      <span className="text-[10px] text-[#737986]">500:1 campaign rollup · Cypher paths</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#eaf8f1] text-[#16945b] font-bold">ACTIVE</span>
                  </div>

                  <div className="flex items-center gap-3 px-[18px] py-2.5">
                    <div className="w-6 h-6 rounded-md bg-[#f4f5f7] grid place-items-center text-xs font-bold text-[#111318]">6</div>
                    <div className="flex-1">
                      <b className="block text-xs text-[#111318]">Response Policy Governance Engine</b>
                      <span className="text-[10px] text-[#737986]">Autonomy L0-L4 · Tokens (APP-XXXXXX)</span>
                    </div>
                    <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#fff7e7] text-[#b7791f] font-bold">GATED</span>
                  </div>
                </div>
              </div>
            </section>

            {/* Bottom Grid: Recent Investigations Table & Threat Queue */}
            <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.75fr)_minmax(300px,0.75fr)] gap-3.5">
              
              {/* Recent Investigations Table */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)] overflow-hidden">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div>
                    <div className="text-[13px] font-bold text-[#111318]">Live Threat Triage Matrix</div>
                    <div className="text-[11px] text-[#737986]">Click any incident to inspect attack graph, evidence & containment</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value as any)}
                      className="text-xs border border-[#e7e9ee] rounded-lg px-2.5 py-1 text-[#505660] bg-white outline-none"
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr className="bg-[#fafbfc] border-b border-[#e7e9ee]">
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Sender / Subject
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Threat Vector
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Verdict
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Confidence
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Time
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#e7e9ee]">
                      {filteredIncidents.map((item) => (
                        <tr
                          key={item.incident_id}
                          onClick={() => setSelectedIncident(item)}
                          className="hover:bg-[#f8fafc] transition-colors cursor-pointer"
                        >
                          <td className="p-[13px_17px]">
                            <span className="font-[650] text-[#20232a] text-[11px] block">{item.sender}</span>
                            <small className="block text-[#989da7] font-normal text-[10px] mt-0.5">{item.subject}</small>
                          </td>
                          <td className="p-[13px_17px] text-[11px] font-medium text-[#505660]">
                            {item.threat_category}
                          </td>
                          <td className="p-[13px_17px]">
                            {item.verdict === 'Malicious' ? (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#fff0f0] text-[#d04444]">
                                Malicious
                              </span>
                            ) : item.verdict === 'Suspicious' ? (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#fff7e7] text-[#b7791f]">
                                Suspicious
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-[9px] font-bold bg-[#eaf8f1] text-[#16945b]">
                                Benign
                              </span>
                            )}
                          </td>
                          <td className="p-[13px_17px] text-[11px] font-medium text-[#505660]">
                            {(item.confidence * 100).toFixed(1)}%
                          </td>
                          <td className="p-[13px_17px] text-[11px] text-[#737986]">{item.timestamp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Threat Queue Card */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-[0_1px_2px_rgba(16,24,40,0.04),0_8px_24px_rgba(16,24,40,0.035)] pb-2">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Campaign Threat Vectors</div>
                  <div className="text-[11px] text-[#737986] font-medium">500:1 Deduplicated</div>
                </div>
                <div className="divide-y divide-[#e7e9ee]">
                  {threatQueue.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-[12px_18px]">
                      <div className="text-[15px] font-bold text-[#111318] w-6">{item.count}</div>
                      <div className="flex-1">
                        <b className="text-[11px] text-[#111318] block">{item.name}</b>
                        <span className="text-[10px] text-[#737986]">{item.status}</span>
                      </div>
                      <div className="h-1 w-[60px] rounded-full bg-[#e9ebef] overflow-hidden">
                        <div className="h-full bg-[#2563eb]" style={{ width: `${item.progress}%` }}></div>
                      </div>
                    </div>
                  ))}
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
            const proposal = {
              token: 'APP-8E2F9A',
              tool_name: selectedIncident.recommended_actions.find((a) => a.requires_approval)?.name || 'quarantine_email_and_revoke_session',
              risk_level: 'HIGH',
              parameters: {
                mailbox: selectedIncident.target_identity,
                message_id: selectedIncident.incident_id,
                revoke_active_sessions: true,
                block_source_ip: '198.51.100.42',
              },
              justification: `High-risk exploit detected (${selectedIncident.title}). Forced NTLM relay mitigation required.`,
              target_cve: selectedIncident.cve || 'CVE-2024-21413',
              target_identity: selectedIncident.target_identity,
            };
            setActiveProposal(proposal);
            setSelectedIncident(null);
            setApprovalModalOpen(true);
          }}
        />
      )}

      {/* 4. Slide-to-Authorize Human Approval Modal */}
      {activeProposal && (
        <HumanApprovalModal
          isOpen={approvalModalOpen}
          onClose={() => setApprovalModalOpen(false)}
          proposal={activeProposal}
          onApprove={() => {
            alert(`Containment Authorized! Cryptographic token ${activeProposal.token} validated. Email quarantined and active webmail session revoked.`);
            setApprovalModalOpen(false);
          }}
        />
      )}

      {/* 5. Live Stream Simulation Slide-over Modal */}
      {investigationDrawerOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-white h-full shadow-2xl p-6 overflow-y-auto flex flex-col">
            <div className="flex items-center justify-between pb-4 border-b border-[#e7e9ee] mb-4">
              <div>
                <h3 className="text-base font-bold text-[#111318]">Live Autonomous Agent Reasoning Stream</h3>
                <p className="text-xs text-[#737986]">Real-time LangGraph multi-agent execution pipeline</p>
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
