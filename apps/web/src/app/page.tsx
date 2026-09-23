'use client';

import React, { useState } from 'react';
import { AttackGraphVisualizer } from '@/components/AttackGraphVisualizer';
import { IncidentDetailModal } from '@/components/IncidentDetailModal';
import { ExposureView } from '@/components/ExposureView';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<'soc' | 'executive' | 'exposure' | 'graph'>('soc');
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  const incidents = [
    {
      incident_id: 'INC-C7DF19',
      tenant_id: 'tenant-enterprise-demo',
      title: 'Potential Email-Platform Exploitation (CVE-2023-35636)',
      severity: 'CRITICAL',
      overall_risk_score: 91.5,
      confidence: 0.95,
      status: 'CONTAINMENT_PROPOSED',
      target_identity: 'cfo@enterprise-corp.internal',
      mail_platform: 'Microsoft Exchange / Outlook Web Access (OWA)',
      exposure_status: 'Internet-Facing',
      interaction_required: 'VIEW',
      cve: 'CVE-2023-35636',
      attack_chain: [
        { stage: 'INITIAL_ACCESS', technique: 'T1566 Phishing', description: 'Attacker delivers crafted email from spoofed sender: spoofed-payroll@corporate-updates.net' },
        { stage: 'EMAIL_DELIVERY', technique: 'SMTP Transport', description: 'Email bypasses perimeter filters and lands in victim mailbox.' },
        { stage: 'RENDERING_PARSING', technique: 'URI Moniker Parsing', description: 'Victim previews email in mail client, triggering CVE-2023-35636 parser vulnerability.' },
        { stage: 'EXPLOITATION', technique: 'T1187 Forced Authentication', description: 'Client automatically attempts outbound SMB/WebDAV authentication leaking NTLM hash.' },
        { stage: 'SESSION_IDENTITY', technique: 'Credential Access', description: 'Identity cfo@enterprise-corp.internal credentials targeted for relay/hijacking.' },
        { stage: 'POST_EXPLOITATION', technique: 'T1114 Email Collection', description: 'Potential unauthorized mailbox access and persistent rule creation.' }
      ],
      mitre_techniques: [
        { technique_id: 'T1566.001', name: 'Phishing: Spearphishing Attachment', tactic: 'Initial Access' },
        { technique_id: 'T1187', name: 'Forced Authentication', tactic: 'Credential Access' }
      ],
      evidence_summary: [
        'SPF/DMARC failure detected for sender domain.',
        'Found URI handler: search-ms:query=compensation_q3.docx&crumb=location:\\\\198.51.100.42\\share',
        'Forced UNC/SMB callout to \\\\198.51.100.42\\share',
        'Target recipient is VIP CFO with high privilege.',
        'Software version 15.1.2507.17 identified on internet-facing OWA portal.'
      ],
      recommended_actions: [
        { action: 'quarantine_email', reasoning: 'Quarantine malicious email to prevent further rendering or user interaction.', requires_approval: true },
        { action: 'revoke_session', reasoning: 'Revoke active sessions to prevent NTLM/cookie relay exploitation.', requires_approval: true },
        { action: 'search_mailbox_history', reasoning: 'Search historical mailboxes for related campaign activity.', requires_approval: false }
      ],
      pending_approvals: [
        { tool_name: 'quarantine_email', approval_token: 'APP-1E1D7CBB', risk_level: 'MEDIUM' },
        { tool_name: 'revoke_session', approval_token: 'APP-F8F446E3', risk_level: 'HIGH' }
      ]
    }
  ];

  const handleSimulateDemo = () => {
    setSimulating(true);
    setSimulationStatus('Running LangGraph Security Workflow: Parsing MIME → Sandbox Execution → CVE Research → Exposure Correlation → Graph Builder...');
    setTimeout(() => {
      setSimulating(false);
      setSimulationStatus('Demo scenario executed successfully! Incident INC-C7DF19 triaged with Severity: CRITICAL (Interaction: VIEW).');
      setSelectedIncident(incidents[0]);
    }, 1500);
  };

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8 space-y-6">
      {/* Top Navbar */}
      <header className="flex flex-col md:flex-row md:items-center justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_12px_#38bdf8]"></span>
            <h1 className="text-xl font-bold tracking-tight text-white">Agentic Email Exploitation Defense Platform</h1>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">Enterprise Email-Rendering & Application Exploitation Detection & Response</p>
        </div>

        {/* Simulation Action Bar */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleSimulateDemo}
            disabled={simulating}
            className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold rounded-lg shadow-lg flex items-center gap-2 transition-all disabled:opacity-50"
          >
            {simulating ? '⚡ Running Agentic Pipeline...' : '▶ Run Master Demo Scenario'}
          </button>
        </div>
      </header>

      {/* Simulation status banner */}
      {simulationStatus && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-800 text-cyan-300 text-xs rounded-lg flex items-center justify-between">
          <span>{simulationStatus}</span>
          <button onClick={() => setSimulationStatus(null)} className="text-cyan-400 font-bold ml-4">✕</button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex border-b border-slate-800 text-xs font-medium space-x-6">
        <button
          onClick={() => setActiveTab('soc')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'soc' ? 'border-cyan-400 text-cyan-400 font-bold' : 'border-transparent text-slate-400 hover:text-white'}`}
        >
          🛡️ SOC Incidents & Evidence
        </button>
        <button
          onClick={() => setActiveTab('executive')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'executive' ? 'border-cyan-400 text-cyan-400 font-bold' : 'border-transparent text-slate-400 hover:text-white'}`}
        >
          📊 Executive Risk Overview
        </button>
        <button
          onClick={() => setActiveTab('exposure')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'exposure' ? 'border-cyan-400 text-cyan-400 font-bold' : 'border-transparent text-slate-400 hover:text-white'}`}
        >
          🌐 Email Attack Surface & Exposure
        </button>
        <button
          onClick={() => setActiveTab('graph')}
          className={`pb-3 border-b-2 transition-colors ${activeTab === 'graph' ? 'border-cyan-400 text-cyan-400 font-bold' : 'border-transparent text-slate-400 hover:text-white'}`}
        >
          🕸️ Attack Graph Explorer
        </button>
      </div>

      {/* Executive Risk View */}
      {activeTab === 'executive' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
              <span className="text-xs text-slate-400 block">Email Attack Surface Score</span>
              <span className="text-3xl font-extrabold text-red-400 font-mono mt-2 block">88.4 / 100</span>
              <span className="text-[10px] text-red-300 mt-1 block">High Exposure (Internet-facing OWA detected)</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
              <span className="text-xs text-slate-400 block">Active Critical Exploitations</span>
              <span className="text-3xl font-extrabold text-amber-400 font-mono mt-2 block">1 Active</span>
              <span className="text-[10px] text-amber-300 mt-1 block">Low Interaction (VIEW Trigger)</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
              <span className="text-xs text-slate-400 block">Vulnerable Exposed Mail Servers</span>
              <span className="text-3xl font-extrabold text-cyan-400 font-mono mt-2 block">2 Hosts</span>
              <span className="text-[10px] text-cyan-300 mt-1 block">Exchange OWA 15.1, Zimbra 8.8</span>
            </div>
            <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
              <span className="text-xs text-slate-400 block">Autonomous Defense Level</span>
              <span className="text-3xl font-extrabold text-emerald-400 font-mono mt-2 block">Level 1</span>
              <span className="text-[10px] text-emerald-300 mt-1 block">Human-in-the-loop approval active</span>
            </div>
          </div>
          <AttackGraphVisualizer />
        </div>
      )}

      {/* SOC Incidents View */}
      {activeTab === 'soc' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-bold text-white">Active Exploitation Incidents</h3>
                <p className="text-xs text-slate-400">Agentic multi-dimensional correlation of email payloads, webmail rendering, and session identity</p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300">
                <thead className="bg-slate-950 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Incident Title</th>
                    <th className="p-3">Target Identity</th>
                    <th className="p-3">Mail Platform</th>
                    <th className="p-3">Interaction Req</th>
                    <th className="p-3">Confidence</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {incidents.map((inc) => (
                    <tr key={inc.incident_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="p-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950/80 text-red-400 border border-red-800">
                          {inc.severity}
                        </span>
                      </td>
                      <td className="p-3 font-medium text-white">{inc.title}</td>
                      <td className="p-3 font-mono text-cyan-300">{inc.target_identity}</td>
                      <td className="p-3 text-slate-300">{inc.mail_platform}</td>
                      <td className="p-3 font-bold text-red-400">{inc.interaction_required}</td>
                      <td className="p-3 font-mono text-emerald-400">{(inc.confidence * 100).toFixed(0)}%</td>
                      <td className="p-3">
                        <button
                          onClick={() => setSelectedIncident(inc)}
                          className="px-3 py-1 bg-cyan-700 hover:bg-cyan-600 text-white rounded text-xs font-bold transition-colors"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <AttackGraphVisualizer />
        </div>
      )}

      {/* Exposure View */}
      {activeTab === 'exposure' && <ExposureView />}

      {/* Graph View */}
      {activeTab === 'graph' && <AttackGraphVisualizer />}

      {/* Modal View */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onApprove={(token) => {
            console.log('Approved token:', token);
          }}
        />
      )}
    </main>
  );
}
