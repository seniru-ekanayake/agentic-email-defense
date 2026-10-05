'use client';

import React, { useState } from 'react';
import { ComprehensiveIncidentRecord, PendingApproval } from '@/lib/api/types';

interface IncidentDetailModalProps {
  incident: ComprehensiveIncidentRecord;
  onClose: () => void;
  onTriggerContainment?: (proposal: PendingApproval) => void;
  onApproveSuccess?: () => void;
}

export function IncidentDetailModal({
  incident,
  onClose,
  onTriggerContainment,
  onApproveSuccess,
}: IncidentDetailModalProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'chain' | 'evidence' | 'trace' | 'tools'>('overview');

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-end p-0 md:p-4 overflow-y-auto animate-in fade-in duration-200 font-sans">
      <div className="bg-white border-l md:border border-[#e7e9ee] w-full max-w-2xl h-full md:h-auto md:max-h-[92vh] md:rounded-2xl shadow-2xl flex flex-col overflow-hidden transition-all">
        {/* Header Bar */}
        <div className="p-6 border-b border-[#e7e9ee] flex items-start justify-between bg-[#fafbfc]">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                incident.severity === 'CRITICAL'
                  ? 'bg-rose-50 text-rose-600 border border-rose-200'
                  : incident.severity === 'HIGH'
                  ? 'bg-orange-50 text-orange-600 border border-orange-200'
                  : 'bg-blue-50 text-blue-600 border border-blue-200'
              }`}>
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-[#737986] font-medium">ID: {incident.incident_id}</span>
              <span className="text-xs font-mono font-bold text-[#16945b]">
                Score: {incident.overall_risk_score} / 100
              </span>
              <span className="text-xs font-mono text-[#505660]">
                Tenant: {incident.tenant_id}
              </span>
            </div>
            <h2 className="text-lg font-bold text-[#111318] tracking-tight">{incident.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[#737986] hover:text-[#111318] hover:bg-[#f2f4f7] transition cursor-pointer"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal Tabs */}
        <div className="flex border-b border-[#e7e9ee] px-6 text-xs font-semibold space-x-6 bg-[#f8fafc] overflow-x-auto">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 border-b-2 transition-all cursor-pointer font-mono text-[11px] whitespace-nowrap ${
              activeTab === 'overview'
                ? 'border-[#1d5eea] text-[#1d5eea] font-bold'
                : 'border-transparent text-[#737986] hover:text-[#111318]'
            }`}
          >
            01_OVERVIEW
          </button>
          <button
            onClick={() => setActiveTab('chain')}
            className={`py-3 border-b-2 transition-all cursor-pointer font-mono text-[11px] whitespace-nowrap ${
              activeTab === 'chain'
                ? 'border-[#1d5eea] text-[#1d5eea] font-bold'
                : 'border-transparent text-[#737986] hover:text-[#111318]'
            }`}
          >
            02_ATTACK_CHAIN ({incident.attack_chain?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-3 border-b-2 transition-all cursor-pointer font-mono text-[11px] whitespace-nowrap ${
              activeTab === 'evidence'
                ? 'border-[#1d5eea] text-[#1d5eea] font-bold'
                : 'border-transparent text-[#737986] hover:text-[#111318]'
            }`}
          >
            03_EVIDENCE ({incident.evidence_items?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab('trace')}
            className={`py-3 border-b-2 transition-all cursor-pointer font-mono text-[11px] whitespace-nowrap ${
              activeTab === 'trace'
                ? 'border-[#1d5eea] text-[#1d5eea] font-bold'
                : 'border-transparent text-[#737986] hover:text-[#111318]'
            }`}
          >
            04_DECISIONS ({incident.decision_trace?.length || 0})
          </button>
          <button
            onClick={() => setActiveTab('tools')}
            className={`py-3 border-b-2 transition-all cursor-pointer font-mono text-[11px] whitespace-nowrap ${
              activeTab === 'tools'
                ? 'border-[#1d5eea] text-[#1d5eea] font-bold'
                : 'border-transparent text-[#737986] hover:text-[#111318]'
            }`}
          >
            05_TOOLS ({incident.tool_executions?.length || 0})
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs custom-scroll">
          {activeTab === 'overview' && (
            <>
              {/* Metadata Cards */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl bg-[#f8fafc] border border-[#e7e9ee]">
                  <span className="text-[#737986] text-[10px] uppercase font-mono block">Sender</span>
                  <span className="text-[#111318] font-mono font-medium text-xs mt-1 block truncate">
                    {incident.sender}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-[#f8fafc] border border-[#e7e9ee]">
                  <span className="text-[#737986] text-[10px] uppercase font-mono block">Target Identity</span>
                  <span className="text-[#1d5eea] font-mono font-medium text-xs mt-1 block truncate">
                    {incident.target_identity || incident.recipient}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-[#f8fafc] border border-[#e7e9ee]">
                  <span className="text-[#737986] text-[10px] uppercase font-mono block">Exposure State</span>
                  <span className="text-amber-600 font-mono font-medium text-xs mt-1 block">
                    {incident.exposure_status}
                  </span>
                </div>
                <div className="p-3.5 rounded-xl bg-[#f8fafc] border border-[#e7e9ee]">
                  <span className="text-[#737986] text-[10px] uppercase font-mono block">Mail Platform</span>
                  <span className="text-[#505660] font-mono font-bold text-xs mt-1 block truncate">
                    {incident.mail_platform}
                  </span>
                </div>
              </div>

              {/* Pending Approvals Section */}
              {incident.pending_approvals && incident.pending_approvals.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold uppercase font-mono text-amber-600 tracking-wider flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" />
                      Pending Human Authorization ({incident.pending_approvals.length})
                    </h4>
                  </div>
                  <div className="space-y-2">
                    {incident.pending_approvals.map((appr, idx) => (
                      <div
                        key={idx}
                        className="p-3.5 rounded-xl bg-amber-50/60 border border-amber-200 flex items-center justify-between gap-3"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-[#111318] text-xs">
                              {appr.tool_name}
                            </span>
                            <span className="text-[10px] font-mono font-bold text-amber-700 bg-white px-2 py-0.5 rounded border border-amber-200">
                              {appr.approval_token}
                            </span>
                          </div>
                          <p className="text-[#505660] text-xs mt-1">{appr.reasoning}</p>
                        </div>
                        {onTriggerContainment && (
                          <button
                            onClick={() => onTriggerContainment(appr)}
                            className="px-3.5 py-1.5 text-xs font-bold bg-[#111318] hover:bg-[#252830] text-white rounded-lg transition font-mono uppercase shrink-0"
                          >
                            Review & Authorize
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Actions */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase font-mono text-[#737986] tracking-wider">
                  Recommended Containment Actions
                </h4>
                <div className="space-y-2">
                  {incident.recommended_actions?.map((act: any, idx: number) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl bg-white border border-[#e7e9ee] flex items-center justify-between gap-4"
                    >
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-[#111318] text-xs">
                            {act.action || act.name}
                          </span>
                          {act.requires_approval && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-600 border border-amber-200">
                              Requires Approval
                            </span>
                          )}
                        </div>
                        <p className="text-[#737986] text-xs mt-0.5">{act.reasoning}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {activeTab === 'chain' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-[#737986] tracking-wider">
                Multi-Stage Attack Path Reconstruction
              </h4>
              <div className="space-y-2.5">
                {incident.attack_chain?.map((stage: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] flex items-start gap-3"
                  >
                    <div className="w-6 h-6 rounded-lg bg-[#f0f4ff] border border-[#1d5eea]/30 text-[#1d5eea] font-mono text-xs flex items-center justify-center shrink-0 font-bold">
                      {idx + 1}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-[#1d5eea] font-bold uppercase">
                          {stage.stage || stage.node}
                        </span>
                        <span className="text-xs font-bold text-[#111318]">
                          {stage.technique || stage.type}
                        </span>
                      </div>
                      <p className="text-xs text-[#505660] mt-1">{stage.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-[#737986] tracking-wider">
                Authoritative Evidence Items ({incident.evidence_items?.length || 0})
              </h4>
              <div className="space-y-2">
                {incident.evidence_items?.map((ev, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] font-bold text-[#1d5eea]">{ev.evidence_id} · {ev.type}</span>
                      <span className="text-[10px] font-mono text-[#16945b] font-bold">{ev.confidence} CONFIDENCE</span>
                    </div>
                    <div className="text-xs text-[#111318] font-mono break-all">{ev.value}</div>
                    <div className="text-[10px] text-[#737986]">Source: {ev.source}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'trace' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-[#737986] tracking-wider">
                Autonomous Decision Trace ({incident.decision_trace?.length || 0})
              </h4>
              <div className="space-y-2">
                {incident.decision_trace?.map((dec, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] font-bold text-purple-600">{dec.decision_id} · {dec.action}</span>
                      <span className="text-[10px] font-mono text-[#737986]">{dec.confidence} CONFIDENCE</span>
                    </div>
                    <div className="text-xs text-[#111318] font-medium">{dec.decision}</div>
                    <div className="text-[11px] text-[#505660]">{dec.reason}</div>
                    {dec.observed && (
                      <div className="text-[10px] text-[#737986] bg-white p-2 rounded border border-[#e7e9ee] font-mono">
                        Observed: {dec.observed}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'tools' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-[#737986] tracking-wider">
                Deterministic Tool Executions ({incident.tool_executions?.length || 0})
              </h4>
              <div className="space-y-2">
                {incident.tool_executions?.map((t, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#111318]">{t.tool_name}</span>
                      <span className="font-mono text-[10px] text-[#16945b] font-bold">{t.status} ({t.duration_ms}ms)</span>
                    </div>
                    <div className="text-xs text-[#505660] font-mono">{t.result_summary}</div>
                    {t.input_parameters && (
                      <pre className="text-[10px] font-mono bg-white p-2 rounded border border-[#e7e9ee] overflow-x-auto text-[#505660]">
                        {JSON.stringify(t.input_parameters, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
