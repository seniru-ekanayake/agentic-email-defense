'use client';

import React, { useState } from 'react';

interface IncidentDetailModalProps {
  incident: any;
  onClose: () => void;
  onApprove: (token: string) => void;
}

export function IncidentDetailModal({ incident, onClose, onApprove }: IncidentDetailModalProps) {
  const [approvedList, setApprovedList] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'chain' | 'evidence'>('overview');

  const handleApproveClick = (token: string) => {
    onApprove(token);
    setApprovedList([...approvedList, token]);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-md flex items-center justify-end p-0 md:p-4 overflow-y-auto animate-in fade-in duration-200 font-poppins">
      <div className="bg-card border-l md:border border-border w-full max-w-2xl h-full md:h-auto md:max-h-[92vh] md:rounded-3xl shadow-2xl flex flex-col overflow-hidden transition-all">
        {/* Header Bar */}
        <div className="p-6 border-b border-border flex items-start justify-between bg-card-secondary">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(255,0,85,0.2)]">
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-muted font-medium">ID: {incident.incident_id}</span>
              <span className="text-xs font-mono font-bold text-neon-emerald">
                Confidence: {(incident.confidence * 100).toFixed(0)}%
              </span>
            </div>
            <h2 className="text-lg font-bold text-foreground tracking-tight">{incident.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl text-muted hover:text-foreground hover:bg-hover-bg transition cursor-pointer"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal Tabs */}
        <div className="flex border-b border-border px-6 text-xs font-semibold space-x-6 bg-card-secondary/60">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3.5 border-b-2 transition-all cursor-pointer font-mono text-[11px] ${
              activeTab === 'overview'
                ? 'border-neon-cyan text-neon-cyan font-bold'
                : 'border-transparent text-muted hover:text-foreground'
            }`}
          >
            01_INVESTIGATION_OVERVIEW
          </button>
          <button
            onClick={() => setActiveTab('chain')}
            className={`py-3.5 border-b-2 transition-all cursor-pointer font-mono text-[11px] ${
              activeTab === 'chain'
                ? 'border-neon-cyan text-neon-cyan font-bold'
                : 'border-transparent text-muted hover:text-foreground'
            }`}
          >
            02_ATTACK_CHAIN_STEPPER
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-3.5 border-b-2 transition-all cursor-pointer font-mono text-[11px] ${
              activeTab === 'evidence'
                ? 'border-neon-cyan text-neon-cyan font-bold'
                : 'border-transparent text-muted hover:text-foreground'
            }`}
          >
            03_VERIFIED_EVIDENCE
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs custom-scroll">
          {activeTab === 'overview' && (
            <>
              {/* Metadata Cards */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-4 rounded-2xl bg-background border border-border">
                  <span className="text-muted text-[10px] uppercase font-mono block">Target Executive</span>
                  <span className="text-foreground font-mono font-medium text-xs mt-1 block truncate">
                    {incident.target_identity}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-background border border-border">
                  <span className="text-muted text-[10px] uppercase font-mono block">Mail Platform</span>
                  <span className="text-neon-cyan font-mono font-medium text-xs mt-1 block truncate">
                    {incident.mail_platform}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-background border border-border">
                  <span className="text-muted text-[10px] uppercase font-mono block">Exposure State</span>
                  <span className="text-neon-amber font-mono font-medium text-xs mt-1 block">
                    {incident.exposure_status}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-background border border-border">
                  <span className="text-muted text-[10px] uppercase font-mono block">Interaction State</span>
                  <span className="text-neon-rose font-mono font-bold text-xs mt-1 block">
                    {incident.interaction_required} (Preview Trigger)
                  </span>
                </div>
              </div>

              {/* Recommended Actions */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase font-mono text-muted tracking-wider">
                  Recommended Containment Actions
                </h4>
                <div className="space-y-2.5">
                  {incident.recommended_actions?.map((act: any, idx: number) => {
                    const pending = incident.pending_approvals?.find((p: any) => p.tool_name === act.action);
                    const isApproved = pending && approvedList.includes(pending.approval_token);

                    return (
                      <div
                        key={idx}
                        className="p-4 rounded-2xl bg-background border border-border flex items-center justify-between gap-4"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-foreground text-xs">
                              {act.action}
                            </span>
                            {act.requires_approval && (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                Policy Gate
                              </span>
                            )}
                          </div>
                          <p className="text-muted text-xs mt-0.5 font-light">{act.reasoning}</p>
                        </div>

                        {pending && (
                          <div className="shrink-0">
                            {isApproved ? (
                              <span className="inline-flex items-center gap-1 text-xs font-mono font-bold text-neon-emerald bg-emerald-500/10 px-3 py-1.5 rounded-xl border border-emerald-500/30">
                                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                                </svg>
                                EXECUTED
                              </span>
                            ) : (
                              <button
                                onClick={() => handleApproveClick(pending.approval_token)}
                                className="px-3.5 py-1.5 text-xs font-bold bg-neon-cyan hover:bg-cyan-300 text-black rounded-xl shadow-glow-cyan transition font-mono cursor-pointer uppercase"
                              >
                                Authorize
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {activeTab === 'chain' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-muted tracking-wider">
                Multi-Stage Attack Path Reconstruction
              </h4>
              <div className="space-y-2.5">
                {incident.attack_chain?.map((stage: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3.5 rounded-2xl bg-background border border-border flex items-start gap-3"
                  >
                    <div className="w-6 h-6 rounded-lg bg-neon-cyan/10 border border-neon-cyan/40 text-neon-cyan font-mono text-xs flex items-center justify-center shrink-0 font-bold">
                      {idx + 1}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-neon-cyan font-bold uppercase">
                          {stage.stage}
                        </span>
                        <span className="text-xs font-bold text-foreground">
                          {stage.technique}
                        </span>
                      </div>
                      <p className="text-xs text-muted font-light mt-1">{stage.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase font-mono text-muted tracking-wider">
                Verified Forensic Indicators
              </h4>
              <div className="p-4 rounded-2xl bg-background border border-border space-y-2.5">
                {incident.evidence_summary?.map((ev: string, idx: number) => (
                  <div key={idx} className="flex items-start gap-2.5 text-xs">
                    <svg className="w-4 h-4 text-neon-emerald shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                    </svg>
                    <span className="text-foreground leading-relaxed font-light">{ev}</span>
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
