'use client';

import React, { useState } from 'react';

interface IncidentDetailModalProps {
  incident: any;
  onClose: () => void;
  onApprove: (token: string) => void;
}

export function IncidentDetailModal({ incident, onClose, onApprove }: IncidentDetailModalProps) {
  const [approvedList, setApprovedList] = useState<string[]>([]);

  const handleApproveClick = (token: string) => {
    onApprove(token);
    setApprovedList([...approvedList, token]);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 w-full max-w-4xl rounded-2xl p-6 shadow-2xl space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 text-xs font-bold rounded-md bg-red-600/20 text-red-400 border border-red-500/30">
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">ID: {incident.incident_id}</span>
              <span className="text-xs font-bold text-emerald-400">Confidence: {(incident.confidence * 100).toFixed(0)}%</span>
            </div>
            <h2 className="text-xl font-bold text-white mt-2">{incident.title}</h2>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-lg font-bold">✕</button>
        </div>

        {/* Metadata Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block">Target Identity</span>
            <span className="text-white font-medium">{incident.target_identity}</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block">Mail Platform</span>
            <span className="text-cyan-400 font-medium">{incident.mail_platform}</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block">Exposure</span>
            <span className="text-amber-400 font-medium">{incident.exposure_status}</span>
          </div>
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
            <span className="text-slate-500 block">Interaction Required</span>
            <span className="text-red-400 font-bold">{incident.interaction_required}</span>
          </div>
        </div>

        {/* Evidence Section */}
        <div>
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-2">Evidence Checklist</h3>
          <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 space-y-1.5 text-xs">
            {incident.evidence_summary?.map((ev: string, idx: number) => (
              <div key={idx} className="flex items-start gap-2">
                <span className="text-emerald-400 font-bold">✓</span>
                <span className="text-slate-300">{ev}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Chain Section */}
        <div>
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-2">Reconstructed Attack Chain</h3>
          <div className="grid grid-cols-1 md:grid-cols-6 gap-2 text-xs">
            {incident.attack_chain?.map((stage: any, idx: number) => (
              <div key={idx} className="bg-slate-950 p-2.5 rounded border border-slate-800 flex flex-col justify-between">
                <div>
                  <span className="text-[10px] font-mono text-cyan-400 font-bold">{stage.stage}</span>
                  <p className="text-slate-300 font-medium mt-1">{stage.technique}</p>
                </div>
                <p className="text-[10px] text-slate-500 mt-2">{stage.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Recommended Actions & Human in the Loop */}
        <div>
          <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-2">Recommended Actions</h3>
          <div className="space-y-2">
            {incident.recommended_actions?.map((act: any, idx: number) => {
              const pending = incident.pending_approvals?.find((p: any) => p.tool_name === act.action);
              const isApproved = pending && approvedList.includes(pending.approval_token);

              return (
                <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-white text-xs font-bold">{idx + 1}. {act.action}</span>
                      {act.requires_approval && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800">
                          Human Approval Required
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 mt-0.5">{act.reasoning}</p>
                  </div>

                  {pending && (
                    <div>
                      {isApproved ? (
                        <span className="text-xs font-bold text-emerald-400 bg-emerald-950/60 px-3 py-1.5 rounded border border-emerald-700">
                          ✓ Response Approved & Executed
                        </span>
                      ) : (
                        <button
                          onClick={() => handleApproveClick(pending.approval_token)}
                          className="px-4 py-1.5 text-xs font-bold bg-cyan-600 hover:bg-cyan-500 text-white rounded-md shadow transition-colors"
                        >
                          [Approve Response]
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
