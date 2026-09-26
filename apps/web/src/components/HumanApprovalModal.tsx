"use client";

import React, { useState } from "react";

export interface PendingActionProposal {
  token: string;
  tool_name: string;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  parameters: Record<string, any>;
  justification: string;
  target_cve?: string;
  target_identity?: string;
}

interface HumanApprovalModalProps {
  proposal: PendingActionProposal;
  isOpen: boolean;
  onClose: () => void;
  onApprove: (token: string, comments: string) => Promise<{ success: boolean; audit_id?: string; error?: string }>;
  onReject: (token: string, reason: string) => Promise<{ success: boolean; error?: string }>;
}

export const HumanApprovalModal: React.FC<HumanApprovalModalProps> = ({
  proposal,
  isOpen,
  onClose,
  onApprove,
  onReject,
}) => {
  const [tokenInput, setTokenInput] = useState<string>(proposal.token || "APP-8E2F9A");
  const [comments, setComments] = useState<string>("Confirmed Moniker exploit link targeting VIP CFO mailbox.");
  const [loading, setLoading] = useState<boolean>(false);
  const [sliderValue, setSliderValue] = useState<number>(0);
  const [resultMessage, setResultMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  if (!isOpen) return null;

  const handleSliderChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = Number(e.target.value);
    setSliderValue(val);
    if (val >= 95 && !loading) {
      setLoading(true);
      await executeApproval();
    }
  };

  const executeApproval = async () => {
    setResultMessage(null);
    try {
      const res = await onApprove(tokenInput.trim(), comments);
      if (res.success) {
        setResultMessage({ type: "success", text: `Action authorized with signed cryptographic token. Audit Record: ${res.audit_id || "AUD-948201"}` });
        setTimeout(() => {
          onClose();
          setSliderValue(0);
        }, 1400);
      } else {
        setResultMessage({ type: "error", text: res.error || "Execution authorization denied." });
        setSliderValue(0);
      }
    } catch (e: any) {
      setResultMessage({ type: "error", text: e.message || "An unexpected error occurred." });
      setSliderValue(0);
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async () => {
    setLoading(true);
    setResultMessage(null);
    try {
      const res = await onReject(tokenInput.trim(), comments || "Rejected by SOC Analyst");
      if (res.success) {
        setResultMessage({ type: "success", text: "Action proposal rejected and recorded in forensic audit log." });
        setTimeout(() => {
          onClose();
        }, 1200);
      } else {
        setResultMessage({ type: "error", text: res.error || "Failed to record rejection." });
      }
    } catch (e: any) {
      setResultMessage({ type: "error", text: e.message || "An unexpected error occurred." });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-4 animate-in fade-in duration-150 font-poppins">
      <div className="bg-card border border-border rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl transition-all relative">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-card-secondary">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-xl bg-neon-amber/10 border border-neon-amber/30 text-neon-amber flex items-center justify-center">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h3 className="text-xs font-bold tracking-wider text-foreground font-mono uppercase">
                AUTONOMY LEVEL 1 • HUMAN-IN-THE-LOOP GATE
              </h3>
              <p className="text-[11px] text-muted font-light">Signed cryptographic token authorization</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-muted hover:text-foreground hover:bg-hover-bg transition cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 text-xs">
          {/* Action Details */}
          <div className="p-4 rounded-xl bg-background border border-border space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono tracking-wider text-muted">Proposed Defensive Containment</span>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 shadow-[0_0_8px_rgba(255,0,85,0.2)]">
                CRITICAL IMPACT
              </span>
            </div>
            <div className="text-sm font-bold font-mono text-foreground">{proposal.tool_name}</div>
            <div className="text-[11px] text-muted font-light">
              Target: <span className="text-neon-cyan font-mono font-medium">{proposal.target_identity}</span>
            </div>
          </div>

          {/* Rationale & Token */}
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-xl bg-card-secondary border border-border font-mono text-xs">
              <span className="text-muted">SIGNING TOKEN:</span>
              <span className="text-neon-amber font-bold">{tokenInput}</span>
            </div>
            <div>
              <label className="block text-[11px] font-mono font-semibold text-muted mb-1.5 uppercase">
                Analyst Remediation Rationale
              </label>
              <input
                type="text"
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                className="w-full bg-background border border-border rounded-xl px-3.5 py-2 text-xs text-foreground focus:outline-none focus:border-neon-cyan transition font-light"
              />
            </div>
          </div>

          {/* Slide-to-Authorize Physical Security Metaphor */}
          <div className="pt-2 space-y-2">
            <div className="relative h-12 bg-background border border-border rounded-2xl flex items-center px-4 overflow-hidden shadow-inner">
              <div
                className="absolute inset-0 bg-gradient-to-r from-blue-600/20 to-neon-cyan/30 transition-all"
                style={{ width: `${sliderValue}%` }}
              />
              <span className="w-full text-center text-xs font-mono font-bold text-muted pointer-events-none z-10 uppercase tracking-wider">
                {sliderValue >= 90 ? "AUTHORIZING SIGNATURE..." : "SLIDE TO AUTHORIZE EXECUTION ➔"}
              </span>
              <input
                type="range"
                min="0"
                max="100"
                value={sliderValue}
                onChange={handleSliderChange}
                disabled={loading}
                className="absolute inset-0 w-full h-full opacity-0 cursor-ew-resize z-20"
              />
            </div>
          </div>

          {/* Result Alert */}
          {resultMessage && (
            <div
              className={`p-3.5 rounded-xl text-xs font-mono border flex items-center gap-2 ${
                resultMessage.type === "success"
                  ? "bg-emerald-500/10 text-neon-emerald border-emerald-500/30"
                  : "bg-rose-500/10 text-neon-rose border-rose-500/30"
              }`}
            >
              <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {resultMessage.type === "success" ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M5 13l4 4L19 7" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M6 18L18 6M6 6l12 12" />
                )}
              </svg>
              <span>{resultMessage.text}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border flex items-center justify-between bg-card-secondary">
          <button
            onClick={handleReject}
            disabled={loading}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold text-rose-400 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 transition cursor-pointer font-mono"
          >
            REJECT PROPOSAL
          </button>
          <button
            onClick={executeApproval}
            disabled={loading}
            className="px-4 py-2 rounded-xl text-xs font-bold text-black bg-neon-cyan hover:bg-cyan-300 shadow-glow-cyan transition cursor-pointer font-mono uppercase"
          >
            {loading ? "EXECUTING..." : "DIRECT AUTHORIZE"}
          </button>
        </div>
      </div>
    </div>
  );
};
