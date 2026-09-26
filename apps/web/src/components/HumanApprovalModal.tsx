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
  const [tokenInput, setTokenInput] = useState<string>(proposal.token || "");
  const [comments, setComments] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [resultMessage, setResultMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  if (!isOpen) return null;

  const handleApprove = async () => {
    setLoading(true);
    setResultMessage(null);
    try {
      const res = await onApprove(tokenInput.trim(), comments);
      if (res.success) {
        setResultMessage({ type: "success", text: `Action authorized. Audit Record: ${res.audit_id || "AUD-SUCCESS"}` });
        setTimeout(() => {
          onClose();
        }, 1400);
      } else {
        setResultMessage({ type: "error", text: res.error || "Execution authorization denied." });
      }
    } catch (e: any) {
      setResultMessage({ type: "error", text: e.message || "An unexpected error occurred." });
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
        setResultMessage({ type: "success", text: "Action proposal rejected and logged." });
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

  const getRiskBadge = (risk: string) => {
    switch (risk) {
      case "CRITICAL":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-400 border border-rose-200 dark:border-rose-800">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            CRITICAL IMPACT
          </span>
        );
      case "HIGH":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            HIGH IMPACT
          </span>
        );
      case "MEDIUM":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-blue-50 dark:bg-blue-950/60 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-800">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
            MEDIUM IMPACT
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-semibold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
            LOW IMPACT
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 dark:bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="bg-card border border-border rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl transition-all">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-slate-50/50 dark:bg-slate-900/40">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800/60 text-amber-600 dark:text-amber-400">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-foreground font-mono">
                AUTONOMY LEVEL 1 • HUMAN AUTHORIZATION GATE
              </h3>
              <p className="text-[11px] text-muted">Signed cryptographic token authorization required</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-muted hover:text-foreground hover:bg-hover-bg transition"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Action & Risk Details */}
          <div className="flex items-center justify-between p-4 rounded-xl bg-slate-50/70 dark:bg-slate-950/50 border border-border">
            <div>
              <span className="text-[10px] uppercase font-mono tracking-wider text-muted block">Proposed Tool Action</span>
              <div className="text-base font-bold font-mono text-foreground mt-0.5">{proposal.tool_name}</div>
              {proposal.target_identity && (
                <div className="text-xs text-muted mt-1">
                  Target: <span className="text-accent-cyan font-mono font-medium">{proposal.target_identity}</span>
                </div>
              )}
            </div>
            <div>{getRiskBadge(proposal.risk_level)}</div>
          </div>

          {/* Justification & CVE */}
          <div className="p-4 rounded-xl bg-slate-50/50 dark:bg-slate-950/30 border border-border space-y-2.5 text-xs">
            <div>
              <span className="text-muted font-medium">Justification: </span>
              <span className="text-foreground">{proposal.justification}</span>
            </div>
            {proposal.target_cve && (
              <div>
                <span className="text-muted font-medium">Correlated Exploit: </span>
                <span className="text-rose-600 dark:text-rose-400 font-mono font-semibold">{proposal.target_cve}</span>
              </div>
            )}
            <div>
              <span className="text-muted font-medium block mb-1">Execution Parameters:</span>
              <pre className="p-2.5 rounded-lg bg-white dark:bg-slate-900 text-[11px] text-slate-700 dark:text-slate-300 font-mono border border-border overflow-x-auto">
                {JSON.stringify(proposal.parameters, null, 2)}
              </pre>
            </div>
          </div>

          {/* Token Input & Analyst Signature */}
          <div className="space-y-3 pt-1">
            <div>
              <label className="block text-xs font-mono font-medium text-foreground mb-1.5">
                AUTHORIZATION TOKEN
              </label>
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="APP-XXXXXX"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-border rounded-xl px-3.5 py-2.5 text-xs font-mono text-amber-600 dark:text-amber-400 font-bold focus:outline-none focus:border-accent-cyan"
              />
            </div>
            <div>
              <label className="block text-xs font-mono font-medium text-foreground mb-1.5">
                SOC ANALYST REMEDIATION RATIONALE
              </label>
              <input
                type="text"
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                placeholder="e.g. Confirmed zero-click Moniker exploit hash relay link"
                className="w-full bg-slate-50 dark:bg-slate-950 border border-border rounded-xl px-3.5 py-2.5 text-xs text-foreground focus:outline-none focus:border-accent-cyan"
              />
            </div>
          </div>

          {/* Result Alert */}
          {resultMessage && (
            <div
              className={`p-3 rounded-xl text-xs font-mono border flex items-center gap-2 ${
                resultMessage.type === "success"
                  ? "bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800"
                  : "bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-800"
              }`}
            >
              <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                {resultMessage.type === "success" ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                )}
              </svg>
              <span>{resultMessage.text}</span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="px-6 py-4 border-t border-border flex items-center justify-end space-x-3 bg-slate-50/50 dark:bg-slate-900/40">
          <button
            onClick={handleReject}
            disabled={loading || !tokenInput}
            className="px-4 py-2 rounded-xl text-xs font-medium text-rose-600 dark:text-rose-400 bg-rose-50/80 dark:bg-rose-950/30 hover:bg-rose-100 dark:hover:bg-rose-950/60 border border-rose-200 dark:border-rose-800/60 transition disabled:opacity-50 cursor-pointer"
          >
            Reject Action
          </button>
          <button
            onClick={handleApprove}
            disabled={loading || !tokenInput}
            className="px-5 py-2 rounded-xl text-xs font-semibold text-white bg-accent-blue hover:bg-blue-600 shadow-sm transition disabled:opacity-50 cursor-pointer flex items-center gap-2 font-mono"
          >
            {loading ? "Executing..." : "Authorize & Execute"}
          </button>
        </div>
      </div>
    </div>
  );
};
