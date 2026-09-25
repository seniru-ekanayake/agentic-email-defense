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
        setResultMessage({ type: "success", text: `Action executed successfully! Audit ID: ${res.audit_id || "N/A"}` });
        setTimeout(() => {
          onClose();
        }, 1500);
      } else {
        setResultMessage({ type: "error", text: res.error || "Execution failed or authorization denied." });
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
        setResultMessage({ type: "success", text: "Action proposal successfully rejected." });
        setTimeout(() => {
          onClose();
        }, 1200);
      } else {
        setResultMessage({ type: "error", text: res.error || "Failed to reject proposal." });
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
        return <span className="bg-red-950 text-red-400 border border-red-600 px-2.5 py-1 rounded text-xs font-bold font-mono">CRITICAL RISK</span>;
      case "HIGH":
        return <span className="bg-orange-950 text-orange-400 border border-orange-600 px-2.5 py-1 rounded text-xs font-bold font-mono">HIGH RISK</span>;
      case "MEDIUM":
        return <span className="bg-yellow-950 text-yellow-400 border border-yellow-600 px-2.5 py-1 rounded text-xs font-bold font-mono">MEDIUM RISK</span>;
      default:
        return <span className="bg-blue-950 text-blue-400 border border-blue-600 px-2.5 py-1 rounded text-xs font-bold font-mono">LOW RISK</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-xl overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="bg-slate-800/90 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <span className="w-3 h-3 rounded-full bg-amber-500 animate-pulse" />
            <h3 className="text-base font-bold text-white font-mono">POLICY-GATED HUMAN AUTHORIZATION</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Action & Risk Details */}
          <div className="flex items-center justify-between bg-slate-950 p-4 rounded-xl border border-slate-800">
            <div>
              <p className="text-xs text-slate-400 font-mono">PROPOSED DEFENSIVE ACTION</p>
              <h4 className="text-lg font-bold text-slate-100 font-mono">{proposal.tool_name}</h4>
              {proposal.target_identity && (
                <p className="text-xs text-slate-300 mt-1">Target: <span className="text-blue-400 font-mono">{proposal.target_identity}</span></p>
              )}
            </div>
            <div>{getRiskBadge(proposal.risk_level)}</div>
          </div>

          {/* Justification & CVE */}
          <div className="bg-slate-950/60 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
            <div>
              <span className="text-slate-400 font-semibold">Justification: </span>
              <span className="text-slate-200">{proposal.justification}</span>
            </div>
            {proposal.target_cve && (
              <div>
                <span className="text-slate-400 font-semibold">Correlated Vulnerability: </span>
                <span className="text-red-400 font-mono">{proposal.target_cve}</span>
              </div>
            )}
            <div>
              <span className="text-slate-400 font-semibold">Action Parameters: </span>
              <pre className="mt-1 bg-slate-900 p-2 rounded text-[11px] text-slate-300 font-mono border border-slate-800">
                {JSON.stringify(proposal.parameters, null, 2)}
              </pre>
            </div>
          </div>

          {/* Token Input & Analyst Signature */}
          <div className="space-y-3 pt-2">
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                SIGNED AUTHORIZATION TOKEN (REQUIRED)
              </label>
              <input
                type="text"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="APP-XXXXXX"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-amber-300 focus:outline-none focus:border-amber-500"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-slate-300 mb-1">
                SOC ANALYST REMEDIATION NOTES (OPTIONAL)
              </label>
              <input
                type="text"
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                placeholder="e.g., Authorized after secondary out-of-band identity check"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Result Alert */}
          {resultMessage && (
            <div
              className={`p-3 rounded-lg text-xs font-mono border ${
                resultMessage.type === "success"
                  ? "bg-emerald-950/80 text-emerald-300 border-emerald-600"
                  : "bg-red-950/80 text-red-300 border-red-600"
              }`}
            >
              {resultMessage.text}
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div className="bg-slate-800/90 border-t border-slate-700 px-6 py-4 flex items-center justify-end space-x-3">
          <button
            onClick={handleReject}
            disabled={loading || !tokenInput}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-red-300 bg-red-950/60 hover:bg-red-900 border border-red-700 transition disabled:opacity-50"
          >
            Deny Action
          </button>
          <button
            onClick={handleApprove}
            disabled={loading || !tokenInput}
            className="px-5 py-2 rounded-lg text-xs font-bold text-slate-900 bg-emerald-400 hover:bg-emerald-300 shadow-md transition disabled:opacity-50 font-mono flex items-center gap-1.5"
          >
            {loading ? "Executing..." : "Authorize & Execute Action"}
          </button>
        </div>
      </div>
    </div>
  );
};
