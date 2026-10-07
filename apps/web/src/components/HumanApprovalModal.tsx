"use client";

import React, { useState } from "react";
import { PendingApproval } from "@/lib/api/types";
import { approveAction, rejectAction } from "@/lib/api/approvals";

interface HumanApprovalModalProps {
  proposal: PendingApproval & { target_identity?: string; incident_id?: string };
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: (token: string, message: string) => void;
  tenantId?: string;
}

export const HumanApprovalModal: React.FC<HumanApprovalModalProps> = ({
  proposal,
  isOpen,
  onClose,
  onSuccess,
  tenantId = "tenant-enterprise-prod",
}) => {
  const token = proposal.approval_token;
  const [comments, setComments] = useState<string>("Remediation confirmed by SOC Lead Analyst.");
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
    setLoading(true);
    try {
      const res = await approveAction(token, { tenantId });
      if (res.status === 'DISPATCHED') {
        setResultMessage({
          type: "success",
          text: res.message || `Action authorized with signed cryptographic token: ${token}`,
        });
        if (onSuccess) onSuccess(token, res.message);
        setTimeout(() => {
          onClose();
          setSliderValue(0);
        }, 1500);
      } else {
        setResultMessage({ type: "error", text: res.message || "Execution authorization denied." });
        setSliderValue(0);
      }
    } catch (e: any) {
      if (e?.status === 502) {
        const out = e.data?.detail?.output || {};
        setResultMessage({
          type: "error",
          text: `Approval recorded, but the connector did not confirm the action (${out.status || 'DISPATCH_FAILED'}): ${out.detail || e.message}`,
        });
      } else {
        setResultMessage({ type: "error", text: e.message || "An unexpected error occurred during approval." });
      }
      setSliderValue(0);
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async () => {
    setLoading(true);
    setResultMessage(null);
    try {
      const res = await rejectAction(token, {
        tenantId,
        reason: comments || "Rejected by SOC Analyst",
      });
      if (res.status === 'REJECTED') {
        setResultMessage({ type: "success", text: "Action proposal rejected and recorded in forensic audit log." });
        if (onSuccess) onSuccess(token, "Proposal rejected");
        setTimeout(() => {
          onClose();
        }, 1200);
      } else {
        setResultMessage({ type: "error", text: res.message || "Failed to record rejection." });
      }
    } catch (e: any) {
      setResultMessage({ type: "error", text: e.message || "An unexpected error occurred during rejection." });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 font-sans">
      <div className="bg-white border border-[#e7e9ee] rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl transition-all relative">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#e7e9ee] flex items-center justify-between bg-[#fafbfc]">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-xl bg-amber-50 border border-amber-200 text-amber-600 flex items-center justify-center">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <div>
              <h3 className="text-xs font-bold tracking-wider text-[#111318] font-mono uppercase">
                AUTONOMY LEVEL 1 • HUMAN-IN-THE-LOOP GATE
              </h3>
              <p className="text-[11px] text-[#737986] font-light">Signed cryptographic token authorization</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-[#737986] hover:text-[#111318] hover:bg-[#f2f4f7] transition cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-4 text-xs">
          {/* Action Details */}
          <div className="p-4 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase font-mono tracking-wider text-[#737986]">Proposed Defensive Containment</span>
              <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                proposal.risk_level === 'CRITICAL' || proposal.risk_level === 'HIGH'
                  ? 'bg-rose-50 text-rose-600 border border-rose-200'
                  : 'bg-amber-50 text-amber-600 border border-amber-200'
              }`}>
                {proposal.risk_level} IMPACT
              </span>
            </div>
            <div className="text-sm font-bold font-mono text-[#111318]">{proposal.tool_name}</div>
            {proposal.target_identity && (
              <div className="text-[11px] text-[#737986]">
                Target: <span className="text-[#1d5eea] font-mono font-medium">{proposal.target_identity}</span>
              </div>
            )}
            {proposal.reasoning && (
              <p className="text-[11px] text-[#505660] leading-relaxed pt-1 border-t border-[#e7e9ee]">
                {proposal.reasoning}
              </p>
            )}
            {proposal.parameters && Object.keys(proposal.parameters).length > 0 && (
              <div className="mt-2">
                <span className="text-[10px] uppercase font-mono text-[#a0a5af] block mb-1">Execution Parameters:</span>
                <pre className="text-[10px] font-mono bg-white p-2 rounded border border-[#e7e9ee] overflow-x-auto text-[#505660]">
                  {JSON.stringify(proposal.parameters, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Rationale & Token */}
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 rounded-xl bg-[#fafbfc] border border-[#e7e9ee] font-mono text-xs">
              <span className="text-[#737986]">SIGNING TOKEN:</span>
              <span className="text-amber-600 font-bold">{token}</span>
            </div>
            <div>
              <label className="block text-[11px] font-mono font-semibold text-[#737986] mb-1.5 uppercase">
                Analyst Remediation Rationale
              </label>
              <input
                type="text"
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                className="w-full bg-white border border-[#e7e9ee] rounded-xl px-3.5 py-2 text-xs text-[#111318] focus:outline-none focus:border-[#1d5eea] transition"
              />
            </div>
          </div>

          {/* Slide-to-Authorize Metaphor */}
          <div className="pt-2 space-y-2">
            <div className="relative h-12 bg-[#f4f5f8] border border-[#e7e9ee] rounded-2xl flex items-center px-4 overflow-hidden shadow-inner">
              <div
                className="absolute inset-0 bg-blue-100 transition-all"
                style={{ width: `${sliderValue}%` }}
              />
              <span className="w-full text-center text-xs font-mono font-bold text-[#737986] pointer-events-none z-10 uppercase tracking-wider">
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
                  ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                  : "bg-rose-50 text-rose-700 border-rose-200"
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
        <div className="px-6 py-4 border-t border-[#e7e9ee] flex items-center justify-between bg-[#fafbfc]">
          <button
            onClick={handleReject}
            disabled={loading}
            className="px-3.5 py-2 rounded-xl text-xs font-semibold text-rose-600 bg-rose-50 hover:bg-rose-100 border border-rose-200 transition cursor-pointer font-mono"
          >
            REJECT PROPOSAL
          </button>
          <button
            onClick={executeApproval}
            disabled={loading}
            className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-[#111318] hover:bg-[#252830] transition cursor-pointer font-mono uppercase"
          >
            {loading ? "EXECUTING..." : "DIRECT AUTHORIZE"}
          </button>
        </div>
      </div>
    </div>
  );
};
