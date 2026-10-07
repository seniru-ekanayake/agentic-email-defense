'use client';

import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  ComprehensiveIncidentRecord,
  AgentLifecycleEvent,
  PendingApproval,
  SystemHealthResponse,
  TrustScore,
} from '@/lib/api/types';
import {
  listIncidents,
  getIncident,
  startInvestigation,
  getSystemHealth,
  getTrustScore,
  getPlatformMode,
} from '@/lib/api/incidents';
import { subscribeInvestigationEvents } from '@/lib/api/events';
import { PixelAgents, moodFromEvent } from '@/components/PixelAgents';
import { getAuthToken, setAuthToken, getTokenTenant } from '@/lib/api/client';
import { AgentLiveStreamVisualizer } from '@/components/AgentLiveStreamVisualizer';
import { AttackGraphVisualizer } from '@/components/AttackGraphVisualizer';
import { IncidentDetailModal } from '@/components/IncidentDetailModal';
import { HumanApprovalModal } from '@/components/HumanApprovalModal';
import { ExposureView } from '@/components/ExposureView';

export default function DashboardPage() {
  const [activeNav, setActiveNav] = useState<'overview' | 'stream' | 'triage' | 'graph' | 'surface' | 'governance'>('overview');
  
  // Authoritative State from Backend
  const [incidentList, setIncidentList] = useState<ComprehensiveIncidentRecord[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<ComprehensiveIncidentRecord | null>(null);
  const [activeProposal, setActiveProposal] = useState<(PendingApproval & { target_identity?: string; incident_id?: string }) | null>(null);
  const [approvalModalOpen, setApprovalModalOpen] = useState(false);
  const [systemHealth, setSystemHealth] = useState<SystemHealthResponse | null>(null);
  const [trustScore, setTrustScore] = useState<TrustScore | null>(null);
  const [platformMode, setPlatformMode] = useState<string>('PRODUCTION');

  // Loading & Error States
  const [loading, setLoading] = useState<boolean>(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [tenantId, setTenantId] = useState<string>('');

  // Search & Filtering
  const [searchFilter, setSearchFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');

  // Live SSE Stream Events
  const [events, setEvents] = useState<AgentLifecycleEvent[]>([]);
  const [isStreaming, setIsStreaming] = useState<boolean>(false);
  const [activeStreamingIncidentId, setActiveStreamingIncidentId] = useState<string | null>(null);
  const [uploadLoading, setUploadLoading] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sseUnsubscribeRef = useRef<(() => void) | null>(null);

  const [tokenInput, setTokenInput] = useState<string>('');
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);

  // Sync token from storage on mount
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = getAuthToken();
      if (stored) {
        setTokenInput(stored);
        setTenantId(getTokenTenant(stored) || '');
      }
    }
  }, []);

  // Fetch initial ledger and backend health
  const refreshLedger = useCallback(async () => {
    try {
      setLoading(true);
      setBackendError(null);
      const [incidents, health, trust, mode] = await Promise.allSettled([
        listIncidents({ tenantId }),
        getSystemHealth(),
        getTrustScore(),
        getPlatformMode(),
      ]);

      if (incidents.status === 'fulfilled') {
        setIncidentList(incidents.value || []);
      } else {
        const errMsg = incidents.reason?.message || 'Failed to connect to backend server at http://localhost:8000';
        setIncidentList([]);
        throw new Error(errMsg);
      }

      if (health.status === 'fulfilled') setSystemHealth(health.value);
      if (trust.status === 'fulfilled') setTrustScore(trust.value);
      if (mode.status === 'fulfilled') setPlatformMode(mode.value.mode);
    } catch (err: any) {
      console.error('Error fetching incident ledger:', err);
      setBackendError(err.message || 'Unable to communicate with FishingMails API');
    } finally {
      setLoading(false);
    }
  }, [tenantId]);

  useEffect(() => {
    refreshLedger();
  }, [refreshLedger]);

  // Clean up SSE connection on unmount
  useEffect(() => {
    return () => {
      if (sseUnsubscribeRef.current) {
        sseUnsubscribeRef.current();
      }
    };
  }, []);

  // Subscribe to live SSE events for a specific investigation
  const subscribeToIncidentStream = useCallback((incidentId: string) => {
    if (sseUnsubscribeRef.current) {
      sseUnsubscribeRef.current();
      sseUnsubscribeRef.current = null;
    }

    setIsStreaming(true);
    setActiveStreamingIncidentId(incidentId);

    const unsubscribe = subscribeInvestigationEvents(incidentId, {
      onOpen: () => {
        setIsStreaming(true);
      },
      onEvent: (event) => {
        setEvents((prev) => [...prev, event]);
        if (event.event_type === 'agent.failed') {
          setBackendError(event.message);
        }
        if (event.event_type === 'agent.proposal.created' && event.data?.approval_token) {
          setActiveProposal({
            approval_token: event.data.approval_token,
            tool_name: event.data.tool_name || event.tool || 'quarantine_email',
            risk_level: event.data.risk_level || 'HIGH',
            parameters: event.data.parameters || {},
            reasoning: event.message,
            target_identity: event.data.target_identity,
            incident_id: incidentId,
          });
          setApprovalModalOpen(true);
        }
      },
      onError: (err) => {
        console.warn('SSE stream notice:', err);
      },
      onClose: async () => {
        setIsStreaming(false);
        refreshLedger();
        try {
          const finished = await getIncident(incidentId, { tenantId });
          setSelectedIncident(finished);
        } catch {
          // A failed investigation has no incident record; the stream already showed agent.failed.
        }
      },
    });

    sseUnsubscribeRef.current = unsubscribe;
  }, [refreshLedger]);

  // Genuine EML File Upload Ingestion
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      setUploadLoading(true);
      setBackendError(null);
      setEvents([]);
      setActiveNav('stream');

      // Start the investigation in the background and follow it live; proposals arrive as stream events.
      const started = await startInvestigation(file, file.name);
      subscribeToIncidentStream(started.incident_id);
    } catch (err: any) {
      console.error('File upload investigation failed:', err);
      setBackendError(`Investigation failed: ${err.message}`);
    } finally {
      setUploadLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Dynamically Computed Metrics directly from real incidents
  const metrics = useMemo(() => {
    const total = incidentList.length;
    const threats = incidentList.filter((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH').length;
    const pendingApprovalCount = incidentList.reduce(
      (acc, curr) => acc + (curr.pending_approvals?.length || 0),
      0
    );
    const avgConfidence = total > 0
      ? (incidentList.reduce((acc, curr) => acc + (curr.confidence || 0.9), 0) / total)
      : 0;

    return {
      totalAnalyzed: total.toLocaleString(),
      threatsCount: threats.toLocaleString(),
      pendingApprovals: pendingApprovalCount,
      confidenceRate: `${(avgConfidence * 100).toFixed(1)}%`,
    };
  }, [incidentList]);

  // Real Threat Categories Grouped from Database
  const threatCategories = useMemo(() => {
    const counts: Record<string, number> = {};
    incidentList.forEach((inc) => {
      const cat = inc.threat_category || 'General Anomaly';
      counts[cat] = (counts[cat] || 0) + 1;
    });

    const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    const max = entries[0]?.[1] || 1;

    return entries.slice(0, 5).map(([name, count]) => ({
      name,
      count: count.toString().padStart(2, '0'),
      progress: Math.min(100, Math.round((count / max) * 100)),
    }));
  }, [incidentList]);

  // Filtered Incident Matrix
  const filteredIncidents = useMemo(() => {
    return incidentList.filter((item) => {
      const matchSearch =
        (item.sender || '').toLowerCase().includes(searchFilter.toLowerCase()) ||
        (item.subject || '').toLowerCase().includes(searchFilter.toLowerCase()) ||
        (item.incident_id || '').toLowerCase().includes(searchFilter.toLowerCase()) ||
        (item.threat_category || '').toLowerCase().includes(searchFilter.toLowerCase());

      const matchSeverity = severityFilter === 'ALL' || item.severity === severityFilter;
      return matchSearch && matchSeverity;
    });
  }, [incidentList, searchFilter, severityFilter]);

  // Load Deep Detail for selected incident
  const handleSelectIncident = async (incident: ComprehensiveIncidentRecord) => {
    setSelectedIncident(incident);
    try {
      const detail = await getIncident(incident.incident_id, { tenantId });
      setSelectedIncident(detail);
      // If incident has recorded events, load them into stream view
      if (detail.events && detail.events.length > 0) {
        setEvents(detail.events);
      }
    } catch (err) {
      console.warn('Could not load deep detail for incident, using ledger row:', err);
    }
  };

  return (
    <div className="flex min-h-screen bg-[#f7f8fa] text-[#111318]">
      {/* Hidden File Input for Real Email Payload Ingestion */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".eml,.msg,message/rfc822"
        className="hidden"
      />

      {/* 1. Left Fixed Sidebar */}
      <aside className="w-[236px] bg-white border-r border-[#e7e9ee] p-[22px_14px] fixed inset-y-0 left-0 z-30 flex flex-col justify-between">
        <div>
          {/* Brand */}
          <div className="flex items-center gap-2.5 px-2.5 pb-6">
            <div className="w-[30px] h-[30px] rounded-[9px] bg-[#111318] grid place-items-center text-white text-sm font-extrabold overflow-hidden">
              <span className="font-mono text-xs">FM</span>
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
        <div className="border-t border-[#e7e9ee] pt-3.5 space-y-2">
          <div className="px-2.5">
            <div className="flex items-center justify-between mb-1">
              <label className="text-[10px] uppercase font-bold text-[#a0a5af]">Authenticated Tenant</label>
              <span className="text-[9px] font-mono text-[#16945b] bg-[#eef8f2] px-1.5 py-0.5 rounded">VERIFIED</span>
            </div>
            <div className="w-full text-xs font-mono bg-[#f4f5f8] border border-[#e7e9ee] rounded px-2 py-1.5 text-[#111318] truncate flex items-center justify-between">
              <span>{tenantId}</span>
              <span className="text-[10px] text-[#737986]" title="Tenant context is cryptographically bound to authenticated session">🔒</span>
            </div>
          </div>
          <div className="flex items-center gap-2.5 px-2.5 py-1.5">
            <div className="w-7 h-7 rounded-full bg-[#e9edf3] grid place-items-center text-[10px] font-bold text-[#111318]">
              SE
            </div>
            <div className="flex-1 truncate text-left">
              <b className="text-xs text-[#111318] block leading-tight truncate">{tenantId}</b>
              <small className="text-[10px] text-[#737986] block leading-tight">Seniru Ekanayake</small>
            </div>
            <span className="text-[#16945b] text-[10px] font-bold">● L1</span>
          </div>
        </div>
      </aside>

      {/* 2. Main Content Area */}
      <main className="ml-[236px] w-[calc(100%-236px)] p-[30px_36px_44px] max-w-[1600px]">
        {/* Backend Connectivity Banner */}
        {backendError && (
          <div className="mb-6 p-4 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-rose-600 animate-pulse" />
              <span>BACKEND ERROR: {backendError}</span>
            </div>
            <button
              onClick={refreshLedger}
              className="px-3 py-1 bg-white border border-rose-300 rounded font-bold hover:bg-rose-100 transition"
            >
              RETRY CONNECTION
            </button>
          </div>
        )}

        {/* Header */}
        <header className="flex items-start justify-between mb-7">
          <div>
            <div className="flex items-center gap-2 text-xs text-[#737986] mb-1.5 font-medium">
              <span>SOC Operations</span>
              <span>&middot;</span>
              <span className="font-mono text-[#16945b] font-bold">
                Backend: {systemHealth ? systemHealth.status : (backendError ? 'OFFLINE' : 'CONNECTING...')}
              </span>
              <span>&middot;</span>
              <span className="font-mono text-[#111318]">Mode: {platformMode}</span>
            </div>
            <h1 className="text-[27px] font-bold tracking-[-0.04em] m-0 text-[#111318]">Threat Operations</h1>
            <div className="text-[13px] text-[#737986] mt-1.5 font-normal">
              Evidence-based email triage with analyst-approved containment.
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => setShowAuthModal(true)}
              className="border border-[#e7e9ee] bg-white px-3.5 py-2.5 rounded-lg text-xs font-medium text-[#535963] shadow-[0_1px_1px_rgba(0,0,0,0.02)] hover:bg-[#f7f8fa] transition cursor-pointer flex items-center gap-1.5"
              title="Configure Authentication Token & Tenant"
            >
              <span>🔑 Session Auth</span>
            </button>
            <button
              onClick={refreshLedger}
              disabled={loading}
              className="border border-[#e7e9ee] bg-white px-3.5 py-2.5 rounded-lg text-xs font-medium text-[#535963] shadow-[0_1px_1px_rgba(0,0,0,0.02)] hover:bg-[#f7f8fa] transition cursor-pointer flex items-center gap-1.5"
            >
              <span>{loading ? '↻ Syncing...' : '↻ Refresh Ledger'}</span>
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploadLoading}
              className="bg-[#111318] text-white border border-[#111318] px-3.5 py-2.5 rounded-lg text-xs font-semibold shadow-sm hover:bg-[#252830] transition cursor-pointer flex items-center gap-1.5"
            >
              <span>{uploadLoading ? 'Ingesting EML...' : '+ Upload & Investigate EML'}</span>
            </button>
          </div>
        </header>

        {/* View Routing */}
        {activeNav === 'stream' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">
                  Investigation Event Stream
                  {activeStreamingIncidentId && (
                    <span className="text-xs font-mono font-normal text-[#737986] ml-2">
                      ({activeStreamingIncidentId})
                    </span>
                  )}
                </h2>
                <p className="text-xs text-[#737986]">Planner decisions, tool executions and evidence recorded for this investigation</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AgentLiveStreamVisualizer
              events={events}
              isStreaming={isStreaming}
              onClear={() => setEvents([])}
            />
          </div>
        ) : activeNav === 'graph' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">Attack Graph Topology</h2>
                <p className="text-xs text-[#737986]">Traversing multi-hop lateral movement from threat actors to target identities</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <AttackGraphVisualizer incident={selectedIncident || incidentList[0] || null} />
          </div>
        ) : activeNav === 'surface' ? (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#111318]">Asset Exposure Radar</h2>
                <p className="text-xs text-[#737986]">Continuous mail infrastructure exposure and exploitability tracking</p>
              </div>
              <button onClick={() => setActiveNav('overview')} className="text-xs text-[#2563eb] font-semibold hover:underline">
                ← Back to Overview
              </button>
            </div>
            <ExposureView incidents={incidentList} />
          </div>
        ) : activeNav === 'governance' ? (
          <div className="bg-white border border-[#e7e9ee] rounded-xl p-6 shadow-sm space-y-5 font-sans">
            <div className="flex items-center justify-between border-b border-[#e7e9ee] pb-4">
              <div>
                <h3 className="text-sm font-bold text-[#111318]">Tenant Autonomy & Response Governance (L0–L4)</h3>
                <p className="text-xs text-[#737986]">Active Policy: Autonomy Level 1 (Human Authorization Required for High/Critical actions)</p>
              </div>
              <span className="text-xs bg-[#eaf8f1] text-[#16945b] font-bold px-3 py-1 rounded-full">
                Active Policy: Level 1
              </span>
            </div>

            {/* Trust Score Card */}
            {trustScore && (
              <div className="p-4 rounded-xl bg-[#f8fafc] border border-[#e7e9ee] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-[#737986] uppercase">Agent Trust Score</span>
                  <span className="text-lg font-mono font-bold text-[#16945b]">
                    {trustScore.overall_score}% (Grade: {trustScore.grade})
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {trustScore.components?.map((c, idx) => (
                    <div key={idx} className="p-3 bg-white border border-[#e7e9ee] rounded-lg">
                      <div className="text-[11px] font-bold text-[#111318]">{c.name}</div>
                      <div className="text-[10px] text-[#737986] mt-0.5">{c.metric_value}</div>
                      <div className="text-xs font-mono font-bold text-[#1d5eea] mt-1">{c.score}%</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Pending Approvals Queue */}
            <div className="space-y-3">
              <h4 className="text-xs font-mono font-bold uppercase text-[#737986]">
                Pending Human Approval Tokens across Tenant ({metrics.pendingApprovals})
              </h4>
              <div className="divide-y divide-[#e7e9ee] border border-[#e7e9ee] rounded-xl overflow-hidden bg-white">
                {incidentList.flatMap((inc) => (inc.pending_approvals || []).map((appr) => ({ ...appr, incident: inc }))).length === 0 ? (
                  <div className="p-6 text-center text-xs text-[#a0a5af] font-mono">
                    Zero pending actions awaiting authorization. All policies currently satisfied.
                  </div>
                ) : (
                  incidentList.flatMap((inc) => (inc.pending_approvals || []).map((appr) => ({ ...appr, incident: inc }))).map((item, idx) => (
                    <div key={idx} className="p-4 flex items-center justify-between hover:bg-[#f8fafc] transition">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold font-mono text-[#111318]">{item.tool_name}</span>
                          <span className="text-[10px] font-mono font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                            Token: {item.approval_token}
                          </span>
                          <span className="text-[10px] font-mono text-[#737986]">
                            Incident: {item.incident.incident_id}
                          </span>
                        </div>
                        <p className="text-xs text-[#737986] mt-1">{item.reasoning}</p>
                      </div>
                      <button
                        onClick={() => {
                          setActiveProposal({
                            approval_token: item.approval_token,
                            tool_name: item.tool_name,
                            risk_level: item.risk_level,
                            parameters: item.parameters,
                            reasoning: item.reasoning,
                            target_identity: item.incident.target_identity || item.incident.recipient,
                            incident_id: item.incident.incident_id,
                          });
                          setApprovalModalOpen(true);
                        }}
                        className="px-3 py-1.5 bg-[#111318] hover:bg-[#252830] text-white rounded-lg text-xs font-mono uppercase font-bold transition"
                      >
                        Authorize Token
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ) : (
          <>
            {isStreaming && (
              <button
                type="button"
                onClick={() => setActiveNav('stream')}
                className="block w-full text-left mb-3.5"
                title="Open the live investigation"
              >
                <PixelAgents mood={moodFromEvent(events[events.length - 1]?.event_type, isStreaming)} compact />
              </button>
            )}
            {/* Top Metrics Row */}
            <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-3.5">
              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-sm">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Durable Incidents</span>
                  <span>Database State</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.totalAnalyzed}</div>
                <div className="text-[11px] text-[#16945b] font-medium">Loaded from SQLite backend</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-sm">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>High / Critical Threats</span>
                  <span>Active Alerts</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.threatsCount}</div>
                <div className="text-[11px] text-[#d04444] font-medium">Severity HIGH or CRITICAL</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-sm">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Pending Containments</span>
                  <span>Policy Gate (L1)</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.pendingApprovals}</div>
                <div className="text-[11px] text-[#b7791f] font-medium">Awaiting analyst approval</div>
              </div>

              <div className="bg-white border border-[#e7e9ee] rounded-xl p-[18px_19px] shadow-sm">
                <div className="flex justify-between text-[#737986] text-xs font-medium">
                  <span>Mean Detection Confidence</span>
                  <span>Verdict engine</span>
                </div>
                <div className="text-[27px] font-bold tracking-[-0.045em] my-3 text-[#111318]">{metrics.confidenceRate}</div>
                <div className="text-[11px] text-[#16945b] font-medium">Mean verdict confidence</div>
              </div>
            </section>

            {/* Bottom Grid: Live Threat Triage Matrix & Threat Vectors */}
            <section className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.75fr)_minmax(300px,0.75fr)] gap-3.5">
              {/* Recent Investigations Table */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-sm overflow-hidden">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div>
                    <div className="text-[13px] font-bold text-[#111318]">Live Threat Triage Matrix</div>
                    <div className="text-[11px] text-[#737986]">
                      Click any incident to inspect attack graph, evidence & containment
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      placeholder="Filter sender, vector..."
                      value={searchFilter}
                      onChange={(e) => setSearchFilter(e.target.value)}
                      className="text-xs border border-[#e7e9ee] rounded-lg px-2.5 py-1 text-[#505660] bg-white outline-none w-40"
                    />
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value as any)}
                      className="text-xs border border-[#e7e9ee] rounded-lg px-2.5 py-1 text-[#505660] bg-white outline-none"
                    >
                      <option value="ALL">All Severities</option>
                      <option value="CRITICAL">Critical</option>
                      <option value="HIGH">High</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="LOW">Low</option>
                    </select>
                  </div>
                </div>

                <div className="overflow-x-auto max-h-[500px]">
                  <table className="w-full border-collapse">
                    <thead className="sticky top-0 bg-[#fafbfc] border-b border-[#e7e9ee] z-10">
                      <tr>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Sender / Subject
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Threat Vector
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Severity
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Risk Score
                        </th>
                        <th className="text-left text-[10px] text-[#969ba5] uppercase tracking-[0.06em] font-[650] p-[13px_17px]">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#e7e9ee]">
                      {filteredIncidents.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="p-8 text-center text-xs text-[#737986] font-mono">
                            {loading ? 'Fetching incidents from backend...' : 'No incidents match the selected filter.'}
                          </td>
                        </tr>
                      ) : (
                        filteredIncidents.map((item) => (
                          <tr
                            key={item.incident_id}
                            onClick={() => handleSelectIncident(item)}
                            className="hover:bg-[#f8fafc] transition-colors cursor-pointer"
                          >
                            <td className="p-[13px_17px]">
                              <span className="font-[650] text-[#20232a] text-[11px] block">{item.sender}</span>
                              <small className="block text-[#989da7] font-normal text-[10px] mt-0.5 truncate max-w-xs">
                                {item.subject || item.title}
                              </small>
                            </td>
                            <td className="p-[13px_17px] text-[11px] font-medium text-[#505660]">
                              {item.threat_category}
                            </td>
                            <td className="p-[13px_17px]">
                              <span
                                className={`inline-flex items-center px-2 py-0.5 rounded-full text-[9px] font-bold ${
                                  item.severity === 'CRITICAL'
                                    ? 'bg-rose-50 text-rose-600'
                                    : item.severity === 'HIGH'
                                    ? 'bg-orange-50 text-orange-600'
                                    : 'bg-blue-50 text-blue-600'
                                }`}
                              >
                                {item.severity}
                              </span>
                            </td>
                            <td className="p-[13px_17px] text-[11px] font-mono font-bold text-[#111318]">
                              {item.overall_risk_score}
                            </td>
                            <td className="p-[13px_17px]">
                              {item.pending_approvals && item.pending_approvals.length > 0 ? (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    const appr = item.pending_approvals[0];
                                    setActiveProposal({
                                      ...appr,
                                      target_identity: item.target_identity || item.recipient,
                                      incident_id: item.incident_id,
                                    });
                                    setApprovalModalOpen(true);
                                  }}
                                  className="px-2 py-1 bg-amber-500 hover:bg-amber-600 text-white text-[10px] font-mono uppercase font-bold rounded shadow-sm transition"
                                >
                                  Authorize
                                </button>
                              ) : (
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    subscribeToIncidentStream(item.incident_id);
                                    setActiveNav('stream');
                                  }}
                                  className="text-[10px] font-mono text-[#1d5eea] hover:underline"
                                >
                                  Stream SSE
                                </button>
                              )}
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Threat Vectors Card */}
              <div className="bg-white border border-[#e7e9ee] rounded-xl shadow-sm pb-2">
                <div className="flex justify-between items-center p-[17px_19px] border-b border-[#e7e9ee]">
                  <div className="text-[13px] font-bold text-[#111318]">Discovered Threat Vectors</div>
                  <div className="text-[11px] text-[#737986] font-medium">Aggregated across SQLite</div>
                </div>
                <div className="divide-y divide-[#e7e9ee]">
                  {threatCategories.map((item, idx) => (
                    <div key={idx} className="flex items-center gap-3 p-[12px_18px]">
                      <div className="text-[15px] font-bold text-[#111318] w-6 font-mono">{item.count}</div>
                      <div className="flex-1 truncate">
                        <b className="text-[11px] text-[#111318] block truncate">{item.name}</b>
                        <span className="text-[10px] text-[#737986]">Observed incident telemetry</span>
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
          onTriggerContainment={(proposal) => {
            setActiveProposal({
              ...proposal,
              target_identity: selectedIncident.target_identity || selectedIncident.recipient,
              incident_id: selectedIncident.incident_id,
            });
            setSelectedIncident(null);
            setApprovalModalOpen(true);
          }}
          onApproveSuccess={refreshLedger}
        />
      )}

      {/* 4. Slide-to-Authorize Human Approval Modal */}
      {activeProposal && (
        <HumanApprovalModal
          isOpen={approvalModalOpen}
          onClose={() => setApprovalModalOpen(false)}
          proposal={activeProposal}
          tenantId={tenantId}
          onSuccess={() => {
            refreshLedger();
          }}
        />
      )}

      {/* 5. Production Session Authentication Configuration Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-lg w-full p-6 border border-[#e7e9ee] space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#e7e9ee]">
              <div className="flex items-center gap-2">
                <span className="text-lg">🔑</span>
                <h3 className="font-bold text-[#111318] text-base">SOC Analyst Authentication</h3>
              </div>
              <button
                onClick={() => setShowAuthModal(false)}
                className="text-[#737986] hover:text-[#111318] text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-[#737986] leading-relaxed">
              Paste a JWT issued by your identity provider. The tenant is taken from the token's tenant_id claim.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-[11px] font-bold text-[#535963] uppercase tracking-wider mb-1">
                  Tenant (from token)
                </label>
                <div className="w-full text-xs font-mono p-2.5 bg-[#f8fafc] border border-[#e7e9ee] rounded-lg">
                  {getTokenTenant(tokenInput) || 'No valid token'}
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-bold text-[#535963] uppercase tracking-wider mb-1">
                  Bearer JWT
                </label>
                <textarea
                  rows={4}
                  value={tokenInput}
                  onChange={(e) => setTokenInput(e.target.value.trim())}
                  placeholder="Paste eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                  className="w-full text-xs font-mono p-2.5 bg-[#f8fafc] border border-[#e7e9ee] rounded-lg outline-none focus:border-blue-500 resize-none break-all"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-[#e7e9ee]">
              <button
                onClick={() => {
                  setTokenInput('');
                  if (typeof window !== 'undefined') {
                    localStorage.removeItem('fishingmails_auth_token');
                    sessionStorage.removeItem('fishingmails_auth_token');
                  }
                }}
                className="text-xs text-rose-600 font-medium hover:underline"
              >
                Clear Token
              </button>

              <div className="flex gap-2">
                <button
                  onClick={() => setShowAuthModal(false)}
                  className="px-3.5 py-2 text-xs font-medium text-[#535963] hover:bg-[#f7f8fa] rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    if (tokenInput) {
                      setAuthToken(tokenInput);
                      setTenantId(getTokenTenant(tokenInput) || '');
                    }
                    setShowAuthModal(false);
                    refreshLedger();
                  }}
                  className="px-4 py-2 bg-[#111318] hover:bg-[#252830] text-white rounded-lg text-xs font-bold transition shadow-sm"
                >
                  Apply & Sync
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
