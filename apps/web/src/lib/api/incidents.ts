import { apiClient } from './client';
import {
  ComprehensiveIncidentRecord,
  SystemHealthResponse,
  TrustScore,
} from './types';

export interface ListIncidentsOptions {
  tenantId?: string;
}

export async function listIncidents(options: ListIncidentsOptions = {}): Promise<ComprehensiveIncidentRecord[]> {
  return apiClient<ComprehensiveIncidentRecord[]>('/api/v1/incidents', {
    tenantId: options.tenantId,
    method: 'GET',
  });
}

export async function getIncident(
  incidentId: string,
  options: { tenantId?: string } = {}
): Promise<ComprehensiveIncidentRecord> {
  return apiClient<ComprehensiveIncidentRecord>(`/api/v1/incidents/${encodeURIComponent(incidentId)}`, {
    tenantId: options.tenantId,
    method: 'GET',
  });
}

/** Starts a background investigation; follow it with subscribeInvestigationEvents(incident_id). */
export async function startInvestigation(
  file: File | Blob,
  filename?: string
): Promise<{ incident_id: string; status: string; events: string }> {
  const formData = new FormData();
  formData.append('file', file, filename || (file instanceof File ? file.name : 'message.eml'));
  return apiClient<{ incident_id: string; status: string; events: string }>('/api/v1/investigations', {
    method: 'POST',
    body: formData,
    headers: {},
  });
}

export async function investigateEmail(
  file: File | Blob,
  filename?: string,
  tenantId?: string
): Promise<ComprehensiveIncidentRecord> {
  const formData = new FormData();
  formData.append('file', file, filename || (file instanceof File ? file.name : 'message.eml'));

  return apiClient<ComprehensiveIncidentRecord>('/api/v1/investigate', {
    method: 'POST',
    tenantId,
    body: formData,
    // Do not set Content-Type header so browser automatically sets multipart/form-data boundary
    headers: {},
  });
}

export async function replayInvestigation(incidentId: string, tenantId?: string): Promise<any[]> {
  return apiClient<any[]>(`/api/v1/investigations/${encodeURIComponent(incidentId)}/replay`, {
    method: 'POST',
    tenantId,
  });
}

export async function getSystemHealth(): Promise<SystemHealthResponse> {
  return apiClient<SystemHealthResponse>('/api/v1/system-health', {
    method: 'GET',
  });
}

export async function getTrustScore(): Promise<TrustScore> {
  return apiClient<TrustScore>('/api/v1/trust-score', {
    method: 'GET',
  });
}

export async function getPlatformMode(): Promise<{ mode: string }> {
  return apiClient<{ mode: string }>('/api/v1/mode', {
    method: 'GET',
  });
}
