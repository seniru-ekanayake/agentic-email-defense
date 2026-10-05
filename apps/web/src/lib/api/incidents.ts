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
  const queryParam = options.tenantId ? `?tenant_id=${encodeURIComponent(options.tenantId)}` : '';
  return apiClient<ComprehensiveIncidentRecord[]>(`/api/v1/incidents${queryParam}`, {
    tenantId: options.tenantId,
    method: 'GET',
  });
}

export async function getIncident(
  incidentId: string,
  options: { tenantId?: string } = {}
): Promise<ComprehensiveIncidentRecord> {
  const queryParam = options.tenantId ? `?tenant_id=${encodeURIComponent(options.tenantId)}` : '';
  return apiClient<ComprehensiveIncidentRecord>(`/api/v1/incidents/${encodeURIComponent(incidentId)}${queryParam}`, {
    tenantId: options.tenantId,
    method: 'GET',
  });
}

export async function investigateEmail(
  file: File | Blob,
  filename?: string,
  tenantId: string = 'tenant-enterprise-prod'
): Promise<ComprehensiveIncidentRecord> {
  const formData = new FormData();
  formData.append('file', file, filename || (file instanceof File ? file.name : 'message.eml'));
  formData.append('tenant_id', tenantId);

  return apiClient<ComprehensiveIncidentRecord>('/api/v1/investigate', {
    method: 'POST',
    tenantId,
    body: formData,
    // Do not set Content-Type header so browser automatically sets multipart/form-data boundary
    headers: {},
  });
}

export async function pauseInvestigation(incidentId: string, tenantId?: string): Promise<{ status: string; incident_id: string }> {
  return apiClient<{ status: string; incident_id: string }>(`/api/v1/investigations/${encodeURIComponent(incidentId)}/pause`, {
    method: 'POST',
    tenantId,
  });
}

export async function resumeInvestigation(incidentId: string, tenantId?: string): Promise<{ status: string; incident_id: string }> {
  return apiClient<{ status: string; incident_id: string }>(`/api/v1/investigations/${encodeURIComponent(incidentId)}/resume`, {
    method: 'POST',
    tenantId,
  });
}

export async function cancelInvestigation(incidentId: string, tenantId?: string): Promise<{ status: string; incident_id: string }> {
  return apiClient<{ status: string; incident_id: string }>(`/api/v1/investigations/${encodeURIComponent(incidentId)}/cancel`, {
    method: 'POST',
    tenantId,
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
