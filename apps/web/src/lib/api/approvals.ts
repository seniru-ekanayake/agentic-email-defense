import { apiClient } from './client';
import { ApprovalResponse } from './types';

export interface ApproveOptions {
  tenantId?: string;
}

export interface RejectOptions {
  tenantId?: string;
  reason?: string;
}

export async function approveAction(
  token: string,
  options: ApproveOptions = {}
): Promise<ApprovalResponse> {
  return apiClient<ApprovalResponse>(`/api/v1/approve/${encodeURIComponent(token)}`, {
    method: 'POST',
    tenantId: options.tenantId,
  });
}

export async function rejectAction(
  token: string,
  options: RejectOptions = {}
): Promise<ApprovalResponse> {
  return apiClient<ApprovalResponse>(`/api/v1/reject/${encodeURIComponent(token)}`, {
    method: 'POST',
    tenantId: options.tenantId,
  });
}

export async function requestMoreInfo(
  token: string,
  options: ApproveOptions = {}
): Promise<ApprovalResponse> {
  return apiClient<ApprovalResponse>(`/api/v1/request-info/${encodeURIComponent(token)}`, {
    method: 'POST',
    tenantId: options.tenantId,
  });
}
