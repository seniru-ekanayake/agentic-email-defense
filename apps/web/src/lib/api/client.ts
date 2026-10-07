/**
 * Centralized HTTP Client for FishingMails API
 * Supports configurable API URL, tenant context headers, timeouts, and error handling.
 */

const DEFAULT_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface RequestOptions extends RequestInit {
  tenantId?: string;
  timeoutMs?: number;
}

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export function getAuthToken(): string | null {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('fishingmails_auth_token') || sessionStorage.getItem('fishingmails_auth_token') || null;
  }
  return process.env.NEXT_PUBLIC_AUTH_TOKEN || null;
}

/** Reads the tenant claim from the stored JWT (display only; the server derives the tenant itself). */
export function getTokenTenant(token?: string | null): string | null {
  const t = token ?? getAuthToken();
  if (!t) return null;
  try {
    const payload = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), '=')));
    return typeof claims.tenant_id === 'string' ? claims.tenant_id : null;
  } catch {
    return null;
  }
}

export function setAuthToken(token: string): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('fishingmails_auth_token', token);
    sessionStorage.setItem('fishingmails_auth_token', token);
  }
}

export function clearAuthToken(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('fishingmails_auth_token');
    sessionStorage.removeItem('fishingmails_auth_token');
  }
}

export async function apiClient<T>(
  endpoint: string,
  options: RequestOptions = {}
): Promise<T> {
  const { tenantId, timeoutMs = 25000, headers = {}, ...fetchOpts } = options;

  const url = endpoint.startsWith('http') ? endpoint : `${DEFAULT_BASE_URL}${endpoint}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const requestHeaders = new Headers(headers);
  if (!requestHeaders.has('Accept')) {
    requestHeaders.set('Accept', 'application/json');
  }
  if (!requestHeaders.has('Authorization')) {
    const token = getAuthToken();
    if (token) {
      requestHeaders.set('Authorization', `Bearer ${token}`);
    }
  }
  if (tenantId && !requestHeaders.has('X-Tenant-ID')) {
    requestHeaders.set('X-Tenant-ID', tenantId);
  }

  try {
    const response = await fetch(url, {
      ...fetchOpts,
      headers: requestHeaders,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      let errorBody: any = null;
      try {
        errorBody = await response.json();
      } catch {
        errorBody = await response.text();
      }
      const detail = typeof errorBody === 'object' ? errorBody?.detail : undefined;
      const message =
        (typeof detail === 'string' && detail) ||
        (typeof detail === 'object' && detail?.message) ||
        (typeof errorBody === 'object' && errorBody?.message) ||
        `HTTP ${response.status}: ${response.statusText}`;
      throw new ApiError(response.status, message, errorBody);
    }

    // Parse JSON
    return (await response.json()) as T;
  } catch (error: any) {
    clearTimeout(timeoutId);
    if (error.name === 'AbortError') {
      throw new ApiError(408, `Request timed out after ${timeoutMs}ms: ${endpoint}`);
    }
    if (error instanceof ApiError) {
      throw error;
    }
    throw new ApiError(0, error.message || 'Failed to connect to backend server');
  }
}

export function getBaseUrl(): string {
  return DEFAULT_BASE_URL;
}
