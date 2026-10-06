import {
  ApiKey,
  Artifact,
  AuditLogPage,
  PolicySimulationResult,
  PolicyValidationResult,
  Project,
  VerificationRun,
  WebhookSubscription,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

let onUnauthorizedCallback: (() => void) | null = null;
let onForbiddenCallback: ((message: string) => void) | null = null;

export function setApiInterceptors(
  onUnauthorized: () => void,
  onForbidden: (message: string) => void
) {
  onUnauthorizedCallback = onUnauthorized;
  onForbiddenCallback = onForbidden;
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
  orgId?: string,
  projectId?: string
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (orgId) {
    headers['X-Organization-ID'] = orgId;
  }
  if (projectId) {
    headers['X-Project-ID'] = projectId;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    if (onUnauthorizedCallback) onUnauthorizedCallback();
    throw new Error('Session expired or unauthorized.');
  }

  if (response.status === 403) {
    const errorData = await response.json().catch(() => ({ detail: 'Forbidden' }));
    const msg = errorData.detail || 'Access forbidden for active tenant/role.';
    if (onForbiddenCallback) onForbiddenCallback(msg);
    throw new Error(msg);
  }

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || `API request failed (${response.status})`);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json();
}

// Development Token Endpoint
export async function issueDevToken(payload: {
  organization_id: string;
  role: string;
  project_id?: string;
}) {
  return request<{ access_token: string; token_type: string; expires_in: number }>(
    '/auth/token',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    }
  );
}

// Projects Endpoint
export async function getProjects(token: string, orgId?: string): Promise<Project[]> {
  return request<Project[]>('/projects', { method: 'GET' }, token, orgId);
}

// Verifications Endpoint
export async function getVerifications(
  token: string,
  orgId?: string,
  projectId?: string
): Promise<VerificationRun[]> {
  return request<VerificationRun[]>('/verifications', { method: 'GET' }, token, orgId, projectId);
}

// Artifacts Upload Endpoint
export async function uploadArtifact(
  token: string,
  file: File,
  projectId?: string,
  version?: string,
  orgId?: string
): Promise<Artifact> {
  const formData = new FormData();
  formData.append('file', file);
  if (projectId) formData.append('project_id', projectId);
  if (version) formData.append('version', version);

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  if (orgId) headers['X-Organization-ID'] = orgId;
  if (projectId) headers['X-Project-ID'] = projectId;

  const response = await fetch(`${API_BASE_URL}/artifacts/upload`, {
    method: 'POST',
    headers,
    body: formData,
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(errorData.detail || `Upload failed (${response.status})`);
  }

  return response.json();
}

export async function submitVerification(
  token: string,
  payload: {
    organization_id: string;
    project_id: string;
    production_artifact_id: string;
    reference_artifact_id?: string;
  },
  orgId?: string
): Promise<{ job_id: string; verification_run_id: string; status: string }> {
  return request<{ job_id: string; verification_run_id: string; status: string }>(
    '/verifications',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    token,
    orgId
  );
}

export async function getVerificationDetails(
  token: string,
  verificationId: string,
  orgId?: string
): Promise<VerificationRun> {
  return request<VerificationRun>(
    `/verifications/${verificationId}`,
    { method: 'GET' },
    token,
    orgId
  );
}

// Audit Log Stream Endpoint
export async function getAuditLogs(
  token: string,
  limit = 20,
  offset = 0,
  action?: string,
  orgId?: string
): Promise<AuditLogPage> {
  const query = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  });
  if (action) query.append('action', action);

  return request<AuditLogPage>(`/audit-log?${query.toString()}`, { method: 'GET' }, token, orgId);
}

// Policy Validation & Live Simulator Endpoints
export async function validatePolicyYaml(
  token: string,
  yamlContent: string,
  orgId?: string
): Promise<PolicyValidationResult> {
  return request<PolicyValidationResult>(
    '/policy/validate',
    {
      method: 'POST',
      body: JSON.stringify({ yaml_content: yamlContent }),
    },
    token,
    orgId
  );
}

export async function simulatePolicyYaml(
  token: string,
  yamlContent: string,
  mockRiskScore?: number,
  verificationId?: string,
  orgId?: string
): Promise<PolicySimulationResult> {
  return request<PolicySimulationResult>(
    '/policy/simulate',
    {
      method: 'POST',
      body: JSON.stringify({
        yaml_content: yamlContent,
        mock_risk_score: mockRiskScore,
        verification_id: verificationId,
      }),
    },
    token,
    orgId
  );
}

// API Keys Management Endpoints
export async function getApiKeys(token: string, orgId?: string): Promise<ApiKey[]> {
  return request<ApiKey[]>('/auth/api-keys', { method: 'GET' }, token, orgId);
}

export async function createApiKey(
  token: string,
  payload: { name: string; role: string; project_id?: string },
  orgId?: string
): Promise<ApiKey & { api_key: string }> {
  const bodyPayload: Record<string, any> = {
    name: payload.name,
    role: payload.role,
  };
  if (payload.project_id && payload.project_id.trim() !== '') {
    bodyPayload.project_id = payload.project_id;
  }
  return request<ApiKey & { api_key: string }>(
    '/auth/api-keys',
    {
      method: 'POST',
      body: JSON.stringify(bodyPayload),
    },
    token,
    orgId
  );
}

export async function revokeApiKey(token: string, keyId: string, orgId?: string): Promise<void> {
  return request<void>(`/auth/api-keys/${keyId}`, { method: 'DELETE' }, token, orgId);
}

// Webhook Subscriptions Management Endpoints
export async function getWebhooks(token: string, orgId?: string): Promise<WebhookSubscription[]> {
  return request<WebhookSubscription[]>('/webhooks/subscriptions', { method: 'GET' }, token, orgId);
}

export async function createWebhook(
  token: string,
  payload: { target_url: string; event_types: string[] },
  orgId?: string
): Promise<WebhookSubscription> {
  return request<WebhookSubscription>(
    '/webhooks/subscriptions',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    token,
    orgId
  );
}

export async function testWebhook(
  token: string,
  subscriptionId: string,
  orgId?: string
): Promise<{ status: string }> {
  return request<{ status: string }>(
    `/webhooks/subscriptions/${subscriptionId}/test`,
    { method: 'POST' },
    token,
    orgId
  );
}

// GitHub CI/CD Integration Endpoints
export async function getGitHubStatus(token: string, orgId?: string) {
  return request<import('../types').GitHubIntegrationStatus>(
    '/ci/github/status',
    { method: 'GET' },
    token,
    orgId
  );
}

export async function configureGitHubRepo(
  token: string,
  payload: { repository: string; default_branch: string; project_id?: string },
  orgId?: string
) {
  return request<{ status: string; repository: string; default_branch: string }>(
    '/ci/github/config',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    token,
    orgId
  );
}

export async function triggerGitHubCollect(token: string, orgId?: string) {
  return request<{
    artifact_id: string;
    verification_run_id: string;
    commit_sha: string;
    digest_sha256: string;
    status: string;
  }>('/ci/github/collect', { method: 'POST' }, token, orgId);
}

export async function triggerGitHubDemoCollect(token: string, orgId?: string) {
  return request<{
    artifact_id: string;
    verification_run_id: string;
    commit_sha: string;
    digest_sha256: string;
    status: string;
    is_demo?: boolean;
  }>('/ci/github/demo-collect', { method: 'POST' }, token, orgId);
}

