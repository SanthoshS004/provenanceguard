export interface Project {
  id: string;
  organization_id: string;
  name: string;
  created_at: string;
}

export interface Artifact {
  id: string;
  organization_id: string;
  project_id: string;
  name: string;
  version: string;
  media_type: string;
  digest_sha256: string;
  size_bytes: number;
  storage_path: string;
  created_at: string;
}

export interface Finding {
  id: string;
  verification_run_id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  category: string;
  explanation: string;
  remediation?: string;
  details_json?: Record<string, any>;
}

export interface VerificationRun {
  id: string;
  organization_id: string;
  project_id: string;
  production_artifact_id: string;
  reference_artifact_id?: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  decision: 'PASS' | 'PASS_WITH_WARNING' | 'BLOCK';
  risk_score: number;
  created_at: string;
  findings?: Finding[];
}

export interface AuditLogEntry {
  id: string;
  organization_id: string;
  actor_id: string;
  action: string;
  resource: string;
  result: string;
  created_at: string;
  timestamp?: string;
  metadata_json?: Record<string, any>;
}

export interface AuditLogPage {
  items: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface ApiKey {
  id: string;
  organization_id: string;
  project_id?: string;
  name: string;
  prefix: string;
  role: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  revoked_at?: string;
}

export interface IdPConfig {
  id: string;
  organization_id: string;
  name: string;
  issuer: string;
  client_id: string;
  jwks_uri: string;
  subject_claim: string;
  group_claim: string;
  group_role_map: Record<string, string>;
  is_active: boolean;
}

export interface WebhookSubscription {
  id: string;
  organization_id: string;
  target_url: string;
  event_types: string[];
  is_active: boolean;
  created_at: string;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: string[];
  policy_name?: string;
  warning_threshold?: number;
  block_threshold?: number;
}

export interface PolicySimulationResult {
  simulated_decision: 'PASS' | 'PASS_WITH_WARNING' | 'BLOCK';
  simulated_risk_score: number;
  mandatory_violations: string[];
  triggered_rules: string[];
  rationale: string;
  watermark: string;
}

export interface UserSession {
  token: string;
  user_id: string;
  organization_id: string;
  project_id?: string;
  role: string;
  scopes: string[];
}

export interface GitHubIntegrationStatus {
  token_configured: boolean;
  connection_status: 'CONNECTED' | 'NO_GITHUB_TOKEN' | 'REPOSITORY_NOT_FOUND' | 'INVALID_GITHUB_TOKEN';
  repository: string;
  branch: string;
  latest_commit_sha?: string;
  commit_message?: string;
  workflow_name?: string;
  workflow_run_id?: string;
  artifact_name?: string;
  artifact_collection_status: string;
  verification_status: string;
  verification_decision: string;
  risk_score: number;
  verification_run_id?: string;
}

