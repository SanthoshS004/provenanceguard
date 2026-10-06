import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import {
  configureGitHubRepo,
  getGitHubStatus,
  triggerGitHubCollect,
  triggerGitHubDemoCollect,
} from '../services/api';
import { GitHubIntegrationStatus } from '../types';
import { PageHeader } from './ui/PageHeader';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import {
  GitBranch,
  GitCommit,
  GitPullRequest,
  Play,
  RefreshCw,
  ShieldCheck,
  Terminal,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Info,
} from 'lucide-react';

interface GitHubIntegrationsProps {
  onNavigateToExplorer?: () => void;
}

export const GitHubIntegrations: React.FC<GitHubIntegrationsProps> = ({ onNavigateToExplorer }) => {
  const { session } = useAuth();
  const { selectedOrgId, selectedProjectId } = useTenant();

  const token = session?.token;

  const [statusInfo, setStatusInfo] = useState<GitHubIntegrationStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const [repositoryInput, setRepositoryInput] = useState<string>('');
  const [branchInput, setBranchInput] = useState<string>('main');

  const fetchStatus = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const data = await getGitHubStatus(token, selectedOrgId);
      setStatusInfo(data);
      if (data.repository && data.repository !== 'owner/repository') {
        setRepositoryInput(data.repository);
      }
      if (data.branch) {
        setBranchInput(data.branch);
      }
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Failed to fetch GitHub integration status.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, [token, selectedOrgId]);

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !repositoryInput) return;
    setSaving(true);
    setMessage(null);
    try {
      await configureGitHubRepo(
        token,
        {
          repository: repositoryInput,
          default_branch: branchInput,
          project_id: selectedProjectId,
        },
        selectedOrgId
      );
      setMessage({ type: 'success', text: 'GitHub repository configuration updated successfully!' });
      fetchStatus();
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Failed to save configuration.' });
    } finally {
      setSaving(false);
    }
  };

  const handlePullCollect = async () => {
    if (!token) return;
    setActionLoading('PULL');
    setMessage(null);
    try {
      const res = await triggerGitHubCollect(token, selectedOrgId);
      setMessage({
        type: 'success',
        text: `Artifact collected via PULL! Verification Run ID: ${res.verification_run_id}`,
      });
      fetchStatus();
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'PULL artifact collection failed.' });
    } finally {
      setActionLoading(null);
    }
  };

  const handleDemoCollect = async () => {
    if (!token) return;
    setActionLoading('DEMO');
    setMessage(null);
    try {
      const res = await triggerGitHubDemoCollect(token, selectedOrgId);
      setMessage({
        type: 'success',
        text: `Local Demo workflow executed successfully! Verification Run ID: ${res.verification_run_id}`,
      });
      fetchStatus();
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Demo collection failed.' });
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Top Header Card */}
      <PageHeader
        category="MAIN OPERATIONS"
        title="GitHub Integrations"
        description="Secure software release builds from GitHub Actions through automated artifact ingestion & zero-trust verification"
        actions={
          <div className="flex items-center gap-3">
            <Button
              variant="secondary"
              onClick={fetchStatus}
              loading={loading}
              icon={<RefreshCw className="h-4 w-4" />}
            >
              Refresh Status
            </Button>
            <Button
              variant="primary"
              onClick={handleDemoCollect}
              loading={actionLoading === 'DEMO'}
              icon={<Play className="h-4 w-4 fill-current" />}
            >
              Run Local Demo
            </Button>
          </div>
        }
      />

      {/* Notifications Alert */}
      {message && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-xs font-medium ${
            message.type === 'success'
              ? 'bg-[#00D7A7]/10 border-[#00D7A7]/30 text-[#00D7A7]'
              : 'bg-[#FF4F72]/10 border-[#FF4F72]/30 text-[#FF4F72]'
          }`}
        >
          {message.type === 'success' ? <CheckCircle2 className="h-4 w-4 shrink-0" /> : <AlertTriangle className="h-4 w-4 shrink-0" />}
          <span>{message.text}</span>
        </div>
      )}

      {/* Grid Layout: Config + Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Form Column (1/3) */}
        <div className="panel-card p-6 space-y-6 self-start border-[#1C2B40] bg-[#0D1728]">
          <div className="space-y-1 border-b border-[#1C2B40] pb-3">
            <h2 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-[#00B8FF]" />
              <span>Repository Settings</span>
            </h2>
            <p className="text-xs text-slate-400">Configure target GitHub repository for PUSH/PULL workflows.</p>
          </div>

          <form onSubmit={handleSaveConfig} className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 block">GitHub Repository</label>
              <input
                type="text"
                placeholder="e.g. owner/repository"
                value={repositoryInput}
                onChange={(e) => setRepositoryInput(e.target.value)}
                className="w-full font-mono text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300 block">Default Target Branch</label>
              <input
                type="text"
                placeholder="main"
                value={branchInput}
                onChange={(e) => setBranchInput(e.target.value)}
                className="w-full font-mono text-xs"
              />
            </div>

            <Button
              type="submit"
              variant="primary"
              loading={saving}
              disabled={!repositoryInput}
              className="w-full"
            >
              Save Configuration
            </Button>
          </form>

          <div className="pt-4 border-t border-[#1C2B40] space-y-3">
            <h3 className="text-xs font-bold text-slate-300">PULL Artifact Collection</h3>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              PULL mode queries GitHub API using <code className="text-[#00B8FF] bg-[#00B8FF]/10 px-1 py-0.5 rounded font-mono">GITHUB_TOKEN</code> to retrieve latest successful workflow build artifacts.
            </p>
            <Button
              variant="secondary"
              onClick={handlePullCollect}
              loading={actionLoading === 'PULL'}
              disabled={!statusInfo?.token_configured}
              icon={<GitPullRequest className="h-4 w-4 text-[#00B8FF]" />}
              className="w-full"
            >
              Collect Latest Artifact (PULL)
            </Button>
            {!statusInfo?.token_configured && (
              <p className="text-[10px] text-[#FFB000] flex items-center gap-1">
                <Info className="h-3 w-3 shrink-0" />
                PULL requires GITHUB_TOKEN environment variable on backend.
              </p>
            )}
          </div>
        </div>

        {/* Right Status Grid (2/3) */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Connection Status Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">GitHub Connection</span>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2.5 w-2.5 rounded-full ${
                      statusInfo?.connection_status === 'CONNECTED' ? 'bg-[#00D7A7] animate-pulse' : 'bg-[#FFB000]'
                    }`}
                  />
                  <span className="text-xs font-bold text-slate-200">
                    {statusInfo?.connection_status || 'CHECKING...'}
                  </span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#0A1424] border border-[#1C2B40] text-slate-400 font-mono">
                  {statusInfo?.token_configured ? 'PAT Present' : 'Push Mode Only'}
                </span>
              </div>
            </div>

            {/* Target Repository Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Configured Repository</span>
              <div className="flex items-center justify-between">
                <TechnicalValue value={statusInfo?.repository || 'owner/repository'} className="text-slate-200 font-bold" />
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#00B8FF]/10 text-[#00B8FF] border border-[#00B8FF]/20 font-mono">
                  {statusInfo?.branch || 'main'}
                </span>
              </div>
            </div>

            {/* Latest Commit Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Latest Source Commit</span>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <GitCommit className="h-4 w-4 text-[#00B8FF]" />
                  <TechnicalValue value={statusInfo?.latest_commit_sha ? statusInfo.latest_commit_sha.substring(0, 7) : 'None'} className="text-slate-200 font-bold" />
                </div>
                {statusInfo?.commit_message && (
                  <span className="text-[10px] text-slate-400 truncate max-w-[140px]" title={statusInfo.commit_message}>
                    {statusInfo.commit_message}
                  </span>
                )}
              </div>
            </div>

            {/* CI Workflow Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">GitHub Actions Workflow</span>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-200 truncate max-w-[160px]">
                  {statusInfo?.workflow_name || 'CI Pipeline'}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#0A1424] text-slate-300 font-mono border border-[#1C2B40]">
                  Run #{statusInfo?.workflow_run_id || 'N/A'}
                </span>
              </div>
            </div>

            {/* Artifact Ingestion Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Build Artifact</span>
              <div className="flex items-center justify-between">
                <TechnicalValue value={statusInfo?.artifact_name || 'No artifact'} className="text-slate-200 font-bold" />
                <Badge status={statusInfo?.artifact_collection_status || 'IDLE'} />
              </div>
            </div>

            {/* Verification Decision Card */}
            <div className="panel-card p-4 space-y-2 border-[#1C2B40] bg-[#0D1728]">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider block">Policy Engine Decision</span>
              <div className="flex items-center justify-between">
                <Badge status={statusInfo?.verification_decision || 'NEUTRAL'} />
                <span className="text-xs font-bold text-slate-300">
                  Risk: <span className="text-[#00B8FF] font-mono">{statusInfo?.risk_score || 0}</span> / 100
                </span>
              </div>
            </div>
          </div>

          {/* Link to Verification Explorer */}
          {statusInfo?.verification_run_id && onNavigateToExplorer && (
            <div className="p-4 rounded-xl bg-[#00B8FF]/10 border border-[#00B8FF]/20 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-5 w-5 text-[#00B8FF]" />
                <div>
                  <h4 className="text-xs font-bold text-slate-200">
                    Active Verification Run <TechnicalValue value={statusInfo.verification_run_id} truncate truncateLength={8} className="text-[#00B8FF]" />
                  </h4>
                  <p className="text-[11px] text-slate-400">View complete security findings, binary diffs, and audit trail in Explorer.</p>
                </div>
              </div>
              <Button variant="secondary" onClick={onNavigateToExplorer} icon={<ExternalLink className="h-3.5 w-3.5" />}>
                Open Explorer
              </Button>
            </div>
          )}

          {/* Primary PUSH Workflow Documentation Snippet Card */}
          <div className="panel-card p-6 space-y-4 border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-[#00B8FF]" />
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Primary PUSH Workflow Snippet (.github/workflows/provenanceguard-ci.yml)</h3>
              </div>
              <span className="text-[10px] px-2 py-0.5 rounded bg-[#00D7A7]/10 text-[#00D7A7] font-bold border border-[#00D7A7]/20">
                RECOMMENDED
              </span>
            </div>

            <p className="text-xs text-slate-400">
              Copy this step into your repository's GitHub Actions workflow. Authenticate using <code className="text-[#00B8FF] font-mono">PROVENANCEGUARD_API_KEY</code> secret.
            </p>

            <div className="code-block text-[11px] leading-relaxed">
              <pre>{`- name: Submit Artifact to ProvenanceGuard Verification Gateway
  env:
    PG_API_URL: \${{ secrets.PROVENANCEGUARD_URL || 'http://127.0.0.1:8000' }}
    PG_API_KEY: \${{ secrets.PROVENANCEGUARD_API_KEY }}
  run: |
    curl -s -X POST "$PG_API_URL/api/v1/ci/github/artifacts" \\
      -H "X-API-Key: $PG_API_KEY" \\
      -F "file=@dist/app-release.bin" \\
      -F "repository=$GITHUB_REPOSITORY" \\
      -F "branch=$GITHUB_REF_NAME" \\
      -F "commit_sha=$GITHUB_SHA" \\
      -F "workflow_run_id=$GITHUB_RUN_ID" \\
      -F "workflow_name=$GITHUB_WORKFLOW" \\
      -F "build_number=$GITHUB_RUN_NUMBER" \\
      -F "artifact_type=BUILD_ARTIFACT"`}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
