import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import { getVerifications } from '../services/api';
import { VerificationRun } from '../types';
import { UploadModal } from './UploadModal';
import { PageHeader } from './ui/PageHeader';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import { EmptyState } from './ui/EmptyState';
import {
  Shield,
  ShieldCheck,
  AlertTriangle,
  ShieldX,
  RefreshCw,
  Activity,
  Layers,
  ArrowUpRight,
  ShieldAlert,
  Terminal,
  FileCheck2,
  SlidersHorizontal,
  FileText,
  ArrowRight,
  Upload,
} from 'lucide-react';

export const Overview: React.FC = () => {
  const { session } = useAuth();
  const { selectedOrgId, selectedProjectId } = useTenant();

  const [verifications, setVerifications] = useState<VerificationRun[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);

  const fetchOverviewData = async () => {
    if (!session?.token) return;
    setLoading(true);
    try {
      const data = await getVerifications(session.token, selectedOrgId, selectedProjectId);
      setVerifications(data);
    } catch {
      setVerifications([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverviewData();

    const interval = setInterval(() => {
      if (!document.hidden) {
        fetchOverviewData();
      }
    }, 10000);

    return () => clearInterval(interval);
  }, [session, selectedOrgId, selectedProjectId]);

  const totalRuns = verifications.length;
  const passCount = verifications.filter((v) => v.decision === 'PASS').length;
  const warningCount = verifications.filter((v) => v.decision === 'PASS_WITH_WARNING').length;
  const blockCount = verifications.filter((v) => v.decision === 'BLOCK').length;

  const highRiskFindingsCount = verifications.reduce((acc, v) => {
    if (!v.findings) return acc;
    return (
      acc +
      v.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length
    );
  }, 0);

  const hasData = totalRuns > 0;
  const complianceRate = hasData ? (((passCount + warningCount) / totalRuns) * 100).toFixed(1) : '—';

  return (
    <div className="space-y-8">
      {/* Page Header (Section 4) */}
      <PageHeader
        category="DASHBOARD"
        title="Security Overview"
        description="Current software supply-chain verification posture"
        actions={
          <>
            <Button
              variant="primary"
              onClick={() => setIsUploadOpen(true)}
              icon={<Upload className="h-4 w-4" />}
            >
              + Submit Artifact
            </Button>
            <Button
              variant="secondary"
              onClick={fetchOverviewData}
              loading={loading}
              icon={<RefreshCw className="h-4 w-4" />}
            >
              Refresh Data
            </Button>
          </>
        }
      />

      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={fetchOverviewData}
      />

      {/* Security Posture + 2x2 KPI Grid (Section 5) */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Security Posture Centerpiece Hero Card (5 Cols) */}
        <div className="panel-card p-6 md:p-8 lg:col-span-5 flex flex-col justify-between relative overflow-hidden bg-[#0D1728] border-[#1C2B40]">
          <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
            <span className="text-xs font-extrabold uppercase tracking-widest text-slate-300 flex items-center gap-2">
              <Activity className="h-4 w-4 text-[#00B8FF]" />
              <span>SECURITY POSTURE</span>
            </span>
            <span className="text-[11px] font-mono text-slate-400 bg-[#0A1424] px-2.5 py-1 rounded-md border border-[#1C2B40] flex items-center gap-1.5">
              <span className="h-1.5 w-1.5 rounded-full bg-[#00D7A7] animate-pulse"></span>
              <span>REST API Synced</span>
            </span>
          </div>

          <div className="my-6">
            {!hasData ? (
              <div className="flex items-start gap-5">
                <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-[#00B8FF]/10 border border-[#00B8FF]/20 text-[#00B8FF]">
                  <Shield className="h-8 w-8 stroke-[1.8]" />
                </div>
                <div className="space-y-1.5">
                  <span className="text-3xl font-extrabold text-slate-400">—</span>
                  <h3 className="text-base font-bold text-slate-100">No verification data yet</h3>
                  <p className="text-xs text-slate-400 leading-relaxed max-w-sm">
                    Submit an artifact for verification to establish your compliance baseline and software supply-chain security posture.
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-baseline gap-3">
                  <span className="text-5xl font-extrabold text-[#00B8FF]">{complianceRate}%</span>
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Verification Compliance</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {blockCount === 0
                    ? 'All evaluated artifacts satisfy security policy rules.'
                    : `${blockCount} deployment(s) blocked due to policy violations.`}
                </p>
              </div>
            )}
          </div>

          {/* Bottom Status Indicators */}
          <div className="pt-4 border-t border-[#1C2B40] grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Verification Engine</span>
              <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                <span className="h-2 w-2 rounded-full bg-[#00B8FF]"></span>
                <span>Authoritative</span>
              </div>
            </div>
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Policy Mode</span>
              <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                <span className="h-2 w-2 rounded-full bg-[#00D7A7]"></span>
                <span>Fail-Closed</span>
              </div>
            </div>
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">REST API</span>
              <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                <span className="h-2 w-2 rounded-full bg-[#6C7CFF]"></span>
                <span>Synced</span>
              </div>
            </div>
            <div className="space-y-0.5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Audit Logging</span>
              <div className="flex items-center gap-1.5 font-semibold text-slate-200">
                <span className="h-2 w-2 rounded-full bg-[#00D7A7]"></span>
                <span>Active</span>
              </div>
            </div>
          </div>
        </div>

        {/* 2x2 KPI Grid Cards (7 Cols) */}
        <div className="lg:col-span-7 grid grid-cols-1 sm:grid-cols-2 gap-5">
          {/* Card 1: Total Runs */}
          <div className="panel-card p-6 flex flex-col justify-between border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Verification Runs</span>
              <div className="p-2 rounded-xl bg-[#00B8FF]/10 border border-[#00B8FF]/20 text-[#00B8FF]">
                <Layers className="h-5 w-5" />
              </div>
            </div>
            <div className="my-4">
              <span className="text-3xl md:text-4xl font-extrabold text-slate-100">{totalRuns}</span>
            </div>
            <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-[#1C2B40]">
              <span>{totalRuns === 0 ? 'No verification activity' : `${totalRuns} Evaluated Runs`}</span>
              <span className="font-mono text-[10px] text-slate-400">SHA256 / PURL</span>
            </div>
          </div>

          {/* Card 2: Passed */}
          <div className="panel-card p-6 flex flex-col justify-between border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Passed</span>
              <div className="p-2 rounded-xl bg-[#00D7A7]/10 border border-[#00D7A7]/20 text-[#00D7A7]">
                <ShieldCheck className="h-5 w-5" />
              </div>
            </div>
            <div className="my-4">
              <span className="text-3xl md:text-4xl font-extrabold text-[#00D7A7]">{passCount}</span>
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-[#1C2B40]">
              <Badge status="PASS" />
              <span className="text-[11px] text-slate-400">{passCount === 0 ? 'No successful runs' : 'Verified Safe'}</span>
            </div>
          </div>

          {/* Card 3: Warnings */}
          <div className="panel-card p-6 flex flex-col justify-between border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Warnings</span>
              <div className="p-2 rounded-xl bg-[#FFB000]/10 border border-[#FFB000]/20 text-[#FFB000]">
                <AlertTriangle className="h-5 w-5" />
              </div>
            </div>
            <div className="my-4">
              <span className="text-3xl md:text-4xl font-extrabold text-[#FFB000]">{warningCount}</span>
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-[#1C2B40]">
              <Badge status="WARNING" />
              <span className="text-[11px] text-slate-400">{warningCount === 0 ? 'No warning decisions' : 'Low Risk Findings'}</span>
            </div>
          </div>

          {/* Card 4: Blocked */}
          <div className="panel-card p-6 flex flex-col justify-between border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Blocked</span>
              <div className="p-2 rounded-xl bg-[#FF4F72]/10 border border-[#FF4F72]/20 text-[#FF4F72]">
                <ShieldX className="h-5 w-5" />
              </div>
            </div>
            <div className="my-4">
              <span className="text-3xl md:text-4xl font-extrabold text-[#FF4F72]">{blockCount}</span>
            </div>
            <div className="flex items-center justify-between text-xs pt-2 border-t border-[#1C2B40]">
              <Badge status="BLOCK" />
              <span className="text-[11px] text-slate-400">{blockCount === 0 ? 'No blocked decisions' : `${highRiskFindingsCount} Critical/High`}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Verification Activity Section */}
      <div className="panel-card p-6 md:p-8 border-[#1C2B40] bg-[#0D1728]">
        <div className="flex items-center justify-between mb-6 border-b border-[#1C2B40] pb-4">
          <div>
            <h3 className="text-base font-bold text-slate-100">Recent Verification Activity</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Latest artifact verification decisions and security findings
            </p>
          </div>
        </div>

        {verifications.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-6 w-6 text-slate-400" />}
            title="No verification activity yet"
            description="There are no verification runs for the active organization or project context. Click '+ Submit Artifact' above to ingest and verify your first artifact."
            action={
              <Button variant="primary" onClick={() => setIsUploadOpen(true)} icon={<Upload className="h-4 w-4" />}>
                Submit Artifact
              </Button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table>
              <thead>
                <tr>
                  <th>Verification ID</th>
                  <th>Production Artifact ID</th>
                  <th>Decision</th>
                  <th>Risk Score</th>
                  <th>Created Date</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {verifications.map((run) => (
                  <tr key={run.id}>
                    <td>
                      <TechnicalValue value={run.id} truncate truncateLength={8} className="text-[#00B8FF] font-semibold" copyable />
                    </td>
                    <td>
                      <TechnicalValue value={run.production_artifact_id} truncate truncateLength={12} className="text-slate-400" copyable />
                    </td>
                    <td>
                      <Badge status={run.decision} />
                    </td>
                    <td>
                      <span className={`font-mono font-bold ${run.risk_score >= 70 ? 'text-[#FF4F72]' : run.risk_score >= 30 ? 'text-[#FFB000]' : 'text-[#00D7A7]'}`}>
                        {run.risk_score} / 100
                      </span>
                    </td>
                    <td className="text-slate-400 text-xs">{new Date(run.created_at).toLocaleString()}</td>
                    <td className="text-right">
                      <span className="inline-flex items-center gap-1 font-semibold text-[#00B8FF] hover:text-[#12C8FF] cursor-pointer">
                        <span>Inspect</span>
                        <ArrowUpRight className="h-3.5 w-3.5" />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Getting Started Guide */}
      <div className="panel-card p-6 md:p-8 border-[#1C2B40] bg-[#0D1728] space-y-6">
        <div className="border-b border-[#1C2B40] pb-4">
          <h3 className="text-base font-bold text-slate-100">Getting Started</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Follow these steps to verify your first artifact
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {/* Step 1 */}
          <div className="rounded-xl bg-[#0A1424] border border-[#1C2B40] p-5 space-y-3 hover:border-[#00B8FF]/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xl font-extrabold text-[#00B8FF] font-mono">01</span>
              <div className="p-2 rounded-lg bg-[#00B8FF]/10 text-[#00B8FF] border border-[#00B8FF]/20">
                <Terminal className="h-4 w-4" />
              </div>
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Submit Artifact</h4>
              <p className="text-xs text-slate-400 leading-relaxed mt-1">
                Submit container digest, ELF binary, or SBOM via CLI or API endpoint.
              </p>
            </div>
            <div className="pt-2 text-[#00B8FF] flex items-center gap-1 text-[11px] font-semibold">
              <span>CLI / REST API</span>
              <ArrowRight className="h-3 w-3" />
            </div>
          </div>

          {/* Step 2 */}
          <div className="rounded-xl bg-[#0A1424] border border-[#1C2B40] p-5 space-y-3 hover:border-[#6C7CFF]/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xl font-extrabold text-[#6C7CFF] font-mono">02</span>
              <div className="p-2 rounded-lg bg-[#6C7CFF]/10 text-[#6C7CFF] border border-[#6C7CFF]/20">
                <FileCheck2 className="h-4 w-4" />
              </div>
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Verify Provenance</h4>
              <p className="text-xs text-slate-400 leading-relaxed mt-1">
                Validate Cosign keyless signatures, Rekor transparency log, and SLSA attestation.
              </p>
            </div>
            <div className="pt-2 text-[#6C7CFF] flex items-center gap-1 text-[11px] font-semibold">
              <span>Sigstore / SLSA</span>
              <ArrowRight className="h-3 w-3" />
            </div>
          </div>

          {/* Step 3 */}
          <div className="rounded-2xl bg-[#0A1424] border border-[#1C2B40] p-5 space-y-3 hover:border-[#FFB000]/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xl font-extrabold text-[#FFB000] font-mono">03</span>
              <div className="p-2 rounded-lg bg-[#FFB000]/10 text-[#FFB000] border border-[#FFB000]/20">
                <SlidersHorizontal className="h-4 w-4" />
              </div>
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Evaluate Policy</h4>
              <p className="text-xs text-slate-400 leading-relaxed mt-1">
                Evaluate against active OPA Rego policy rules with deterministic risk scoring.
              </p>
            </div>
            <div className="pt-2 text-[#FFB000] flex items-center gap-1 text-[11px] font-semibold">
              <span>OPA / Rego</span>
              <ArrowRight className="h-3 w-3" />
            </div>
          </div>

          {/* Step 4 */}
          <div className="rounded-xl bg-[#0A1424] border border-[#1C2B40] p-5 space-y-3 hover:border-[#00D7A7]/40 transition">
            <div className="flex items-center justify-between">
              <span className="text-xl font-extrabold text-[#00D7A7] font-mono">04</span>
              <div className="p-2 rounded-lg bg-[#00D7A7]/10 text-[#00D7A7] border border-[#00D7A7]/20">
                <FileText className="h-4 w-4" />
              </div>
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-200">Inspect Audit Log</h4>
              <p className="text-xs text-slate-400 leading-relaxed mt-1">
                Review tamper-evident Merkle tree audit log events and verification reports.
              </p>
            </div>
            <div className="pt-2 text-[#00D7A7] flex items-center gap-1 text-[11px] font-semibold">
              <span>Audit Chain</span>
              <ArrowRight className="h-3 w-3" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
