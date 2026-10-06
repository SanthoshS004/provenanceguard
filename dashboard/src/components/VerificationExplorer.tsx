import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import { getVerifications, getVerificationDetails } from '../services/api';
import { VerificationRun } from '../types';
import { UploadModal } from './UploadModal';
import { PageHeader } from './ui/PageHeader';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import { EmptyState } from './ui/EmptyState';
import {
  Layers,
  Search,
  Filter,
  FileText,
  AlertCircle,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Upload,
} from 'lucide-react';

export const VerificationExplorer: React.FC = () => {
  const { session } = useAuth();
  const { selectedOrgId, selectedProjectId } = useTenant();

  const [verifications, setVerifications] = useState<VerificationRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<VerificationRun | null>(null);
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);

  useEffect(() => {
    if (!session?.token) return;
    setLoading(true);
    getVerifications(session.token, selectedOrgId, selectedProjectId)
      .then((data) => {
        setVerifications(data);
        if (data.length > 0) {
          handleSelectRun(data[0].id);
        }
      })
      .catch(() => setVerifications([]))
      .finally(() => setLoading(false));
  }, [session, selectedOrgId, selectedProjectId]);

  const handleSelectRun = async (id: string) => {
    if (!session?.token) return;
    try {
      const details = await getVerificationDetails(session.token, id, selectedOrgId);
      setSelectedRun(details);
    } catch {
      const found = verifications.find((v) => v.id === id);
      if (found) setSelectedRun(found);
    }
  };

  const filteredRuns = verifications.filter((r) => {
    const matchesDecision = filterDecision === 'ALL' || r.decision === filterDecision;
    const matchesSearch =
      !searchQuery ||
      r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.production_artifact_id.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesDecision && matchesSearch;
  });

  return (
    <div className="space-y-8">
      {/* Title & Filter Controls Header */}
      <PageHeader
        category="PIPELINE & STREAM"
        title="Verification Explorer"
        description="Inspect supply chain verification runs and explainable finding models"
        actions={
          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search ID or Artifact..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-52 sm:w-64 pl-10"
              />
            </div>

            {/* Decision Filter */}
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-400" />
              <select
                value={filterDecision}
                onChange={(e) => setFilterDecision(e.target.value)}
                className="text-xs font-semibold"
              >
                <option value="ALL">All Decisions</option>
                <option value="PASS">PASS Only</option>
                <option value="PASS_WITH_WARNING">WARNING Only</option>
                <option value="BLOCK">BLOCK Only</option>
              </select>
            </div>

            {/* Submit Artifact Button */}
            <Button
              variant="primary"
              onClick={() => setIsUploadOpen(true)}
              icon={<Upload className="h-4 w-4" />}
            >
              + Submit Artifact
            </Button>
          </div>
        }
      />

      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={() => {
          if (session?.token) {
            getVerifications(session.token, selectedOrgId, selectedProjectId)
              .then((data) => {
                setVerifications(data);
                if (data.length > 0) handleSelectRun(data[0].id);
              });
          }
        }}
      />

      {/* Split Master-Detail Layout */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Verification Stream List */}
        <div className="panel-card p-5 lg:col-span-5 flex flex-col h-[750px] border-[#1C2B40] bg-[#0D1728]">
          <div className="flex items-center justify-between pb-3.5 mb-3 border-b border-[#1C2B40]">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <Layers className="h-4 w-4 text-[#00B8FF]" />
              <span>Verification Stream ({filteredRuns.length})</span>
            </span>
          </div>

          <div className="flex-1 overflow-y-auto space-y-2.5 pr-1">
            {loading ? (
              <div className="space-y-3 p-2">
                {[1, 2, 3, 4].map((i) => (
                  <div key={i} className="h-20 skeleton rounded-xl" />
                ))}
              </div>
            ) : filteredRuns.length === 0 ? (
              <EmptyState
                icon={<FileText className="h-6 w-6 text-slate-400" />}
                title="No verification runs"
                description="No verification runs match the current filters or query."
              />
            ) : (
              filteredRuns.map((run) => (
                <div
                  key={run.id}
                  onClick={() => handleSelectRun(run.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition ${
                    selectedRun?.id === run.id
                      ? 'border-[#00B8FF] bg-[#102238] shadow-md shadow-[#00B8FF]/10'
                      : 'border-[#1C2B40] bg-[#0A1424] hover:border-slate-600 hover:bg-[#111F32]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <TechnicalValue value={run.id} truncate truncateLength={8} className="text-[#00B8FF] font-bold" />
                    <Badge status={run.decision} />
                  </div>

                  <p className="text-[11px] text-slate-400 truncate">
                    Artifact: <TechnicalValue value={run.production_artifact_id} truncate truncateLength={16} />
                  </p>

                  <div className="flex items-center justify-between text-[11px] text-slate-400 mt-3 pt-2.5 border-t border-[#1C2B40]">
                    <span>Risk Score: <strong className="text-slate-200 font-mono">{run.risk_score}</strong>/100</span>
                    <span className="flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5" />
                      <span>{new Date(run.created_at).toLocaleTimeString()}</span>
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Detailed Pipeline View & Decision Banner */}
        <div className="panel-card p-6 md:p-8 lg:col-span-7 flex flex-col h-[750px] overflow-y-auto border-[#1C2B40] bg-[#0D1728]">
          {!selectedRun ? (
            <EmptyState
              icon={<Layers className="h-8 w-8 text-slate-400" />}
              title="Select a Verification Run"
              description="Select a verification run from the left stream to inspect pipeline details and explainable findings."
            />
          ) : (
            <div className="space-y-6">
              {/* Prominent Decision Banner */}
              <div className={`p-5 rounded-xl border flex items-center justify-between ${
                selectedRun.decision === 'PASS'
                  ? 'border-[#00D7A7]/40 bg-[#00D7A7]/10 text-[#00D7A7]'
                  : selectedRun.decision === 'PASS_WITH_WARNING'
                  ? 'border-[#FFB000]/40 bg-[#FFB000]/10 text-[#FFB000]'
                  : 'border-[#FF4F72]/40 bg-[#FF4F72]/10 text-[#FF4F72]'
              }`}>
                <div className="flex items-center gap-4">
                  {selectedRun.decision === 'PASS' && <CheckCircle2 className="h-8 w-8 text-[#00D7A7] shrink-0" />}
                  {selectedRun.decision === 'PASS_WITH_WARNING' && <AlertTriangle className="h-8 w-8 text-[#FFB000] shrink-0" />}
                  {selectedRun.decision === 'BLOCK' && <XCircle className="h-8 w-8 text-[#FF4F72] shrink-0" />}

                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider opacity-80 block">POLICY DECISION RESULT</span>
                    <h3 className="text-base font-extrabold tracking-tight">
                      {selectedRun.decision === 'PASS' && '✓ PASS — Artifact Verification Satisfied'}
                      {selectedRun.decision === 'PASS_WITH_WARNING' && '⚠ PASS WITH WARNING — Low Risk Findings Flagged'}
                      {selectedRun.decision === 'BLOCK' && '✕ BLOCK — Policy Violations Detected'}
                    </h3>
                  </div>
                </div>

                <div className="text-right font-mono shrink-0">
                  <span className="text-[10px] opacity-70 block">RISK SCORE</span>
                  <span className="text-xl font-bold">{selectedRun.risk_score} / 100</span>
                </div>
              </div>

              {/* Pipeline Step Indicators */}
              <div className="rounded-xl border border-[#1C2B40] bg-[#0A1424] p-5 space-y-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Verification Pipeline Flow</span>
                <div className="grid grid-cols-4 gap-3 text-center text-xs">
                  <div className="p-3 rounded-lg bg-[#0D1728] border border-[#1C2B40] text-slate-200 font-semibold">
                    1. Identity
                  </div>
                  <div className="p-3 rounded-lg bg-[#0D1728] border border-[#1C2B40] text-slate-200 font-semibold">
                    2. Provenance
                  </div>
                  <div className="p-3 rounded-lg bg-[#0D1728] border border-[#1C2B40] text-slate-200 font-semibold">
                    3. SBOM Diff
                  </div>
                  <div className="p-3 rounded-lg bg-[#0D1728] border border-[#1C2B40] text-slate-200 font-semibold">
                    4. Policy Engine
                  </div>
                </div>
              </div>

              {/* Artifact Metadata Info */}
              <div className="rounded-xl border border-[#1C2B40] bg-[#0A1424] p-5 space-y-4">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block border-b border-[#1C2B40] pb-2">
                  Artifact Technical Identifiers
                </span>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Verification UUID</span>
                    <TechnicalValue value={selectedRun.id} copyable className="text-[#00B8FF] font-bold" />
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Production Artifact ID</span>
                    <TechnicalValue value={selectedRun.production_artifact_id} copyable className="text-slate-200" />
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Timestamp</span>
                    <span className="text-slate-300">{new Date(selectedRun.created_at).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Status</span>
                    <Badge status={selectedRun.status} />
                  </div>
                </div>
              </div>

              {/* CI/CD & Source Origin Metadata */}
              <div className="rounded-xl border border-[#1C2B40] bg-[#0A1424] p-5 space-y-4">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block border-b border-[#1C2B40] pb-2">
                  CI/CD & Source Origin Metadata
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Git Provider / Integration</span>
                    <span className="font-bold text-[#00B8FF]">GitHub Actions CI</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Source Commit & Branch</span>
                    <TechnicalValue value="8e1c03f (main)" className="text-slate-200" />
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">CI Pipeline & Run</span>
                    <span className="text-slate-200">Build & Verify (#104)</span>
                  </div>
                </div>
              </div>

              {/* Explainable Findings List */}
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-[#1C2B40] pb-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-[#00B8FF]" />
                    <span>Explainable Security Findings ({selectedRun.findings?.length || 0})</span>
                  </h3>
                </div>

                {!selectedRun.findings || selectedRun.findings.length === 0 ? (
                  <div className="rounded-xl border border-[#1C2B40] bg-[#0A1424] p-6 text-center text-xs text-slate-400">
                    No security findings or policy anomalies flagged for this verification run.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {selectedRun.findings.map((f) => (
                      <div key={f.id} className="rounded-xl border border-[#1C2B40] bg-[#0A1424] p-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className={`text-xs font-bold ${
                            f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'text-[#FF4F72]' : 'text-[#FFB000]'
                          }`}>
                            [{f.severity}] {f.category}
                          </span>
                          <TechnicalValue value={f.id} truncate truncateLength={8} className="text-slate-400" />
                        </div>

                        <p className="text-xs text-slate-200 font-medium leading-relaxed">{f.explanation}</p>

                        {f.remediation && (
                          <div className="rounded-lg border border-[#00B8FF]/20 bg-[#00B8FF]/10 p-3.5 text-xs text-[#12C8FF] leading-relaxed">
                            <strong className="block font-semibold mb-1">Remediation Guidance:</strong>
                            <span>{f.remediation}</span>
                          </div>
                        )}

                        {f.details_json && (
                          <pre className="code-block text-[11px] mt-2">
                            {JSON.stringify(f.details_json, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
