import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import { validatePolicyYaml, simulatePolicyYaml } from '../services/api';
import { PolicyValidationResult, PolicySimulationResult } from '../types';
import { PageHeader } from './ui/PageHeader';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import {
  FileCode,
  Play,
  CheckCircle2,
  XCircle,
  Sliders,
  Sparkles,
  ShieldAlert,
} from 'lucide-react';

const DEFAULT_YAML_POLICY = `name: enterprise-security-policy
version: 1.0.0

# Risk Thresholds
warning_threshold: 30
block_threshold: 70

# Explicit Mandatory Security Rules
require_valid_signature: true
require_provenance: true
require_rekor_tlog: true
disallow_wx_sections: true
disallow_dependency_changes: false
`;

export const PolicyEditor: React.FC = () => {
  const { session } = useAuth();
  const { selectedOrgId } = useTenant();

  const [yamlInput, setYamlInput] = useState<string>(DEFAULT_YAML_POLICY);
  const [mockScoreInput, setMockScoreInput] = useState<number>(75);
  const [validationResult, setValidationResult] = useState<PolicyValidationResult | null>(null);
  const [simulationResult, setSimulationResult] = useState<PolicySimulationResult | null>(null);
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleValidate = async () => {
    if (!session?.token) return;
    setIsValidating(true);
    setErrorMsg(null);
    try {
      const res = await validatePolicyYaml(session.token, yamlInput, selectedOrgId);
      setValidationResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Validation failed');
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const handleSimulate = async () => {
    if (!session?.token) return;
    setIsSimulating(true);
    setErrorMsg(null);
    try {
      const res = await simulatePolicyYaml(session.token, yamlInput, mockScoreInput, undefined, selectedOrgId);
      setSimulationResult(res);
    } catch (err: any) {
      setErrorMsg(err.message || 'Simulation failed');
      setSimulationResult(null);
    } finally {
      setIsSimulating(false);
    }
  };

  const isLoading = isValidating || isSimulating;

  return (
    <div className="space-y-6">
      <PageHeader
        category="GOVERNANCE"
        title="Policy Editor & Simulator"
        description="Validate Rego/YAML security policy schemas and simulate evaluation outcomes via server PolicyEngine"
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: YAML Code Editor Container */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 lg:col-span-7 flex flex-col h-[700px]">
          <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-[#1C2B40]">
            <span className="text-sm font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <FileCode className="h-5 w-5 text-[#00B8FF]" />
              <span>YAML Policy Definition (PyYAML Safe Schema)</span>
            </span>
            <span className="text-[11px] font-mono text-[#667B94]">Max 64 KB</span>
          </div>

          <textarea
            value={yamlInput}
            onChange={(e) => setYamlInput(e.target.value)}
            className="flex-1 w-full rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 font-mono text-xs text-[#C8D5E5] focus:border-[#168DCC] focus:outline-none resize-none leading-relaxed"
            rows={20}
          />

          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mt-4 pt-4 border-t border-[#1C2B40]">
            <div className="flex items-center gap-2.5 text-xs">
              <Sliders className="h-4 w-4 text-[#91A5BD]" />
              <span className="text-[#91A5BD] font-medium">Mock Risk Score:</span>
              <input
                type="number"
                min="0"
                max="100"
                value={mockScoreInput}
                onChange={(e) => setMockScoreInput(Number(e.target.value))}
                className="w-20 rounded-lg border border-[#1C2B40] bg-[#0A1424] px-3 py-1 text-xs font-bold font-mono text-[#F4F8FC] focus:border-[#168DCC] focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-3">
              <Button
                variant="secondary"
                loading={isValidating}
                disabled={isLoading}
                onClick={handleValidate}
                icon={<CheckCircle2 className="h-4 w-4 text-[#00B8FF]" />}
              >
                Validate Schema
              </Button>

              <Button
                variant="primary"
                loading={isSimulating}
                disabled={isLoading}
                onClick={handleSimulate}
                icon={<Play className="h-4 w-4" />}
              >
                Simulate Policy
              </Button>
            </div>
          </div>
        </div>

        {/* Right Column: Validation & Simulation Output Drawer */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 lg:col-span-5 flex flex-col h-[700px] overflow-y-auto space-y-5">
          {errorMsg && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300 flex items-start gap-2.5">
              <ShieldAlert className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block font-semibold mb-0.5">Execution Error:</strong>
                <span>{errorMsg}</span>
              </div>
            </div>
          )}

          {/* Validation Output Card */}
          {validationResult && (
            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-3">
              <span className="text-[10px] font-bold uppercase tracking-wider text-[#667B94] block border-b border-[#1C2B40] pb-2">
                Schema Validation Result
              </span>

              {validationResult.valid ? (
                <div className="flex items-center gap-2 text-xs font-semibold text-[#00D7A7] pt-1">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>Valid Policy Configuration Schema</span>
                </div>
              ) : (
                <div className="space-y-1.5 text-xs text-[#FF4F72] pt-1">
                  <div className="flex items-center gap-2 font-semibold">
                    <XCircle className="h-4 w-4" />
                    <span>Schema Validation Failed</span>
                  </div>
                  {validationResult.errors.map((err, idx) => (
                    <p key={idx} className="text-[11px] text-[#91A5BD] font-mono leading-relaxed">{err}</p>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Live Simulation Decision Card */}
          {simulationResult && (
            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-[#1C2B40] pb-3">
                <span className="text-[10px] font-bold uppercase tracking-wider text-[#91A5BD]">
                  {simulationResult.watermark}
                </span>
                {simulationResult.simulated_decision === 'PASS' && <Badge variant="pass">PASS</Badge>}
                {simulationResult.simulated_decision === 'PASS_WITH_WARNING' && <Badge variant="warning">WARNING</Badge>}
                {simulationResult.simulated_decision === 'BLOCK' && <Badge variant="block">BLOCK</Badge>}
              </div>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[#91A5BD]">Simulated Decision:</span>
                  <span className="font-bold text-[#F4F8FC]">{simulationResult.simulated_decision}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[#91A5BD]">Simulated Risk Score:</span>
                  <TechnicalValue value={`${simulationResult.simulated_risk_score} / 100`} copyable={false} />
                </div>

                <div className="pt-2">
                  <span className="text-[#91A5BD] font-semibold block mb-1.5">Evaluation Rationale:</span>
                  <div className="text-[11px] bg-[#07111F] p-3 rounded-lg border border-[#1C2B40] font-mono text-[#C8D5E5] leading-relaxed">
                    {simulationResult.rationale}
                  </div>
                </div>
              </div>
            </div>
          )}

          {!validationResult && !simulationResult && !errorMsg && (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-xs text-[#91A5BD] space-y-3 p-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-[#0A1424] border border-[#1C2B40] text-[#667B94]">
                <Sparkles className="h-6 w-6 stroke-[1.8]" />
              </div>
              <p className="max-w-xs leading-relaxed">
                Click "Validate Schema" or "Simulate Policy" to test the YAML definition against the server PolicyEngine.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

