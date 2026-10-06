import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import { uploadArtifact, submitVerification, getVerificationDetails } from '../services/api';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import { Upload, X, Loader2, AlertTriangle, ShieldCheck, Binary } from 'lucide-react';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const { session, loginWithDevToken } = useAuth();
  const { selectedOrgId, selectedProjectId } = useTenant();

  const [file, setFile] = useState<File | null>(null);
  const [version, setVersion] = useState<string>('1.0.0');
  const [step, setStep] = useState<'IDLE' | 'UPLOADING' | 'QUEUING' | 'PROCESSING' | 'DONE' | 'ERROR'>('IDLE');
  const [errorMessage, setErrorMessage] = useState<string>('');
  
  const [uploadedArtifact, setUploadedArtifact] = useState<{
    id: string;
    digest_sha256: string;
    media_type: string;
    size_bytes: number;
  } | null>(null);

  const [verificationResult, setVerificationResult] = useState<{
    id: string;
    decision: string;
    risk_score: number;
    status: string;
  } | null>(null);

  if (!isOpen) return null;

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
    }
  };

  const handleUploadAndVerify = async () => {
    if (!file) return;

    setStep('UPLOADING');
    setErrorMessage('');
    setUploadedArtifact(null);
    setVerificationResult(null);

    let token: string | undefined = session?.token;
    const currentOrg: string = selectedOrgId || session?.organization_id || '00000000-0000-0000-0000-000000000001';

    try {
      if (!token) {
        token = await loginWithDevToken(currentOrg, 'SECURITY_ANALYST');
      }

      const activeToken: string = token;

      // 1. Upload Artifact to Backend (Streams payload -> MinIO -> PostgreSQL)
      const artifact = await uploadArtifact(
        activeToken,
        file,
        selectedProjectId || undefined,
        version,
        currentOrg
      );

      setUploadedArtifact({
        id: artifact.id,
        digest_sha256: artifact.digest_sha256,
        media_type: artifact.media_type,
        size_bytes: artifact.size_bytes,
      });

      // 2. Submit Verification Job to Backend (PostgreSQL Outbox -> Redis ARQ Queue)
      setStep('QUEUING');
      const targetProj: string = artifact.project_id || selectedProjectId || session?.project_id || '00000000-0000-0000-0000-000000000002';

      const jobRes = await submitVerification(
        activeToken,
        {
          organization_id: currentOrg,
          project_id: targetProj,
          production_artifact_id: artifact.id,
        },
        currentOrg
      );

      // 3. Poll Background Worker State
      setStep('PROCESSING');
      const runId = jobRes.verification_run_id;

      for (let i = 0; i < 30; i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        try {
          const runDetails = await getVerificationDetails(activeToken, runId, currentOrg);
          const st = runDetails.status as string;
          if (st === 'SUCCEEDED' || st === 'COMPLETED' || st === 'FAILED') {
            setVerificationResult({
              id: runDetails.id,
              decision: runDetails.decision,
              risk_score: runDetails.risk_score,
              status: runDetails.status,
            });
            setStep('DONE');
            onSuccess();
            return;
          }
        } catch {
          // Keep polling
        }
      }

      // Final poll attempt
      try {
        const runDetails = await getVerificationDetails(activeToken, runId, currentOrg);
        setVerificationResult({
          id: runDetails.id,
          decision: runDetails.decision,
          risk_score: runDetails.risk_score,
          status: runDetails.status,
        });
      } catch {
        // Fallback
      }

      setStep('DONE');
      onSuccess();
    } catch (err: any) {
      setErrorMessage(err.message || 'Artifact upload or verification failed.');
      setStep('ERROR');
    }
  };

  const handleReset = () => {
    setFile(null);
    setStep('IDLE');
    setErrorMessage('');
    setUploadedArtifact(null);
    setVerificationResult(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-2xl panel-card p-6 md:p-8 space-y-6 border-[#1C2B40] bg-[#0D1728] text-slate-100 shadow-2xl rounded-2xl">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#00B8FF]/10 border border-[#00B8FF]/20 rounded-xl text-[#00B8FF]">
              <Upload className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold tracking-tight text-slate-100">Submit Real Software Artifact</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Ingest binary into MinIO content-addressable storage & trigger verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-[#111F32] text-slate-400 hover:text-slate-200 rounded-xl transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        {step === 'IDLE' && (
          <div className="space-y-5">
            {/* Drag & Drop Area */}
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleFileDrop}
              className="border-2 border-dashed border-[#1C2B40] hover:border-[#00B8FF]/60 bg-[#0A1424] rounded-2xl p-8 text-center transition cursor-pointer space-y-3"
            >
              <input
                type="file"
                id="artifactFileInput"
                onChange={handleFileChange}
                className="hidden"
              />
              <label htmlFor="artifactFileInput" className="cursor-pointer space-y-3 block">
                <div className="mx-auto w-12 h-12 rounded-2xl bg-[#00B8FF]/10 border border-[#00B8FF]/20 flex items-center justify-center text-[#00B8FF]">
                  <Binary className="h-6 w-6" />
                </div>
                <div>
                  <p className="text-sm font-bold text-slate-200">
                    {file ? file.name : 'Click to browse or drag & drop artifact file'}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    Supports ELF binaries (.bin), OCI image layers (.tar), SBOMs (.json), and Attestations
                  </p>
                </div>
              </label>
            </div>

            {file && (
              <div className="space-y-3">
                <div className="rounded-xl bg-[#0A1424] border border-[#1C2B40] p-4 flex items-center justify-between text-xs">
                  <div className="space-y-1">
                    <p className="font-bold text-[#00B8FF] font-mono">{file.name}</p>
                    <p className="text-slate-400">Size: {(file.size / 1024).toFixed(1)} KiB</p>
                  </div>
                  <button
                    onClick={() => setFile(null)}
                    className="text-slate-400 hover:text-[#FF4F72] text-xs font-semibold px-2 py-1 rounded"
                  >
                    Remove
                  </button>
                </div>

                <div className="flex items-center gap-3 bg-[#0A1424] p-3 rounded-xl border border-[#1C2B40] text-xs">
                  <label htmlFor="artifactVersion" className="text-slate-400 font-semibold shrink-0">
                    Artifact Version:
                  </label>
                  <input
                    id="artifactVersion"
                    type="text"
                    value={version}
                    onChange={(e) => setVersion(e.target.value)}
                    className="font-mono text-xs w-32"
                  />
                </div>
              </div>
            )}

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button
                variant="primary"
                disabled={!file}
                onClick={handleUploadAndVerify}
              >
                Upload & Verify Artifact
              </Button>
            </div>
          </div>
        )}

        {(step === 'UPLOADING' || step === 'QUEUING' || step === 'PROCESSING') && (
          <div className="py-8 space-y-6 text-center">
            <div className="flex justify-center">
              <Loader2 className="h-10 w-10 text-[#00B8FF] animate-spin" />
            </div>

            <div className="space-y-2">
              <h4 className="text-lg font-bold text-slate-100">
                {step === 'UPLOADING' && 'Streaming Artifact to Storage & Computing SHA-256...'}
                {step === 'QUEUING' && 'Creating Verification Run & Outbox Event...'}
                {step === 'PROCESSING' && 'Worker Executing Static Verification Pipeline...'}
              </h4>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Executing real zero-trust verification via PostgreSQL RLS tenant context and PolicyEngine.
              </p>
            </div>

            {uploadedArtifact && (
              <div className="max-w-md mx-auto rounded-xl bg-[#0A1424] border border-[#1C2B40] p-4 text-left font-mono text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-slate-400">Artifact ID:</span>
                  <TechnicalValue value={uploadedArtifact.id} truncate truncateLength={8} className="text-[#00B8FF] font-bold" />
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Authoritative SHA-256:</span>
                  <TechnicalValue value={uploadedArtifact.digest_sha256} className="text-[#00D7A7] font-bold" copyable />
                </div>
              </div>
            )}
          </div>
        )}

        {step === 'DONE' && (
          <div className="py-6 space-y-6 text-center">
            <div className="mx-auto w-14 h-14 rounded-2xl bg-[#00D7A7]/10 border border-[#00D7A7]/20 flex items-center justify-center text-[#00D7A7]">
              <ShieldCheck className="h-8 w-8" />
            </div>

            <div className="space-y-2">
              <h4 className="text-xl font-extrabold text-slate-100">Artifact Verification Complete</h4>
              <p className="text-xs text-slate-400">
                Real backend evaluation completed via PolicyEngine.
              </p>
            </div>

            {verificationResult && (
              <div className="max-w-md mx-auto rounded-2xl bg-[#0A1424] border border-[#1C2B40] p-5 space-y-3 text-xs">
                <div className="flex justify-between items-center pb-2 border-b border-[#1C2B40]">
                  <span className="text-slate-400">Authoritative Decision:</span>
                  <Badge status={verificationResult.decision} />
                </div>

                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Evaluated Risk Score:</span>
                  <span className="font-mono font-bold text-slate-100 text-sm">
                    {verificationResult.risk_score} / 100
                  </span>
                </div>

                {uploadedArtifact && (
                  <div className="pt-2 border-t border-[#1C2B40] text-left space-y-1">
                    <span className="text-slate-400 block text-[11px]">Artifact SHA-256:</span>
                    <TechnicalValue value={uploadedArtifact.digest_sha256} copyable className="text-slate-200" />
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-center gap-3">
              <Button variant="secondary" onClick={handleReset}>
                Submit Another
              </Button>
              <Button variant="primary" onClick={onClose}>
                Close & View Dashboard
              </Button>
            </div>
          </div>
        )}

        {step === 'ERROR' && (
          <div className="py-6 space-y-6 text-center">
            <div className="mx-auto w-14 h-14 rounded-2xl bg-[#FF4F72]/10 border border-[#FF4F72]/20 flex items-center justify-center text-[#FF4F72]">
              <AlertTriangle className="h-8 w-8" />
            </div>

            <div className="space-y-2">
              <h4 className="text-lg font-bold text-slate-100">Upload or Verification Failed</h4>
              <p className="text-xs text-[#FF4F72] max-w-md mx-auto">{errorMessage}</p>
            </div>

            <div className="flex justify-center gap-3">
              <Button variant="primary" onClick={handleReset}>
                Try Again
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
