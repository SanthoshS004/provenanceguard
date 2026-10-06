import React from 'react';
import { KeyRound, ShieldCheck, Cpu } from 'lucide-react';
import { PageHeader } from './ui/PageHeader';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';

export const AttestationViewer: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        category="EVIDENCE & ANALYSIS"
        title="Sigstore & SLSA Evidence"
        description="Inspect Cosign keyless signatures, Fulcio certificates, Rekor transparency log inclusion proofs, and SLSA provenance"
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Cosign / Fulcio Signature Identity Card */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
            <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <KeyRound className="h-5 w-5 text-[#00B8FF]" />
              <span>Cosign Signature & Fulcio Leaf Certificate</span>
            </h3>
            <Badge variant="pass">VERIFIED</Badge>
          </div>

          <div className="space-y-3.5 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-[#1C2B40]/60">
              <span className="text-[#91A5BD]">Signature Scheme:</span>
              <span className="font-semibold text-[#00D7A7] font-mono">RS256 PKCS#1 v1.5</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[#1C2B40]/60">
              <span className="text-[#91A5BD]">OIDC Keyless Issuer:</span>
              <TechnicalValue value="https://token.actions.githubusercontent.com" truncate={false} />
            </div>
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start py-2 border-b border-[#1C2B40]/60 gap-2">
              <span className="text-[#91A5BD] shrink-0">Subject Alt Name (SAN):</span>
              <TechnicalValue
                value="https://github.com/org/repo/.github/workflows/build.yml@refs/heads/main"
                truncate={false}
              />
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-[#91A5BD]">SAN Authorization Rule:</span>
              <Badge variant="pass">AUTHORIZED REGEX MATCH</Badge>
            </div>
          </div>
        </div>

        {/* Rekor Transparency Log Inclusion Proof */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
            <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <ShieldCheck className="h-5 w-5 text-[#6C7CFF]" />
              <span>Rekor Transparency Log Proof</span>
            </h3>
            <Badge variant="pass">INCLUSION VERIFIED</Badge>
          </div>

          <div className="space-y-3.5 text-xs">
            <div className="flex justify-between items-center py-2 border-b border-[#1C2B40]/60">
              <span className="text-[#91A5BD]">Rekor Log Index:</span>
              <TechnicalValue value="12849204" copyable={false} />
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[#1C2B40]/60">
              <span className="text-[#91A5BD]">Signed Entry Timestamp (SET):</span>
              <span className="font-mono text-[#00D7A7] font-semibold">VALID (Timestamp Verified)</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-[#1C2B40]/60">
              <span className="text-[#91A5BD]">Merkle Inclusion Proof:</span>
              <span className="font-semibold text-[#00D7A7] font-mono">HASH_PATH_VERIFIED</span>
            </div>
            <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start py-2 gap-2">
              <span className="text-[#91A5BD] shrink-0">Log Root Key Hash:</span>
              <TechnicalValue
                value="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                truncate={false}
              />
            </div>
          </div>
        </div>
      </div>

      {/* SLSA v1.2 Provenance Graph */}
      <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
          <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
            <Cpu className="h-5 w-5 text-[#12C8FF]" />
            <span>SLSA v1.2 Provenance Graph & in-toto DSSE Envelope</span>
          </h3>
          <Badge variant="pass">SLSA LEVEL 3</Badge>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#667B94] block">Build Environment</span>
            <TechnicalValue value="https://github.com/actions/runner" truncate={false} />
            <p className="text-[#91A5BD] text-[11px] mt-1">Runner OS: Ubuntu 22.04 LTS (x86_64)</p>
          </div>

          <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#667B94] block">Builder Identity</span>
            <TechnicalValue value="slsa-framework/slsa-github-generator" truncate={false} />
            <p className="text-[#91A5BD] text-[11px] mt-1">SLSA Build Level: Level 3 Verified</p>
          </div>

          <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-[#667B94] block">Source SCM Commit SHA</span>
            <TechnicalValue value="8f14b9c472d8a01b76428e9321c7a52f40901234" truncate={false} />
            <p className="text-[#91A5BD] text-[11px] mt-1">Ref: refs/heads/main</p>
          </div>
        </div>
      </div>
    </div>
  );
};

