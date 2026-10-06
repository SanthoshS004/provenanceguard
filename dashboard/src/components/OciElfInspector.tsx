import React from 'react';
import { Box, Binary } from 'lucide-react';
import { PageHeader } from './ui/PageHeader';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';

export const OciElfInspector: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        category="EVIDENCE & ANALYSIS"
        title="OCI Container & ELF Diff"
        description="OCI container layer whiteout inspector, RootFS diff verification, and ELF W^X section protection analysis"
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* OCI RootFS Structural Diff */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
            <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <Box className="h-5 w-5 text-[#00B8FF]" />
              <span>OCI RootFS Layer & Whiteout Inspector</span>
            </h3>
            <Badge variant="pass">LAYER DIFF CLEAN</Badge>
          </div>

          <div className="space-y-4 text-xs">
            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-[#F4F8FC] font-bold">Layer 0 (Base OS):</span>
                <Badge variant="neutral">COMPRESSED GZIP</Badge>
              </div>
              <TechnicalValue
                value="sha256:74892bc012849204a91b... -> diff_id: sha256:1a829f03..."
                truncate={false}
              />
            </div>

            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-[#F4F8FC] font-bold">Layer 1 (Application Binaries):</span>
                <Badge variant="neutral">COMPRESSED GZIP</Badge>
              </div>
              <TechnicalValue
                value="sha256:9f812a45bc101294820a... -> diff_id: sha256:4b901a89..."
                truncate={false}
              />
            </div>

            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
              <span className="text-[#91A5BD] font-bold block mb-1">Whiteout & Symlink Metadata Security Check:</span>
              <div className="grid grid-cols-2 gap-3 text-[11px]">
                <div>
                  <span className="text-[#91A5BD] block">Whiteout Files (.wh.*):</span>
                  <span className="font-bold text-[#F4F8FC] text-xs block mt-0.5">0 Detected</span>
                </div>
                <div>
                  <span className="text-[#91A5BD] block">Inert Symlinks Check:</span>
                  <div className="mt-0.5">
                    <Badge variant="pass">ALL INERT SAFE</Badge>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ELF Binary Symbol Delta Tree */}
        <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
            <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <Binary className="h-5 w-5 text-[#12C8FF]" />
              <span>ELF Section Permissions & Symbol Delta Tree</span>
            </h3>
            <Badge variant="pass">W^X HARDENED</Badge>
          </div>

          <div className="space-y-4 text-xs">
            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-2">
              <span className="text-[#91A5BD] font-bold block">Section W^X Permission Evaluation:</span>
              <p className="text-[#00D7A7] font-semibold text-[11px]">
                STRICT W^X ENFORCED — No Writeable+Executable (.text / .rodata) Sections
              </p>
            </div>

            <div className="rounded-lg border border-[#1C2B40] bg-[#0A1424] p-4 space-y-3">
              <span className="text-[#91A5BD] font-bold block">Exported Function Symbol Delta:</span>
              <ul className="space-y-2 font-mono text-[11px]">
                <li className="flex items-center gap-2 text-[#00D7A7] bg-[#00D7A7]/10 px-3 py-2 rounded-lg border border-[#00D7A7]/20">
                  <span className="font-bold">+</span>
                  <span>pg_verification_init()</span>
                </li>
                <li className="flex items-center gap-2 text-[#00D7A7] bg-[#00D7A7]/10 px-3 py-2 rounded-lg border border-[#00D7A7]/20">
                  <span className="font-bold">+</span>
                  <span>pg_policy_eval()</span>
                </li>
                <li className="flex items-center gap-2 text-[#91A5BD] bg-[#0A1424] px-3 py-2 rounded-lg border border-[#1C2B40]">
                  <span className="font-bold">=</span>
                  <span>main() (Unchanged)</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

