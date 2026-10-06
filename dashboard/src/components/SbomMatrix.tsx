import React from 'react';
import { Package } from 'lucide-react';
import { PageHeader } from './ui/PageHeader';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';

export const SbomMatrix: React.FC = () => {
  return (
    <div className="space-y-6">
      <PageHeader
        category="EVIDENCE & ANALYSIS"
        title="SBOM Dependency Drift"
        description="SPDX v2.3 and CycloneDX v1.5 inventory diff, Package URL (PURL) drift analysis, and license compliance"
      />

      {/* Main Table Card */}
      <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
          <div>
            <h3 className="text-base font-bold text-[#F4F8FC] flex items-center gap-2.5">
              <Package className="h-5 w-5 text-[#00B8FF]" />
              <span>Dependency Inventory Summary</span>
            </h3>
            <p className="text-xs text-[#91A5BD] mt-0.5">
              Automated Package URL (PURL) drift analysis against golden reference SBOMs
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-[#91A5BD] min-w-[750px]">
            <thead className="border-b border-[#1C2B40] bg-[#0A1424] font-semibold text-[#91A5BD]">
              <tr>
                <th className="py-3 px-4">Package Identity (PURL)</th>
                <th className="py-3 px-4">Reference Version</th>
                <th className="py-3 px-4">Production Version</th>
                <th className="py-3 px-4">Drift Status</th>
                <th className="py-3 px-4">Declared License</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1C2B40]/60">
              <tr className="hover:bg-[#111F32] transition h-12">
                <td className="py-3 px-4 max-w-[280px]">
                  <TechnicalValue value="pkg:deb/ubuntu/openssl" truncate={false} />
                </td>
                <td className="py-3 px-4 font-mono text-[#91A5BD]">3.0.2-0ubuntu1.10</td>
                <td className="py-3 px-4 font-mono text-[#F4F8FC]">3.0.2-0ubuntu1.12</td>
                <td className="py-3 px-4">
                  <Badge variant="pass">MATCH / PATCH</Badge>
                </td>
                <td className="py-3 px-4 text-[#91A5BD] font-mono text-[11px]">Apache-2.0</td>
              </tr>
              <tr className="hover:bg-[#111F32] transition h-12">
                <td className="py-3 px-4 max-w-[280px]">
                  <TechnicalValue value="pkg:deb/ubuntu/libcurl4" truncate={false} />
                </td>
                <td className="py-3 px-4 font-mono text-[#91A5BD]">7.81.0-1ubuntu1.14</td>
                <td className="py-3 px-4 font-mono text-[#FFB000]">7.81.0-1ubuntu1.16</td>
                <td className="py-3 px-4">
                  <Badge variant="warning">VERSION SHIFT</Badge>
                </td>
                <td className="py-3 px-4 text-[#91A5BD] font-mono text-[11px]">curl</td>
              </tr>
              <tr className="hover:bg-[#111F32] transition h-12">
                <td className="py-3 px-4 max-w-[280px]">
                  <TechnicalValue value="pkg:npm/unauthorized-lib" truncate={false} />
                </td>
                <td className="py-3 px-4 font-mono text-[#667B94]">None (Absent)</td>
                <td className="py-3 px-4 font-mono text-[#FF4F72]">1.0.0-malicious</td>
                <td className="py-3 px-4">
                  <Badge variant="block">UNEXPECTED ADDITION</Badge>
                </td>
                <td className="py-3 px-4 text-[#FF4F72] font-mono text-[11px]">UNLICENSE</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

