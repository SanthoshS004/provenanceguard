import React, { useState } from 'react';
import { AuthProvider } from './context/AuthContext';
import { TenantProvider } from './context/TenantContext';
import { Header } from './components/Header';
import { Overview } from './components/Overview';
import { VerificationExplorer } from './components/VerificationExplorer';
import { AttestationViewer } from './components/AttestationViewer';
import { OciElfInspector } from './components/OciElfInspector';
import { SbomMatrix } from './components/SbomMatrix';
import { PolicyEditor } from './components/PolicyEditor';
import { AdminWebhooks } from './components/AdminWebhooks';
import { AuditLogViewer } from './components/AuditLogViewer';
import { GitHubIntegrations } from './components/GitHubIntegrations';
import {
  LayoutDashboard,
  Layers,
  Github,
  KeyRound,
  Box,
  Package,
  FileCode,
  Settings,
  FileLock2,
  ChevronRight,
  ShieldCheck,
} from 'lucide-react';

type Tab = 'OVERVIEW' | 'EXPLORER' | 'GITHUB' | 'ATTESTATION' | 'OCI_ELF' | 'SBOM' | 'POLICY' | 'ADMIN' | 'AUDIT';

export const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('OVERVIEW');

  const navItems: { id: Tab; label: string; category: string; icon: React.FC<{ className?: string }> }[] = [
    { id: 'OVERVIEW', label: 'Executive Overview', category: 'MAIN OPERATIONS', icon: LayoutDashboard },
    { id: 'EXPLORER', label: 'Verification Explorer', category: 'MAIN OPERATIONS', icon: Layers },
    { id: 'GITHUB', label: 'GitHub Integrations', category: 'MAIN OPERATIONS', icon: Github },

    { id: 'ATTESTATION', label: 'Sigstore & SLSA Evidence', category: 'EVIDENCE & ANALYSIS', icon: KeyRound },
    { id: 'OCI_ELF', label: 'OCI Container & ELF Diff', category: 'EVIDENCE & ANALYSIS', icon: Box },
    { id: 'SBOM', label: 'SBOM Dependency Drift', category: 'EVIDENCE & ANALYSIS', icon: Package },

    { id: 'POLICY', label: 'Policy Editor & Simulator', category: 'GOVERNANCE', icon: FileCode },

    { id: 'ADMIN', label: 'API Keys & Webhooks', category: 'ADMINISTRATION', icon: Settings },
    { id: 'AUDIT', label: 'Audit Log Stream', category: 'ADMINISTRATION', icon: FileLock2 },
  ];

  const categories = Array.from(new Set(navItems.map((item) => item.category)));

  return (
    <div className="min-h-screen flex flex-col bg-[#07111F] text-slate-100 selection:bg-[#00B8FF] selection:text-slate-950">
      <Header />

      <div className="flex-1 flex max-w-[1750px] w-full mx-auto px-6 md:px-8 py-8 gap-8">
        {/* Sidebar Navigation Rail (260px wide) */}
        <aside className="w-[260px] rounded-2xl bg-[#07111E] border border-[#1C2B40] p-4 flex flex-col justify-between self-start shrink-0 shadow-xl">
          <div className="space-y-6">
            {categories.map((category) => (
              <div key={category} className="space-y-2">
                <span className="px-3 text-[10px] font-extrabold tracking-widest uppercase text-slate-400">
                  {category}
                </span>
                <div className="space-y-1">
                  {navItems
                    .filter((item) => item.category === category)
                    .map((item) => {
                      const Icon = item.icon;
                      const isActive = activeTab === item.id;
                      return (
                        <button
                          key={item.id}
                          onClick={() => setActiveTab(item.id)}
                          className={`w-full h-10 flex items-center justify-between px-3.5 rounded-lg text-xs transition duration-150 ${
                            isActive
                              ? 'bg-[#102238] text-[#12C8FF] border-l-3 border-[#00B8FF] font-bold shadow-sm'
                              : 'text-slate-400 hover:bg-[#111F32] hover:text-slate-200 font-medium'
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <Icon className={`h-4 w-4 ${isActive ? 'text-[#00B8FF]' : 'text-slate-400'}`} />
                            <span>{item.label}</span>
                          </div>
                          {isActive && <ChevronRight className="h-3.5 w-3.5 text-[#00B8FF]" />}
                        </button>
                      );
                    })}
                </div>
              </div>
            ))}
          </div>

          {/* Bottom Engine Indicator Card */}
          <div className="pt-6 mt-6 border-t border-[#1C2B40]">
            <div className="rounded-xl bg-[#081321] border border-[#1C2B40] p-3.5 space-y-1 text-center">
              <div className="flex items-center justify-center gap-2 text-xs font-bold text-[#00D7A7]">
                <ShieldCheck className="h-4 w-4" />
                <span>Fail-Closed Engine</span>
              </div>
              <p className="text-[11px] text-slate-400 leading-snug">
                Authoritative verification, policy & audit logging active.
              </p>
            </div>
          </div>
        </aside>

        {/* Main Content Area (Spacious 30-32px horizontal padding) */}
        <main className="flex-1 min-w-0 bg-[#081321] p-6 md:p-8 rounded-2xl border border-[#1C2B40] shadow-xl">
          {activeTab === 'OVERVIEW' && <Overview />}
          {activeTab === 'EXPLORER' && <VerificationExplorer />}
          {activeTab === 'GITHUB' && <GitHubIntegrations onNavigateToExplorer={() => setActiveTab('EXPLORER')} />}
          {activeTab === 'ATTESTATION' && <AttestationViewer />}
          {activeTab === 'OCI_ELF' && <OciElfInspector />}
          {activeTab === 'SBOM' && <SbomMatrix />}
          {activeTab === 'POLICY' && <PolicyEditor />}
          {activeTab === 'ADMIN' && <AdminWebhooks />}
          {activeTab === 'AUDIT' && <AuditLogViewer />}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <TenantProvider>
        <AppContent />
      </TenantProvider>
    </AuthProvider>
  );
};
