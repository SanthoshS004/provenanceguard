import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import { Button } from './ui/Button';
import { TechnicalValue } from './ui/TechnicalValue';
import {
  Shield,
  Building2,
  FolderGit2,
  LogOut,
  Key,
  ShieldAlert,
  Search,
  ChevronDown,
  UserCheck,
  Sparkles,
  Bell,
  X,
} from 'lucide-react';

export const Header: React.FC = () => {
  const { session, isAuthenticated, loginWithDevToken, logout, toastMessage, clearToast } = useAuth();
  const { selectedOrgId, selectedProjectId, projects, setSelectedOrgId, setSelectedProjectId } = useTenant();

  const [devOrgInput, setDevOrgInput] = useState(selectedOrgId);
  const [devRoleInput, setDevRoleInput] = useState('SECURITY_ANALYST');
  const [showDevModal, setShowDevModal] = useState(false);
  const [showTenantModal, setShowTenantModal] = useState(false);

  const handleDevLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    await loginWithDevToken(devOrgInput, devRoleInput);
    setShowDevModal(false);
  };

  const handleTenantChange = (e: React.FormEvent) => {
    e.preventDefault();
    setSelectedOrgId(devOrgInput);
    setShowTenantModal(false);
  };

  const formattedOrgName = selectedOrgId === '00000000-0000-0000-0000-000000000001'
    ? 'Acme Security (Default)'
    : `${selectedOrgId.slice(0, 8)}...${selectedOrgId.slice(-4)}`;

  return (
    <header className="sticky top-0 z-40 h-[70px] border-b border-[#1C2B40] bg-[#07111E]/95 backdrop-blur-md px-6 flex items-center justify-between gap-4 shrink-0">
      {toastMessage && (
        <div className="absolute top-[70px] left-6 right-6 z-50 flex items-center justify-between rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs font-medium text-amber-300 shadow-lg">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
            <span>{toastMessage}</span>
          </div>
          <button onClick={clearToast} className="text-amber-400 hover:text-amber-200 text-xs">Dismiss</button>
        </div>
      )}

      {/* Left: Brand Identity */}
      <div className="flex items-center gap-3 shrink-0">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-[#00B8FF]/20 to-[#168DCC]/40 text-[#00B8FF] border border-[#00B8FF]/30">
          <Shield className="h-5 w-5 stroke-[2.2]" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm font-extrabold tracking-tight text-slate-100">ProvenanceGuard</h1>
            <span className="rounded bg-[#00B8FF]/10 px-1.5 py-0.5 text-[10px] font-bold text-[#00B8FF] border border-[#00B8FF]/20">v1.0.0</span>
          </div>
          <p className="text-[11px] font-medium text-slate-400">Software Supply-Chain Security Operations</p>
        </div>
      </div>

      {/* Center: Global Search Bar (475-485px on desktop, ~38-40px height) */}
      <div className="hidden md:flex items-center flex-1 max-w-[480px] mx-4">
        <div className="relative w-full">
          <Search className="absolute left-3.5 top-2.5 h-4 w-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search verification ID, artifact SHA, or SBOM PURL..."
            className="w-full h-10 rounded-lg border border-[#1C2B40] bg-[#0A1424] pl-10 pr-14 text-xs text-slate-200 placeholder-slate-400 focus:border-[#168DCC] focus:ring-1 focus:ring-[#168DCC]/30 focus:outline-none transition"
          />
          <kbd className="absolute right-3 top-2.5 hidden sm:inline-flex items-center rounded border border-[#1C2B40] bg-[#0D1728] px-1.5 py-0.5 text-[10px] font-mono text-slate-400">
            Ctrl K
          </kbd>
        </div>
      </div>

      {/* Right: Tenant Controls & Authentication */}
      <div className="flex items-center gap-3 shrink-0">
        {/* Organization / Project Selector */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setDevOrgInput(selectedOrgId);
              setShowTenantModal(true);
            }}
            className="flex items-center gap-2 h-9 rounded-lg border border-[#1C2B40] bg-[#0D1728] px-3 text-xs font-medium text-slate-200 hover:border-[#223650] hover:bg-[#111F32] transition"
            title="Switch Organization Context"
          >
            <Building2 className="h-4 w-4 text-[#00B8FF]" />
            <span className="font-semibold">{formattedOrgName}</span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
          </button>

          {projects.length > 0 && (
            <div className="hidden lg:flex items-center gap-2 h-9 rounded-lg border border-[#1C2B40] bg-[#0D1728] px-3 text-xs text-slate-200">
              <FolderGit2 className="h-4 w-4 text-indigo-400" />
              <select
                value={selectedProjectId}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="bg-transparent font-medium text-slate-200 focus:outline-none cursor-pointer"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id} className="bg-[#0D1728] text-slate-200">
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* Notifications Icon Button */}
        <button
          className="relative h-9 w-9 flex items-center justify-center rounded-lg border border-[#1C2B40] bg-[#0D1728] text-slate-400 hover:text-slate-100 hover:bg-[#111F32] transition"
          title="Notifications & Security Alerts"
        >
          <Bell className="h-4 w-4" />
          <span className="absolute top-2 right-2 h-2 w-2 rounded-full bg-[#00B8FF] ring-2 ring-[#07111E]"></span>
        </button>

        {/* Auth / Dev Token Button */}
        {isAuthenticated && session ? (
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 h-9 rounded-lg border border-[#1C2B40] bg-[#0D1728] px-3 text-xs font-semibold text-slate-200">
              <UserCheck className="h-4 w-4 text-[#00D7A7]" />
              <span>{session.role}</span>
            </div>
            <button
              onClick={logout}
              className="h-9 w-9 flex items-center justify-center rounded-lg border border-[#1C2B40] bg-[#0D1728] text-slate-400 hover:text-slate-100 hover:bg-[#111F32] transition"
              title="Logout Session"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <Button
            variant="primary"
            onClick={() => setShowDevModal(true)}
            icon={<Key className="h-4 w-4" />}
          >
            Dev Token Login
          </Button>
        )}
      </div>

      {/* Tenant Context Switcher Modal */}
      {showTenantModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="panel-card w-full max-w-md p-6 space-y-4 border border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between border-b border-[#1C2B40] pb-3">
              <div className="flex items-center gap-2">
                <Building2 className="h-5 w-5 text-[#00B8FF]" />
                <h2 className="text-sm font-bold text-slate-100">Switch Organization Tenant Context</h2>
              </div>
              <button onClick={() => setShowTenantModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              ProvenanceGuard enforces strict tenant isolation using PostgreSQL Row Level Security (RLS).
            </p>

            <form onSubmit={handleTenantChange} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Organization UUID</label>
                <input
                  type="text"
                  value={devOrgInput}
                  onChange={(e) => setDevOrgInput(e.target.value)}
                  placeholder="Org UUID"
                  className="w-full font-mono text-xs"
                  required
                />
                <p className="text-[11px] text-slate-400 mt-1">
                  Default org: <TechnicalValue value="00000000-0000-0000-0000-000000000001" copyable />
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowTenantModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary">
                  Update Context
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Dev Token Modal */}
      {showDevModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="panel-card w-full max-w-md p-6 space-y-4 border border-[#1C2B40] bg-[#0D1728]">
            <div className="flex items-center justify-between border-b border-[#1C2B40] pb-3">
              <div className="flex items-center gap-2">
                <Sparkles className="h-5 w-5 text-[#00B8FF]" />
                <h2 className="text-sm font-bold text-slate-100">Issue Development Auth Token</h2>
              </div>
              <button onClick={() => setShowDevModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="h-4 w-4" />
              </button>
            </div>
            <p className="text-xs text-slate-400">
              Issues an RS256 JWT access token via API gateway when dev auth is enabled.
            </p>

            <form onSubmit={handleDevLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Organization UUID</label>
                <input
                  type="text"
                  value={devOrgInput}
                  onChange={(e) => setDevOrgInput(e.target.value)}
                  placeholder="Org UUID"
                  className="w-full font-mono text-xs"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">System Role</label>
                <select
                  value={devRoleInput}
                  onChange={(e) => setDevRoleInput(e.target.value)}
                  className="w-full text-xs font-semibold"
                >
                  <option value="ADMIN">ADMIN</option>
                  <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                  <option value="DEVELOPER">DEVELOPER</option>
                  <option value="AUDITOR">AUDITOR</option>
                  <option value="VIEWER">VIEWER</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <Button type="button" variant="secondary" onClick={() => setShowDevModal(false)}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary">
                  Issue & Authenticate
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </header>
  );
};
