import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useTenant } from '../context/TenantContext';
import {
  getApiKeys,
  createApiKey,
  revokeApiKey,
  getWebhooks,
  createWebhook,
  testWebhook,
} from '../services/api';
import { ApiKey, WebhookSubscription } from '../types';
import { PageHeader } from './ui/PageHeader';
import { Button } from './ui/Button';
import { Badge } from './ui/Badge';
import { TechnicalValue } from './ui/TechnicalValue';
import { EmptyState } from './ui/EmptyState';
import {
  Key,
  Webhook,
  Plus,
  Trash2,
  Send,
  ShieldAlert,
  Copy,
  Check,
} from 'lucide-react';

export const AdminWebhooks: React.FC = () => {
  const { session } = useAuth();
  const { selectedOrgId, selectedProjectId } = useTenant();

  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookSubscription[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Modal States
  const [showKeyModal, setShowKeyModal] = useState<boolean>(false);
  const [keyName, setKeyName] = useState<string>('');
  const [keyRole, setKeyRole] = useState<string>('SECURITY_ANALYST');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [isCreatingKey, setIsCreatingKey] = useState<boolean>(false);
  const [keyModalError, setKeyModalError] = useState<string | null>(null);
  const [copiedSuccess, setCopiedSuccess] = useState<boolean>(false);

  const [showWebhookModal, setShowWebhookModal] = useState<boolean>(false);
  const [webhookUrl, setWebhookUrl] = useState<string>('');
  const [isCreatingWebhook, setIsCreatingWebhook] = useState<boolean>(false);
  const [testingWebhookId, setTestingWebhookId] = useState<string | null>(null);
  const webhookEvents = ['VERIFICATION_COMPLETED', 'FINDING_DETECTED'];

  const fetchData = async () => {
    if (!session?.token) return;
    try {
      const [keysData, hooksData] = await Promise.all([
        getApiKeys(session.token, selectedOrgId),
        getWebhooks(session.token, selectedOrgId),
      ]);
      setApiKeys(keysData);
      setWebhooks(hooksData);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load administrative data');
    }
  };

  useEffect(() => {
    fetchData();
  }, [session, selectedOrgId]);

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!session?.token) return;
    setIsCreatingKey(true);
    setKeyModalError(null);
    try {
      const result = await createApiKey(
        session.token,
        { name: keyName, role: keyRole, project_id: selectedProjectId },
        selectedOrgId
      );
      setCreatedSecret(result.api_key);
      fetchData();
    } catch (err: any) {
      setKeyModalError(err.message || 'API key creation failed');
    } finally {
      setIsCreatingKey(false);
    }
  };

  const handleCopyKey = async () => {
    if (!createdSecret) return;
    try {
      await navigator.clipboard.writeText(createdSecret);
      setCopiedSuccess(true);
      setTimeout(() => setCopiedSuccess(false), 3000);
    } catch {
      setCopiedSuccess(true);
    }
  };

  const handleRevokeKey = async (keyId: string) => {
    if (!session?.token || !confirm('Are you sure you want to revoke this API Key?')) return;
    try {
      await revokeApiKey(session.token, keyId, selectedOrgId);
      fetchData();
    } catch (err: any) {
      alert(err.message || 'Revocation failed');
    }
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!session?.token) return;
    setIsCreatingWebhook(true);
    try {
      await createWebhook(
        session.token,
        { target_url: webhookUrl, event_types: webhookEvents },
        selectedOrgId
      );
      setShowWebhookModal(false);
      setWebhookUrl('');
      fetchData();
    } catch (err: any) {
      alert(err.message || 'Webhook creation failed');
    } finally {
      setIsCreatingWebhook(false);
    }
  };

  const handleTestWebhook = async (subId: string) => {
    if (!session?.token) return;
    setTestingWebhookId(subId);
    try {
      await testWebhook(session.token, subId, selectedOrgId);
      alert('Test webhook payload dispatched successfully.');
    } catch (err: any) {
      alert(`Webhook test failed: ${err.message}`);
    } finally {
      setTestingWebhookId(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        category="ADMINISTRATION"
        title="API Keys & Webhooks"
        description="Manage REST API access credentials and HMAC-SHA256 signed outbound SIEM event webhooks"
      />

      {errorMsg && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-300 flex items-center gap-3">
          <ShieldAlert className="h-5 w-5 text-rose-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Section 1: API Keys Management */}
      <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
          <div className="flex items-center gap-2.5">
            <Key className="h-5 w-5 text-[#00B8FF]" />
            <h3 className="text-base font-bold text-[#F4F8FC]">API Access Keys</h3>
          </div>
          <Button
            variant="primary"
            onClick={() => setShowKeyModal(true)}
            icon={<Plus className="h-4 w-4" />}
          >
            Create API Key
          </Button>
        </div>

        {apiKeys.length === 0 ? (
          <EmptyState
            icon={Key}
            title="No API keys issued"
            description="No API access keys have been generated for the active organization context. Click 'Create API Key' to issue a credential."
            actionLabel="Issue API Key"
            onAction={() => setShowKeyModal(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-[#91A5BD] min-w-[700px]">
              <thead className="border-b border-[#1C2B40] bg-[#0A1424] font-semibold text-[#91A5BD]">
                <tr>
                  <th className="py-3 px-4">Key Name</th>
                  <th className="py-3 px-4">Prefix</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2B40]/60">
                {apiKeys.map((k) => (
                  <tr key={k.id} className="hover:bg-[#111F32] transition h-12">
                    <td className="py-3 px-4 font-bold text-[#F4F8FC]">{k.name}</td>
                    <td className="py-3 px-4">
                      <TechnicalValue value={`${k.prefix}...`} truncate={false} />
                    </td>
                    <td className="py-3 px-4 font-mono text-[#C8D5E5]">{k.role}</td>
                    <td className="py-3 px-4">
                      {k.revoked_at ? (
                        <Badge variant="block">REVOKED</Badge>
                      ) : (
                        <Badge variant="pass">ACTIVE</Badge>
                      )}
                    </td>
                    <td className="py-3 px-4 text-[#91A5BD]">{new Date(k.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-4 text-right">
                      {!k.revoked_at && (
                        <Button
                          variant="danger"
                          onClick={() => handleRevokeKey(k.id)}
                          icon={<Trash2 className="h-3.5 w-3.5" />}
                        >
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Section 2: Webhooks Subscriptions */}
      <div className="rounded-xl border border-[#1C2B40] bg-[#0D1728] p-5 md:p-6 space-y-5">
        <div className="flex items-center justify-between border-b border-[#1C2B40] pb-4">
          <div className="flex items-center gap-2.5">
            <Webhook className="h-5 w-5 text-[#6C7CFF]" />
            <h3 className="text-base font-bold text-[#F4F8FC]">Outbound Webhook Subscriptions</h3>
          </div>
          <Button
            variant="primary"
            onClick={() => setShowWebhookModal(true)}
            icon={<Plus className="h-4 w-4" />}
          >
            Add Webhook
          </Button>
        </div>

        {webhooks.length === 0 ? (
          <EmptyState
            icon={Webhook}
            title="No webhook subscriptions"
            description="No outbound webhook subscribers configured. Add an endpoint URL to receive real-time SIEM event notifications."
            actionLabel="Add Webhook"
            onAction={() => setShowWebhookModal(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-[#91A5BD] min-w-[750px]">
              <thead className="border-b border-[#1C2B40] bg-[#0A1424] font-semibold text-[#91A5BD]">
                <tr>
                  <th className="py-3 px-4">Target Endpoint URL</th>
                  <th className="py-3 px-4">Subscribed Events</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Test Delivery</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2B40]/60">
                {webhooks.map((w) => (
                  <tr key={w.id} className="hover:bg-[#111F32] transition h-12">
                    <td className="py-3 px-4 max-w-[280px]">
                      <TechnicalValue value={w.target_url} truncate={false} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1.5">
                        {w.event_types.map((e) => (
                          <Badge key={e} variant="neutral">{e}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {w.is_active ? <Badge variant="pass">ACTIVE</Badge> : <Badge variant="block">INACTIVE</Badge>}
                    </td>
                    <td className="py-3 px-4 text-[#91A5BD]">{new Date(w.created_at).toLocaleDateString()}</td>
                    <td className="py-3 px-4 text-right">
                      <Button
                        variant="secondary"
                        loading={testingWebhookId === w.id}
                        disabled={testingWebhookId === w.id}
                        onClick={() => handleTestWebhook(w.id)}
                        icon={<Send className="h-3.5 w-3.5 text-[#00B8FF]" />}
                      >
                        Test
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create API Key Modal */}
      {showKeyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#07111F]/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-[#1C2B40] bg-[#0D1728] p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-[#F4F8FC]">Create New API Access Key</h3>

            {keyModalError && (
              <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-xs text-rose-300 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 shrink-0 text-rose-400" />
                <span>{keyModalError}</span>
              </div>
            )}

            {createdSecret ? (
              <div className="space-y-4">
                <div className="rounded-xl border border-[#00D7A7]/30 bg-[#00D7A7]/10 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-[#00D7A7] uppercase tracking-wider">API Key Issued</span>
                    {copiedSuccess && (
                      <span className="text-[10px] font-bold text-[#00D7A7] bg-[#00D7A7]/20 px-2 py-0.5 rounded flex items-center gap-1">
                        <Check className="h-3 w-3" /> Copied!
                      </span>
                    )}
                  </div>
                  
                  <p className="text-xs text-[#91A5BD] leading-relaxed">
                    Copy this API key now. It will <strong className="text-[#00D7A7] underline">NOT</strong> be displayed again.
                  </p>

                  <div className="relative">
                    <pre className="p-3 rounded-lg bg-[#0A1424] border border-[#1C2B40] text-xs font-mono text-[#00D7A7] overflow-x-auto break-all select-all font-semibold">
                      {createdSecret}
                    </pre>
                  </div>

                  <Button
                    variant="primary"
                    onClick={handleCopyKey}
                    className="w-full justify-center"
                    icon={copiedSuccess ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  >
                    {copiedSuccess ? 'API Key Copied!' : 'Copy API Key'}
                  </Button>
                </div>

                <Button
                  variant="secondary"
                  onClick={() => {
                    setShowKeyModal(false);
                    setCreatedSecret(null);
                    setKeyName('');
                    setKeyModalError(null);
                  }}
                  className="w-full justify-center"
                >
                  Done
                </Button>
              </div>
            ) : (
              <form onSubmit={handleCreateApiKey} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-[#91A5BD] mb-1.5">Key Description Name</label>
                  <input
                    type="text"
                    value={keyName}
                    onChange={(e) => setKeyName(e.target.value)}
                    placeholder="e.g. CI/CD GitHub Actions Key"
                    className="w-full rounded-lg border border-[#1C2B40] bg-[#0A1424] px-3.5 py-2 text-xs text-[#F4F8FC] placeholder-[#667B94] focus:border-[#168DCC] focus:outline-none"
                    required
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-[#91A5BD] mb-1.5">Assigned System Role</label>
                  <select
                    value={keyRole}
                    onChange={(e) => setKeyRole(e.target.value)}
                    className="w-full rounded-lg border border-[#1C2B40] bg-[#0A1424] px-3.5 py-2 text-xs font-semibold text-[#F4F8FC] focus:border-[#168DCC] focus:outline-none"
                  >
                    <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                    <option value="DEVELOPER">DEVELOPER</option>
                    <option value="AUDITOR">AUDITOR</option>
                  </select>
                </div>

                <div className="flex justify-end gap-2.5 pt-2">
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => {
                      setShowKeyModal(false);
                      setKeyModalError(null);
                    }}
                    disabled={isCreatingKey}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    variant="primary"
                    loading={isCreatingKey}
                    disabled={isCreatingKey}
                  >
                    Issue API Key
                  </Button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Create Webhook Modal */}
      {showWebhookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#07111F]/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-xl border border-[#1C2B40] bg-[#0D1728] p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-[#F4F8FC]">Add Outbound Webhook Subscription</h3>

            <form onSubmit={handleCreateWebhook} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[#91A5BD] mb-1.5">Target Endpoint URL</label>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://siem.enterprise.com/hooks/pg-events"
                  className="w-full rounded-lg border border-[#1C2B40] bg-[#0A1424] px-3.5 py-2 text-xs font-mono text-[#F4F8FC] placeholder-[#667B94] focus:border-[#168DCC] focus:outline-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-2">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => setShowWebhookModal(false)}
                  disabled={isCreatingWebhook}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  loading={isCreatingWebhook}
                  disabled={isCreatingWebhook}
                >
                  Save Subscription
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

