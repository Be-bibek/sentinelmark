"use client";

import React, { useState, useEffect } from "react";
import { Key, Plus, Copy, Trash2, RefreshCw, AlertCircle } from "lucide-react";
import { useTheme } from "next-themes";

interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  is_active: boolean;
  rate_limit_rpm: number;
  last_used_at: string | null;
  created_at: string;
  usage_count: number;
}

export default function ApiKeysPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [newKeyName, setNewKeyName] = useState("");
  const [rawKeyModal, setRawKeyModal] = useState<{name: string, raw_key: string} | null>(null);

  useEffect(() => {
    // In a real app, this would fetch from /api/v1/api-keys
    // For UI demonstration, we provide dummy data matching the DB schema.
    setTimeout(() => {
      setKeys([
        {
          id: "1",
          name: "Mobile App Production",
          key_prefix: "sm_live_aB3x9...",
          is_active: true,
          rate_limit_rpm: 1000,
          last_used_at: "2026-06-29T18:30:00Z",
          created_at: "2026-01-15T10:00:00Z",
          usage_count: 3442
        },
        {
          id: "2",
          name: "Backend Service Staging",
          key_prefix: "sm_test_p0oL2...",
          is_active: true,
          rate_limit_rpm: 500,
          last_used_at: "2026-06-28T09:15:00Z",
          created_at: "2026-03-22T14:20:00Z",
          usage_count: 856
        }
      ]);
      setLoading(false);
    }, 500);
  }, []);

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    
    // Simulate creating a key
    const rawKey = "sm_live_" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const newKey: ApiKey = {
      id: Date.now().toString(),
      name: newKeyName,
      key_prefix: rawKey.substring(0, 14) + "...",
      is_active: true,
      rate_limit_rpm: 1000,
      last_used_at: null,
      created_at: new Date().toISOString(),
      usage_count: 0
    };
    
    setKeys([newKey, ...keys]);
    setNewKeyName("");
    setRawKeyModal({ name: newKey.name, raw_key: rawKey });
  };

  const handleRevoke = (id: string) => {
    setKeys(keys.map(k => k.id === id ? { ...k, is_active: false } : k));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  if (loading) {
    return <div className="p-8 text-center text-zinc-500">Loading API Keys...</div>;
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className={`text-2xl font-bold tracking-tight ${isDark ? "text-white" : "text-zinc-900"}`}>API Keys</h1>
          <p className={`text-sm mt-1 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
            Manage keys used to authenticate SDKs and API requests.
          </p>
        </div>
      </div>

      {rawKeyModal && (
        <div className={`p-6 rounded-xl border mb-6 ${isDark ? "bg-amber-500/10 border-amber-500/20" : "bg-amber-50 border-amber-200"}`}>
          <div className="flex gap-3">
            <AlertCircle className="w-5 h-5 text-amber-500 flex-shrink-0" />
            <div>
              <h3 className={`text-sm font-semibold ${isDark ? "text-amber-400" : "text-amber-800"}`}>
                Save your API key
              </h3>
              <p className={`text-sm mt-1 mb-4 ${isDark ? "text-amber-500/80" : "text-amber-700"}`}>
                Please copy this key now. For your security, it will never be shown again.
              </p>
              <div className="flex items-center gap-2">
                <code className={`px-4 py-2 rounded-lg font-mono text-sm border ${isDark ? "bg-black/50 border-white/10 text-white" : "bg-white border-zinc-200 text-zinc-900"}`}>
                  {rawKeyModal.raw_key}
                </code>
                <button 
                  onClick={() => copyToClipboard(rawKeyModal.raw_key)}
                  className="p-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
              <button 
                onClick={() => setRawKeyModal(null)}
                className={`mt-4 text-sm font-medium ${isDark ? "text-amber-400 hover:text-amber-300" : "text-amber-800 hover:text-amber-600"}`}
              >
                I have saved it securely
              </button>
            </div>
          </div>
        </div>
      )}

      <div className={`ui-card p-6 ${isDark ? "bg-black/20" : "bg-white"}`}>
        <form onSubmit={handleCreate} className="flex gap-4 items-end mb-8">
          <div className="flex-1 max-w-sm">
            <label className={`block text-xs font-medium mb-2 ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
              New Key Name
            </label>
            <input 
              type="text" 
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="e.g. Mobile App Production"
              className="ui-input w-full"
            />
          </div>
          <button type="submit" disabled={!newKeyName.trim()} className="h-10 px-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 text-sm font-medium">
            <Plus className="w-4 h-4" />
            Generate Key
          </button>
        </form>

        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className={`text-xs uppercase bg-transparent border-b ${isDark ? "text-zinc-500 border-white/10" : "text-zinc-500 border-zinc-200"}`}>
              <tr>
                <th className="px-4 py-3 font-medium">Name & Prefix</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Usage</th>
                <th className="px-4 py-3 font-medium">Last Used</th>
                <th className="px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-white/5">
              {keys.map((key) => (
                <tr key={key.id} className="bg-transparent hover:bg-zinc-50 dark:hover:bg-white/5 transition-colors">
                  <td className="px-4 py-4">
                    <div className={`font-medium ${isDark ? "text-white" : "text-zinc-900"}`}>{key.name}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <code className={`text-xs px-1.5 py-0.5 rounded ${isDark ? "bg-white/5 text-zinc-400" : "bg-zinc-100 text-zinc-600"}`}>
                        {key.key_prefix}
                      </code>
                    </div>
                  </td>
                  <td className="px-4 py-4">
                    {key.is_active ? (
                      <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                        Active
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-500 border border-red-500/20">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                        Revoked
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-4">
                    <div className={`font-medium ${isDark ? "text-zinc-300" : "text-zinc-700"}`}>
                      {key.usage_count.toLocaleString()} <span className="text-xs font-normal text-zinc-500">requests</span>
                    </div>
                    <div className="text-xs text-zinc-500 mt-1">Limit: {key.rate_limit_rpm} rpm</div>
                  </td>
                  <td className="px-4 py-4">
                    {key.last_used_at ? (
                      <div className={`text-xs ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                        {new Date(key.last_used_at).toLocaleDateString()}
                      </div>
                    ) : (
                      <span className="text-xs text-zinc-500 italic">Never</span>
                    )}
                  </td>
                  <td className="px-4 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                      <button 
                        className={`p-1.5 rounded transition-colors ${isDark ? "text-zinc-400 hover:bg-white/10" : "text-zinc-500 hover:bg-zinc-100"}`}
                        title="Rotate Key"
                      >
                        <RefreshCw className="w-4 h-4" />
                      </button>
                      <button 
                        onClick={() => handleRevoke(key.id)}
                        disabled={!key.is_active}
                        className={`p-1.5 rounded transition-colors ${!key.is_active ? "opacity-30 cursor-not-allowed" : "text-red-400 hover:bg-red-400/10"}`}
                        title="Revoke Key"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
