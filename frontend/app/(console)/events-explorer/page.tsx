"use client";

import React, { useState, useEffect } from "react";
import { Search, Filter, ShieldAlert, ShieldCheck, Activity, Terminal, Shield } from "lucide-react";
import { useTheme } from "next-themes";

interface TrustEvent {
  id: string;
  product_slug: string;
  event_type: string;
  severity: string;
  risk_score: number;
  trust_score: number;
  action_taken: string;
  timestamp: string;
}

export default function EventExplorerPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [events, setEvents] = useState<TrustEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterProduct, setFilterProduct] = useState("all");

  useEffect(() => {
    // Simulated fetch from /api/v1/events-explorer
    setTimeout(() => {
      setEvents([
        {
          id: "evt_1",
          product_slug: "dicom-trace",
          event_type: "Image Verified",
          severity: "low",
          risk_score: 2,
          trust_score: 98,
          action_taken: "ALLOW",
          timestamp: "2026-06-30T09:12:00Z"
        },
        {
          id: "evt_2",
          product_slug: "prooftrace",
          event_type: "Packet Tampered",
          severity: "critical",
          risk_score: 89,
          trust_score: 22,
          action_taken: "BLOCK",
          timestamp: "2026-06-30T09:13:00Z"
        },
        {
          id: "evt_3",
          product_slug: "stellarflow",
          event_type: "Treasury Transfer",
          severity: "medium",
          risk_score: 45,
          trust_score: 61,
          action_taken: "MFA",
          timestamp: "2026-06-30T09:14:00Z"
        }
      ]);
      setLoading(false);
    }, 600);
  }, []);

  const getActionColor = (action: string) => {
    switch(action) {
      case "ALLOW": return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
      case "BLOCK": return "text-red-500 bg-red-500/10 border-red-500/20";
      case "MFA": return "text-amber-500 bg-amber-500/10 border-amber-500/20";
      default: return "text-zinc-500 bg-zinc-500/10 border-zinc-500/20";
    }
  };

  const filteredEvents = events.filter(e => {
    if (filterProduct !== "all" && e.product_slug !== filterProduct) return false;
    if (searchQuery && !e.event_type.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6 h-full flex flex-col">
      <div className="flex justify-between items-center">
        <div>
          <h1 className={`text-2xl font-bold tracking-tight ${isDark ? "text-white" : "text-zinc-900"}`}>Event Explorer</h1>
          <p className={`text-sm mt-1 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
            Unified log search and analytics across all SentinelMark products.
          </p>
        </div>
      </div>

      <div className={`ui-card p-4 flex gap-4 ${isDark ? "bg-black/20" : "bg-white"}`}>
        <div className="relative flex-1">
          <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${isDark ? "text-zinc-500" : "text-zinc-400"}`} />
          <input 
            type="text" 
            placeholder="Search events (e.g., 'Packet Tampered')..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="ui-input w-full pl-10 font-mono text-sm"
          />
        </div>
        <select 
          value={filterProduct}
          onChange={(e) => setFilterProduct(e.target.value)}
          className="ui-input w-48 text-sm"
        >
          <option value="all">All Products</option>
          <option value="dicom-trace">DICOM-Trace</option>
          <option value="prooftrace">ProofTrace-5G</option>
          <option value="stellarflow">StellarFlow</option>
        </select>
        <button className={`px-4 rounded-lg border flex items-center gap-2 text-sm font-medium transition-colors ${isDark ? "border-white/10 text-zinc-300 hover:bg-white/5" : "border-zinc-200 text-zinc-700 hover:bg-zinc-50"}`}>
          <Filter className="w-4 h-4" />
          Advanced
        </button>
      </div>

      <div className={`ui-card flex-1 overflow-hidden flex flex-col ${isDark ? "bg-black/20" : "bg-white"}`}>
        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <Activity className="w-6 h-6 text-blue-500 animate-pulse" />
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            <table className="w-full text-sm text-left">
              <thead className={`text-xs uppercase sticky top-0 backdrop-blur-md z-10 ${isDark ? "bg-black/80 text-zinc-500 border-b border-white/10" : "bg-white/80 text-zinc-500 border-b border-zinc-200"}`}>
                <tr>
                  <th className="px-4 py-3 font-medium w-32">Time</th>
                  <th className="px-4 py-3 font-medium w-40">Product</th>
                  <th className="px-4 py-3 font-medium">Event</th>
                  <th className="px-4 py-3 font-medium w-24">Trust</th>
                  <th className="px-4 py-3 font-medium w-24">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-200 dark:divide-white/5 font-mono text-xs">
                {filteredEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-zinc-50 dark:hover:bg-white/5 transition-colors cursor-pointer">
                    <td className={`px-4 py-3 whitespace-nowrap ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
                      {new Date(evt.timestamp).toLocaleTimeString([], { hour12: false })}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-1 rounded border ${isDark ? "bg-white/5 border-white/10 text-zinc-300" : "bg-zinc-100 border-zinc-200 text-zinc-700"}`}>
                        {evt.product_slug}
                      </span>
                    </td>
                    <td className={`px-4 py-3 font-medium ${isDark ? "text-zinc-200" : "text-zinc-900"}`}>
                      {evt.event_type}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {evt.trust_score >= 80 ? (
                          <ShieldCheck className="w-4 h-4 text-emerald-500" />
                        ) : evt.trust_score <= 30 ? (
                          <ShieldAlert className="w-4 h-4 text-red-500" />
                        ) : (
                          <Shield className="w-4 h-4 text-amber-500" />
                        )}
                        <span className={evt.trust_score >= 80 ? "text-emerald-500" : evt.trust_score <= 30 ? "text-red-500" : "text-amber-500"}>
                          {evt.trust_score}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-1 rounded text-[10px] font-bold border ${getActionColor(evt.action_taken)}`}>
                        {evt.action_taken}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredEvents.length === 0 && (
              <div className="flex flex-col items-center justify-center p-12 text-center">
                <Terminal className={`w-8 h-8 mb-4 ${isDark ? "text-zinc-700" : "text-zinc-300"}`} />
                <p className={`text-sm ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>No events found matching your query.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
