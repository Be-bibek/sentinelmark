"use client";

import { useState } from "react";
import { PolicyStackedBar } from "@/components/charts/PolicyStackedBar";
import { Search, Download, Filter, ChevronLeft, ChevronRight, FileText } from "lucide-react";

export default function AuditExplorer() {
  const [search, setSearch] = useState("");

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <header className="mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            Audit Explorer
          </h1>
          <p className="text-muted-foreground mt-1">Immutable ledger of all trust evaluations and policy enforcement</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 flex items-center gap-2 bg-card border text-sm font-medium rounded-lg hover:bg-muted transition-colors">
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button className="px-4 py-2 flex items-center gap-2 bg-primary text-primary-foreground text-sm font-medium rounded-lg hover:opacity-90 transition-opacity">
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>
      </header>

      {/* Analytics Row */}
      <div className="p-6 rounded-xl border bg-card shadow-sm">
        <h2 className="text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
          <FileText className="w-4 h-4 text-blue-500" />
          Enforcement Timeline (7 Days)
        </h2>
        <PolicyStackedBar />
      </div>

      {/* Ledger Table */}
      <div className="rounded-xl border bg-card shadow-sm overflow-hidden flex flex-col">
        <div className="p-4 border-b flex items-center justify-between">
          <div className="relative w-full max-w-sm">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <input 
              type="text" 
              placeholder="Search by User ID, Action, or IP..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-background border rounded-md text-sm outline-none focus:border-primary"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="p-4 font-semibold text-muted-foreground whitespace-nowrap">Timestamp</th>
                <th className="p-4 font-semibold text-muted-foreground">User ID</th>
                <th className="p-4 font-semibold text-muted-foreground">Event</th>
                <th className="p-4 font-semibold text-muted-foreground">Trust / Risk</th>
                <th className="p-4 font-semibold text-muted-foreground">Decision</th>
                <th className="p-4 font-semibold text-muted-foreground">Anomalies</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {/* Dummy data for layout, will connect to useQuery(SentinelAPI.getAuditLog) */}
              {[1, 2, 3, 4, 5, 6, 7, 8].map((i) => (
                <tr key={i} className="hover:bg-muted/30 transition-colors">
                  <td className="p-4 font-mono text-xs text-muted-foreground">2026-06-28 14:0{i}:22</td>
                  <td className="p-4 font-mono text-xs text-primary font-bold">user-123</td>
                  <td className="p-4">LOGIN</td>
                  <td className="p-4 font-mono text-xs">
                    <span className="text-emerald-500">0.92</span> / <span className="text-red-500">0.08</span>
                  </td>
                  <td className="p-4">
                    <span className="px-2 py-0.5 text-[10px] font-bold uppercase rounded border bg-emerald-500/10 text-emerald-500 border-emerald-500/20">
                      ALLOW
                    </span>
                  </td>
                  <td className="p-4 text-xs text-muted-foreground max-w-xs truncate">
                    None
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        <div className="p-4 border-t flex items-center justify-between text-sm text-muted-foreground">
          <span>Showing 1 to 8 of 1,248 entries</span>
          <div className="flex gap-1">
            <button className="p-1 border rounded hover:bg-muted disabled:opacity-50" disabled><ChevronLeft className="w-4 h-4" /></button>
            <button className="px-3 py-1 border rounded bg-primary text-primary-foreground font-bold">1</button>
            <button className="px-3 py-1 border rounded hover:bg-muted">2</button>
            <button className="px-3 py-1 border rounded hover:bg-muted">3</button>
            <button className="p-1 border rounded hover:bg-muted"><ChevronRight className="w-4 h-4" /></button>
          </div>
        </div>
      </div>
    </div>
  );
}
