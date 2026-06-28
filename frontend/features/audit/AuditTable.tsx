"use client";

import React, { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SentinelAPI } from "@/lib/api";
import { useAuditStore } from "@/stores/audit-store";
import { DataSourceBadge } from "@/components/ui/DataSourceBadge";
import { OfflineBanner } from "@/components/ui/OfflineBanner";
import { Search, Download, Copy, Eye, Filter, ArrowUpDown, RefreshCw } from "lucide-react";
import { format } from "date-fns";
import { SkeletonRow } from "@/components/ui/SkeletonCard";

const USER_ID = "dev.ops@enterprise.com";

export default function AuditTable() {
  const { records, addRecord, setDataSource, dataSource } = useAuditStore();
  const [searchTerm, setSearchTerm]       = useState("");
  const [filterDecision, setFilterDecision] = useState<string>("ALL");
  const [page, setPage]                   = useState(1);
  const rowsPerPage = 10;

  // Fetch from backend on mount (and when manually refreshed)
  const { isError, isLoading, refetch } = useQuery({
    queryKey: ["audit", USER_ID],
    queryFn: async () => {
      const data = await SentinelAPI.getAuditLogs(USER_ID, 1, 100);
      // Map AuditRow[] → AuditRecord[] and push into store
      data.entries.forEach((e) => {
        addRecord({
          user:       e.user_id,
          trustScore: Math.round(e.trust_score * 100),
          anomalies:  e.reasons ?? [],
          decision:   e.decision as any,
          riskScore:  e.risk_score,
          auditId:    e.id,
          explanation: e.explanation,
          source:     "live",
        });
      });
      setDataSource("LIVE");
      return data;
    },
    retry: 1,
    staleTime: 30000,
  });

  useEffect(() => {
    if (isError) setDataSource("OFFLINE");
  }, [isError, setDataSource]);

  const filtered = records.filter((r) => {
    const matchSearch   = r.user.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          r.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          (r.auditId ?? "").toLowerCase().includes(searchTerm.toLowerCase());
    const matchDecision = filterDecision === "ALL" || r.decision === filterDecision;
    return matchSearch && matchDecision;
  });

  const paginated  = filtered.slice((page - 1) * rowsPerPage, page * rowsPerPage);
  const totalPages = Math.ceil(filtered.length / rowsPerPage);

  const exportJSON = () => {
    const a = document.createElement("a");
    a.href = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filtered, null, 2));
    a.download = "audit_export.json";
    a.click();
  };
  const exportCSV = () => {
    const header = "ID,Timestamp,User,Trust Score,Decision,Anomalies\n";
    const csv = filtered.map((r) =>
      `${r.auditId ?? r.id},${r.timestamp.toISOString()},${r.user},${r.trustScore},${r.decision},"${r.anomalies.join("; ")}"`
    ).join("\n");
    const a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(header + csv);
    a.download = "audit_export.csv";
    a.click();
  };
  const copyEvent = (r: typeof records[0]) =>
    navigator.clipboard.writeText(JSON.stringify(r, null, 2));

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <DataSourceBadge source={dataSource} />
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              placeholder="Search user, ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="ui-input pl-9 w-56"
            />
          </div>
          <div className="flex items-center gap-2 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm">
            <Filter className="w-4 h-4 text-zinc-500" />
            <select
              value={filterDecision}
              onChange={(e) => setFilterDecision(e.target.value)}
              className="bg-transparent text-white outline-none"
            >
              <option value="ALL">All Decisions</option>
              <option value="ALLOW">Allow</option>
              <option value="MFA">MFA</option>
              <option value="BLOCK">Block</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="ui-button">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={exportCSV}  className="ui-button">
            <Download className="w-4 h-4" /> CSV
          </button>
          <button onClick={exportJSON} className="ui-button">
            <Download className="w-4 h-4" /> JSON
          </button>
        </div>
      </div>

      {isError && <OfflineBanner onRetry={() => refetch()} />}

      {/* Table */}
      <div className="flex-1 overflow-x-auto border border-white/10 rounded-lg bg-black/20">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="bg-white/5 border-b border-white/10 text-xs uppercase tracking-wider text-zinc-400">
            <tr>
              <th className="px-4 py-3 font-medium">Timestamp</th>
              <th className="px-4 py-3 font-medium">Audit ID</th>
              <th className="px-4 py-3 font-medium">User</th>
              <th className="px-4 py-3 font-medium text-center">Score</th>
              <th className="px-4 py-3 font-medium">Decision</th>
              <th className="px-4 py-3 font-medium">Anomalies</th>
              <th className="px-4 py-3 font-medium text-center">Source</th>
              <th className="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-zinc-300">
            {isLoading && records.length === 0
              ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
              : paginated.map((record) => (
                <tr key={record.id} className="hover:bg-white/[0.03] transition-colors group">
                  <td className="px-4 py-3 font-mono text-xs">{format(record.timestamp, "MMM dd, HH:mm:ss")}</td>
                  <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                    {(record.auditId ?? record.id).substring(0, 12)}…
                  </td>
                  <td className="px-4 py-3 font-medium text-white">{record.user}</td>
                  <td className="px-4 py-3 text-center">
                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${
                      record.trustScore >= 80 ? "bg-emerald-500/20 text-emerald-400" :
                      record.trustScore >= 50 ? "bg-amber-500/20 text-amber-400" :
                                                "bg-red-500/20 text-red-400"
                    }`}>
                      {record.trustScore}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-bold text-xs ${
                      record.decision === "ALLOW"  ? "text-emerald-400" :
                      record.decision === "BLOCK"  ? "text-red-400" : "text-amber-400"
                    }`}>
                      {record.decision}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1 flex-wrap max-w-[180px]">
                      {record.anomalies.slice(0, 2).map((a, i) => (
                        <span key={i} className="bg-red-500/10 text-red-300 border border-red-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono truncate max-w-[80px]">
                          {a}
                        </span>
                      ))}
                      {record.anomalies.length === 0 && <span className="text-zinc-600 text-xs font-mono">—</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <DataSourceBadge source={record.source === "live" ? "LIVE" : "MOCK"} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => copyEvent(record)} className="p-1.5 text-zinc-400 hover:text-white hover:bg-white/10 rounded" title="Copy JSON">
                        <Copy className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            }
            {!isLoading && paginated.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-zinc-500 text-sm">
                  No audit records found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-zinc-400">
        <div>
          Showing {Math.min((page - 1) * rowsPerPage + 1, filtered.length)}–{Math.min(page * rowsPerPage, filtered.length)} of {filtered.length} records
        </div>
        <div className="flex gap-1">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="ui-button px-3 py-1">
            Prev
          </button>
          <div className="px-3 py-1 text-white">{page} / {Math.max(1, totalPages)}</div>
          <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
            className="ui-button px-3 py-1">
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
