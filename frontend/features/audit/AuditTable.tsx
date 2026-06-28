"use client";

import React, { useState } from "react";
import { Search, Download, Copy, Eye, Filter, ArrowUpDown } from "lucide-react";
import { format } from "date-fns";

export interface AuditRecord {
  id: string;
  timestamp: Date;
  user: string;
  trustScore: number;
  decision: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
  anomalies: string[];
}

export default function AuditTable({ records }: { records: AuditRecord[] }) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterDecision, setFilterDecision] = useState<string>("ALL");
  const [page, setPage] = useState(1);
  const rowsPerPage = 10;

  const filtered = records.filter(r => {
    const matchesSearch = r.user.toLowerCase().includes(searchTerm.toLowerCase()) || r.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesDecision = filterDecision === "ALL" || r.decision === filterDecision;
    return matchesSearch && matchesDecision;
  });

  const paginated = filtered.slice((page - 1) * rowsPerPage, page * rowsPerPage);
  const totalPages = Math.ceil(filtered.length / rowsPerPage);

  const exportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filtered, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", "audit_export.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const exportCSV = () => {
    const header = "ID,Timestamp,User,Trust Score,Decision,Anomalies\n";
    const csv = filtered.map(r => `${r.id},${r.timestamp.toISOString()},${r.user},${r.trustScore},${r.decision},"${r.anomalies.join('; ')}"`).join("\n");
    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(header + csv);
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href",     dataStr);
    downloadAnchorNode.setAttribute("download", "audit_export.csv");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  const copyEvent = (r: AuditRecord) => {
    navigator.clipboard.writeText(JSON.stringify(r, null, 2));
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 w-1/2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input 
              type="text"
              placeholder="Search by User or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>
          <div className="flex items-center gap-2 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm">
            <Filter className="w-4 h-4 text-zinc-500" />
            <select 
              value={filterDecision} 
              onChange={e => setFilterDecision(e.target.value)}
              className="bg-transparent text-white outline-none w-24"
            >
              <option value="ALL">All Decisions</option>
              <option value="ALLOW">Allow</option>
              <option value="MFA">MFA</option>
              <option value="BLOCK">Block</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={exportCSV} className="flex items-center gap-2 px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-sm text-white transition-colors">
            <Download className="w-4 h-4" /> CSV
          </button>
          <button onClick={exportJSON} className="flex items-center gap-2 px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-sm text-white transition-colors">
            <Download className="w-4 h-4" /> JSON
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-x-auto border border-white/10 rounded-lg bg-black/20">
        <table className="w-full text-left text-sm whitespace-nowrap">
          <thead className="bg-white/5 border-b border-white/10 text-xs uppercase tracking-wider text-zinc-400">
            <tr>
              <th className="px-4 py-3 font-medium flex items-center gap-1 cursor-pointer hover:text-white">Timestamp <ArrowUpDown className="w-3 h-3"/></th>
              <th className="px-4 py-3 font-medium">Event ID</th>
              <th className="px-4 py-3 font-medium">User / Entity</th>
              <th className="px-4 py-3 font-medium text-center">Score</th>
              <th className="px-4 py-3 font-medium">Policy Decision</th>
              <th className="px-4 py-3 font-medium">Flagged Anomalies</th>
              <th className="px-4 py-3 font-medium text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 text-zinc-300">
            {paginated.map((record) => (
              <tr key={record.id} className="hover:bg-white/5 transition-colors group">
                <td className="px-4 py-3 font-mono text-xs">{format(record.timestamp, "MMM dd, HH:mm:ss")}</td>
                <td className="px-4 py-3 font-mono text-xs text-zinc-500">{record.id.substring(0, 8)}...</td>
                <td className="px-4 py-3 font-medium text-white">{record.user}</td>
                <td className="px-4 py-3 text-center">
                  <span className={`inline-block px-2 py-0.5 rounded text-xs font-bold ${
                    record.trustScore >= 80 ? 'bg-emerald-500/20 text-emerald-400' :
                    record.trustScore >= 50 ? 'bg-amber-500/20 text-amber-400' : 'bg-red-500/20 text-red-400'
                  }`}>
                    {record.trustScore}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span className={`inline-flex items-center gap-1.5 ${
                    record.decision === 'ALLOW' ? 'text-emerald-400' :
                    record.decision === 'BLOCK' ? 'text-red-400' : 'text-amber-400'
                  } font-bold text-xs`}>
                    {record.decision}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 overflow-hidden w-48">
                    {record.anomalies.map((a, i) => (
                      <span key={i} className="bg-red-500/10 text-red-300 border border-red-500/20 px-1.5 py-0.5 rounded text-[10px] font-mono truncate max-w-[100px]">
                        {a}
                      </span>
                    ))}
                    {record.anomalies.length === 0 && <span className="text-zinc-600 text-xs font-mono">-</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => copyEvent(record)} className="p-1.5 text-zinc-400 hover:text-white hover:bg-white/10 rounded transition-colors" title="Copy JSON">
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                    <button className="p-1.5 text-zinc-400 hover:text-white hover:bg-white/10 rounded transition-colors" title="View Details">
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {paginated.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-zinc-500 text-sm">
                  No audit records found matching the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-zinc-400">
        <div>
          Showing {(page - 1) * rowsPerPage + 1} to {Math.min(page * rowsPerPage, filtered.length)} of {filtered.length} records
        </div>
        <div className="flex gap-1">
          <button 
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1 bg-white/5 border border-white/10 rounded hover:bg-white/10 disabled:opacity-50 disabled:pointer-events-none"
          >
            Prev
          </button>
          <div className="px-3 py-1 text-white">{page} / {Math.max(1, totalPages)}</div>
          <button 
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages || totalPages === 0}
            className="px-3 py-1 bg-white/5 border border-white/10 rounded hover:bg-white/10 disabled:opacity-50 disabled:pointer-events-none"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
