"use client";

import React from "react";
import { motion } from "motion/react";
import { ShieldAlert, CheckCircle, AlertTriangle, XCircle, Clock } from "lucide-react";
import StarBorder from "./StarBorder";

interface AuditRecord {
  id: string;
  timestamp: Date;
  user: string;
  trustScore: number;
  anomalies: string[];
  decision: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
}

interface AuditLedgerProps {
  records: AuditRecord[];
  theme?: "light" | "dark";
}

export default function AuditLedger({ records, theme = "dark" }: AuditLedgerProps) {
  const isDark = theme === "dark";

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case "ALLOW":
        return {
          icon: CheckCircle,
          class: isDark 
            ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" 
            : "text-emerald-700 bg-emerald-50 border-emerald-200",
        };
      case "MFA":
        return {
          icon: ShieldAlert,
          class: isDark 
            ? "text-amber-400 bg-amber-500/10 border-amber-500/20" 
            : "text-amber-700 bg-amber-50 border-amber-200",
        };
      case "MULTI-SIG":
        return {
          icon: AlertTriangle,
          class: isDark 
            ? "text-orange-400 bg-orange-500/10 border-orange-500/20" 
            : "text-orange-700 bg-orange-50 border-orange-200",
        };
      case "BLOCK":
        return {
          icon: XCircle,
          class: isDark 
            ? "text-red-400 bg-red-500/10 border-red-500/20" 
            : "text-red-700 bg-red-50 border-red-200",
        };
      default:
        return {
          icon: CheckCircle,
          class: isDark 
            ? "text-zinc-400 bg-zinc-500/10 border-zinc-500/20" 
            : "text-zinc-600 bg-zinc-50 border-zinc-200",
        };
    }
  };

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(59, 130, 246, 0.5)" : "rgba(59, 130, 246, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.5 }}
      className={`rounded-[24px] p-6 flex flex-col h-[320px] overflow-hidden border ${
        isDark
          ? "bg-zinc-950/40 border-white/5 text-zinc-100"
          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
      }`}
    >
      <div className={`flex items-center justify-between border-b pb-4 mb-4 shrink-0 ${
        isDark ? "border-white/5" : "border-zinc-200"
      }`}>
        <h3 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
          isDark ? "text-zinc-400" : "text-zinc-500"
        }`}>
          Enterprise Audit Ledger
        </h3>
        <span className={`text-[10px] font-mono ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
          SIGNED AUDIT CHAIN
        </span>
      </div>

      <div className="flex-1 overflow-y-auto no-scrollbar">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className={`font-semibold border-b text-[10px] uppercase tracking-wider ${
              isDark ? "text-zinc-500 border-white/5" : "text-zinc-400 border-zinc-200"
            }`}>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Identity Context</th>
              <th className="py-2.5 px-3">Trust Score</th>
              <th className="py-2.5 px-3">Detected Anomaly</th>
              <th className="py-2.5 px-3 text-right">Adaptive Action</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${
            isDark ? "divide-white/[0.02] text-zinc-300" : "divide-zinc-100 text-zinc-700"
          }`}>
            {records.map((record) => {
              const badge = getDecisionBadge(record.decision);
              const BadgeIcon = badge.icon;
              return (
                <tr key={record.id} className={isDark ? "hover:bg-white/[0.01] transition-colors" : "hover:bg-zinc-50/55 transition-colors"}>
                  <td className={`py-3 px-3 font-mono text-[10px] flex items-center gap-1.5 ${
                    isDark ? "text-zinc-500" : "text-zinc-400"
                  }`}>
                    <Clock className="w-3.5 h-3.5" />
                    {record.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 })}
                  </td>
                  <td className={`py-3 px-3 font-medium ${isDark ? "text-zinc-200" : "text-zinc-800"}`}>{record.user}</td>
                  <td className="py-3 px-3 font-mono">
                    <span className={
                      record.trustScore >= 80 
                        ? isDark ? "text-emerald-400" : "text-emerald-600" 
                        : record.trustScore >= 50 
                        ? isDark ? "text-amber-400" : "text-amber-600" 
                        : isDark ? "text-red-400" : "text-red-600"
                    }>
                      {(record.trustScore / 100).toFixed(2)}
                    </span>
                  </td>
                  <td className={`py-3 px-3 font-mono text-[10px] ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                    {record.anomalies.length > 0 ? record.anomalies.join(", ") : "NONE"}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[9px] uppercase font-bold font-mono tracking-wider ml-auto" style={{ width: "fit-content" }}>
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border ${badge.class}`}>
                        <BadgeIcon className="w-3 h-3" />
                        {record.decision}
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
            {records.length === 0 && (
              <tr>
                <td colSpan={5} className={`py-12 text-center italic ${
                  isDark ? "text-zinc-500" : "text-zinc-400"
                }`}>
                  Awaiting audit event stream pipeline sync...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </StarBorder>
  );
}
