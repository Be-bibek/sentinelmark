"use client";

import React from "react";
import AuditTable from "@/features/audit/AuditTable";
import { useAuditStore } from "@/stores/audit-store";

export default function AuditPage() {
  const { records } = useAuditStore();
  
  return (
    <div className="h-full py-6 flex flex-col">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">Audit Ledger</h1>
          <p className="text-zinc-400">Immutable, paginated history of all policy decisions and trust evaluations.</p>
        </div>
      </div>
      
      <div className="flex-1 bg-[#0c0c0c] border border-white/10 rounded-2xl p-5 shadow-lg overflow-hidden flex flex-col">
        <AuditTable records={records as any} />
      </div>
    </div>
  );
}