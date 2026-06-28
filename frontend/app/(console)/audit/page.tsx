"use client";

import React from "react";
import AuditTable from "@/features/audit/AuditTable";
import { ErrorBoundary } from "@/components/ui/ErrorBoundary";
import { Card } from "@/components/ui/Card";

export default function AuditPage() {
  return (
    <div className="h-full py-6 flex flex-col">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold dark:text-white text-zinc-900 mb-2">Audit Ledger</h1>
          <p className="dark:text-zinc-400 text-zinc-500">Immutable history of all policy decisions. Live-synced from PostgreSQL via the Axum backend.</p>
        </div>
      </div>

      <Card className="flex-1 p-5 overflow-hidden flex flex-col">
        <ErrorBoundary fallbackLabel="Audit Table Error">
          <AuditTable />
        </ErrorBoundary>
      </Card>
    </div>
  );
}