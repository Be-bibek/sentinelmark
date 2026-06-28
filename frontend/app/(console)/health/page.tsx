"use client";

import React from "react";
import SystemHealth from "@/features/health/SystemHealth";
import { ErrorBoundary } from "@/components/ui/ErrorBoundary";

export default function HealthPage() {
  return (
    <div className="py-6 flex flex-col max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">System Health</h1>
        <p className="text-zinc-400">Real-time operational status of the SentinelMark TrustOS platform.</p>
      </div>

      <ErrorBoundary fallbackLabel="Health Module Error">
        <SystemHealth />
      </ErrorBoundary>
    </div>
  );
}
