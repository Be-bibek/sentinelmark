"use client";

import React from "react";
import { WifiOff, RefreshCw } from "lucide-react";

export function OfflineBanner({ onRetry }: { onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3 bg-red-500/10 border border-red-500/20 rounded-xl text-sm">
      <div className="flex items-center gap-3">
        <WifiOff className="w-4 h-4 text-red-400 shrink-0" />
        <span className="text-red-200">
          <span className="font-bold text-red-400">Backend Offline</span> — The SentinelMark API Gateway is unreachable. Displaying last cached data.
        </span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 text-xs text-red-400 hover:text-red-300 border border-red-500/30 px-3 py-1.5 rounded-lg hover:bg-red-500/10 transition-colors shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Retry
        </button>
      )}
    </div>
  );
}
