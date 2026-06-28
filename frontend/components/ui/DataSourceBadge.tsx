"use client";

import React from "react";

export type DataSource = "LIVE" | "CACHED" | "MOCK" | "OFFLINE";

const CONFIG: Record<DataSource, { dot: string; text: string; bg: string }> = {
  LIVE:    { dot: "bg-emerald-400 animate-pulse", text: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20" },
  CACHED:  { dot: "bg-amber-400",                 text: "text-amber-400",   bg: "bg-amber-500/10 border-amber-500/20" },
  MOCK:    { dot: "bg-zinc-500",                   text: "text-zinc-400",   bg: "bg-zinc-500/10 border-zinc-500/20" },
  OFFLINE: { dot: "bg-red-400 animate-pulse",      text: "text-red-400",    bg: "bg-red-500/10 border-red-500/20" },
};

export function DataSourceBadge({ source }: { source: DataSource }) {
  const c = CONFIG[source];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-bold tracking-wider ${c.bg} ${c.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {source}
    </span>
  );
}
