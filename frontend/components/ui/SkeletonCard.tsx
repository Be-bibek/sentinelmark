"use client";

import React from "react";

export function SkeletonCard({ className = "" }: { className?: string }) {
  return (
    <div className={`bg-[#0c0c0c] border border-white/5 rounded-xl p-4 animate-pulse ${className}`}>
      <div className="w-8 h-8 bg-white/5 rounded-lg mb-4" />
      <div className="h-6 bg-white/5 rounded w-2/3 mb-2" />
      <div className="h-3 bg-white/5 rounded w-1/2" />
    </div>
  );
}

export function SkeletonRow() {
  return (
    <tr className="animate-pulse border-b border-white/5">
      {Array.from({ length: 6 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-3 bg-white/5 rounded w-full" />
        </td>
      ))}
    </tr>
  );
}
