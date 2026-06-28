"use client";

import React from "react";
import ApiExplorer from "@/features/api-explorer/ApiExplorer";

export default function ApiPage() {
  return (
    <div className="h-full py-6 flex flex-col max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">REST API Explorer</h1>
          <p className="text-zinc-400">Interact with the TrustOS engine endpoints directly.</p>
        </div>
      </div>
      
      <ApiExplorer />
    </div>
  );
}
