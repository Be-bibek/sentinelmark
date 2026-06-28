"use client";

import React from "react";
import SdkPlayground from "@/features/sdk/SdkPlayground";

export default function SdkPage() {
  return (
    <div className="h-full py-6 flex flex-col max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">SDK Integrations</h1>
          <p className="text-zinc-400">Official client libraries for integrating Continuous Trust into your application.</p>
        </div>
      </div>
      
      <SdkPlayground />
    </div>
  );
}
