"use client";

import React from "react";
import RiskContribution from "@/features/explainability/RiskContribution";

export default function ExplainabilityPage() {
  return (
    <div className="h-full max-w-4xl mx-auto py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white mb-2">Deterministic Engine Trace</h1>
        <p className="text-zinc-400">Deep-dive into the exact mathematical contributions leading to the final policy decision.</p>
      </div>
      
      <div className="h-[600px]">
        <RiskContribution />
      </div>
    </div>
  );
}