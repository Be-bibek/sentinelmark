"use client";

import React from "react";
import BehaviorProfile from "@/features/behavior/BehaviorProfile";

export default function BehaviorPage() {
  return (
    <div className="h-full py-6 flex flex-col max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">Behavioral Identity Profile</h1>
          <p className="text-zinc-400">Continuous biometric and contextual baselining for the active entity.</p>
        </div>
      </div>
      
      <BehaviorProfile />
    </div>
  );
}