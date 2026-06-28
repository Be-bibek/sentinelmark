"use client";

import React from "react";
import ActiveSessions from "@/features/sessions/ActiveSessions";

export default function SessionsPage() {
  return (
    <div className="h-full py-6 flex flex-col max-w-6xl mx-auto">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold text-white mb-2">Active Session Management</h1>
          <p className="text-zinc-400">Monitor and revoke currently authenticated sessions in real-time.</p>
        </div>
      </div>
      
      <ActiveSessions />
    </div>
  );
}