"use client";

import React, { useState } from "react";
import { Laptop, Smartphone, Globe, Shield, TerminalSquare } from "lucide-react";

export default function ActiveSessions() {
  const [sessions, setSessions] = useState([
    {
      id: "sess_1a2b3c",
      browser: "Chrome 120.0",
      device: "MacBook Pro M2",
      deviceType: "desktop",
      country: "US (San Francisco)",
      ip: "104.28.19.1",
      trust: 98,
      policy: "ALLOW",
      live: true
    },
    {
      id: "sess_4d5e6f",
      browser: "Safari 17.0",
      device: "iPhone 14 Pro",
      deviceType: "mobile",
      country: "US (San Francisco)",
      ip: "104.28.19.1",
      trust: 94,
      policy: "ALLOW",
      live: true
    },
    {
      id: "sess_7g8h9i",
      browser: "Firefox 119.0",
      device: "Unknown Windows",
      deviceType: "desktop",
      country: "JP (Tokyo)",
      ip: "133.32.4.1",
      trust: 12,
      policy: "BLOCK",
      live: false
    }
  ]);

  const terminateSession = (id: string) => {
    setSessions(prev => prev.map(s => s.id === id ? { ...s, live: false, policy: "BLOCK", trust: 0 } : s));
  };

  return (
    <div className="space-y-4">
      {sessions.map((session) => (
        <div key={session.id} className="ui-card p-5 flex items-center justify-between group dark:hover:border-white/20 hover:border-zinc-300 transition-colors">
          <div className="flex items-center gap-5">
            <div className="w-12 h-12 dark:bg-white/5 bg-zinc-100 rounded-full flex items-center justify-center border dark:border-white/10 border-zinc-200">
              {session.deviceType === 'desktop' ? <Laptop className="w-6 h-6 dark:text-zinc-400 text-zinc-500" /> : <Smartphone className="w-6 h-6 dark:text-zinc-400 text-zinc-500" />}
            </div>
            
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-bold dark:text-white text-zinc-900 text-sm">{session.device}</span>
                {session.live && <span className="flex items-center gap-1 text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded font-bold uppercase"><span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse"></span> Live</span>}
                {!session.live && <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded font-bold uppercase">Terminated</span>}
              </div>
              <div className="flex items-center gap-3 text-xs text-zinc-500 font-mono">
                <span className="flex items-center gap-1"><Globe className="w-3 h-3"/> {session.country}</span>
                <span className="w-1 h-1 bg-zinc-700 rounded-full"></span>
                <span>{session.ip}</span>
                <span className="w-1 h-1 bg-zinc-700 rounded-full"></span>
                <span>{session.browser}</span>
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-8">
            <div className="text-center">
              <span className="block text-[10px] uppercase text-zinc-500 mb-1">Trust</span>
              <span className={`text-xl font-bold ${
                session.trust >= 80 ? 'text-emerald-400' :
                session.trust >= 50 ? 'text-amber-400' : 'text-red-400'
              }`}>{session.trust}</span>
            </div>
            
            <div className="text-center w-20">
              <span className="block text-[10px] uppercase text-zinc-500 mb-1">Policy</span>
              <span className={`text-xs font-bold inline-flex items-center gap-1 ${
                session.policy === 'ALLOW' ? 'text-emerald-400 bg-emerald-500/10' :
                session.policy === 'BLOCK' ? 'text-red-400 bg-red-500/10' : 'text-amber-400 bg-amber-500/10'
              } px-2 py-1 rounded`}>
                {session.policy === 'ALLOW' ? <Shield className="w-3 h-3"/> : <Shield className="w-3 h-3"/>}
                {session.policy}
              </span>
            </div>

            <div className="pl-4 border-l dark:border-white/5 border-zinc-200">
              <button 
                onClick={() => terminateSession(session.id)}
                disabled={!session.live}
                className="flex items-center gap-2 px-4 py-2 bg-red-500/10 hover:bg-red-500/20 disabled:dark:bg-zinc-800 disabled:bg-zinc-100 disabled:dark:text-zinc-600 disabled:text-zinc-400 disabled:border-transparent text-red-400 text-xs font-bold uppercase border border-red-500/20 rounded-lg transition-colors"
              >
                <TerminalSquare className="w-4 h-4" />
                {session.live ? 'Terminate' : 'Revoked'}
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
