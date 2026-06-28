"use client";

import { useState } from "react";
import { Code2, Play, Copy, Check } from "lucide-react";
import { SentinelAPI } from "@/lib/api";

const ENDPOINTS = [
  { id: 'eval', method: 'POST', path: '/api/v1/evaluate', description: 'Evaluate an event synchronously' },
  { id: 'telemetry', method: 'POST', path: '/api/v1/telemetry', description: 'Ingest an event asynchronously' },
  { id: 'behavior', method: 'GET', path: '/api/v1/behavior-profile/:user_id', description: 'Get behavior profile for a user' },
  { id: 'audit', method: 'GET', path: '/api/v1/audit/:user_id', description: 'Get paginated audit logs' },
  { id: 'health', method: 'GET', path: '/api/v1/health', description: 'Check system health' }
];

export default function ApiExplorer() {
  const [active, setActive] = useState(ENDPOINTS[0]);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(`curl -X ${active.method} ${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080"}${active.path.replace(":user_id", "user-123")}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6 flex flex-col h-full">
      <header className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          API Explorer
        </h1>
        <p className="text-muted-foreground mt-1">Interactive API documentation and live request runner</p>
      </header>

      <div className="flex-1 grid grid-cols-1 md:grid-cols-4 gap-6 min-h-[500px]">
        {/* Sidebar list of endpoints */}
        <div className="md:col-span-1 space-y-2">
          {ENDPOINTS.map(ep => (
            <button 
              key={ep.id}
              onClick={() => setActive(ep)}
              className={`w-full text-left p-3 rounded-lg border text-sm font-mono transition-colors flex flex-col gap-1 ${
                active.id === ep.id 
                  ? "bg-primary/10 border-primary text-primary" 
                  : "bg-card border-transparent hover:border-border text-muted-foreground"
              }`}
            >
              <span className={`font-bold ${ep.method === 'GET' ? 'text-blue-500' : 'text-emerald-500'}`}>{ep.method}</span>
              <span className="truncate">{ep.path}</span>
            </button>
          ))}
        </div>

        {/* Main detail pane */}
        <div className="md:col-span-3 rounded-xl border bg-card shadow-sm flex flex-col overflow-hidden">
          <div className="p-4 border-b bg-muted/30 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className={`px-2 py-1 text-[10px] rounded font-bold ${active.method === 'GET' ? 'bg-blue-500/10 text-blue-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
                {active.method}
              </span>
              <span className="font-mono text-sm font-bold">{active.path}</span>
            </div>
            <button onClick={handleCopy} className="p-2 border rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground">
              {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          
          <div className="p-6 flex-1 flex flex-col gap-6">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-2">Description</h3>
              <p className="text-sm">{active.description}</p>
            </div>

            {active.method === 'POST' && (
              <div>
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center justify-between">
                  Request Body (JSON)
                </h3>
                <div className="bg-black/50 p-4 rounded-lg border font-mono text-xs text-blue-400">
                  {`{
  "user_id": "string",
  "event": {
    "action_type": "string"
  }
}`}
                </div>
              </div>
            )}

            <div className="flex-1 flex flex-col">
              <div className="flex justify-between items-center mb-2">
                <h3 className="text-sm font-bold uppercase tracking-wider text-muted-foreground">Response Preview</h3>
                <button className="flex items-center gap-2 px-3 py-1 bg-primary text-primary-foreground text-xs font-bold rounded hover:opacity-90">
                  <Play className="w-3 h-3" /> Execute Request
                </button>
              </div>
              <div className="bg-black/50 p-4 rounded-lg border font-mono text-xs text-emerald-400 flex-1">
                {`{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "req-123",
    "timestamp": "2026-06-28T12:00:00Z"
  }
}`}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
