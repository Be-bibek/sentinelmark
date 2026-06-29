"use client";

import React, { useState } from "react";
import { Play, Activity, Clock, FileJson, Copy, Check } from "lucide-react";
import { useTheme } from "next-themes";

export default function ApiPlaygroundPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const defaultPayload = `{
  "product_slug": "dicom-trace",
  "event_type": "Image Upload",
  "payload": {
    "file_hash": "a1b2c3d4",
    "metadata_integrity": 100
  },
  "context": {
    "ip": "192.168.1.1",
    "device_id": "dev_xyz"
  }
}`;

  const [requestBody, setRequestBody] = useState(defaultPayload);
  const [method, setMethod] = useState("POST");
  const [endpoint, setEndpoint] = useState("/api/v1/events");
  const [response, setResponse] = useState<string | null>(null);
  const [latency, setLatency] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const executeRequest = () => {
    setLoading(true);
    setResponse(null);
    setLatency(null);
    
    // Simulate API request delay
    const start = performance.now();
    setTimeout(() => {
      const end = performance.now();
      setLatency(Math.round(end - start));
      setResponse(JSON.stringify({
        status: "success",
        evaluation: {
          risk_score: 12,
          trust_score: 95,
          decision: "ALLOW",
          factors: ["Known Device", "Metadata Valid"]
        },
        event_id: "evt_123456"
      }, null, 2));
      setLoading(false);
    }, 450 + Math.random() * 200);
  };

  const copyCurl = () => {
    const curl = `curl -X ${method} https://api.sentinelmark.dev${endpoint} \\
  -H "Authorization: Bearer sm_live_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '${requestBody.replace(/\n/g, "")}'`;
    navigator.clipboard.writeText(curl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className={`text-2xl font-bold tracking-tight ${isDark ? "text-white" : "text-zinc-900"}`}>API Playground</h1>
          <p className={`text-sm mt-1 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
            Test SentinelMark evaluations interactively before integrating the SDKs.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Request Panel */}
        <div className={`ui-card flex flex-col ${isDark ? "bg-black/20" : "bg-white"}`}>
          <div className={`p-4 border-b flex items-center gap-3 ${isDark ? "border-white/10" : "border-zinc-200"}`}>
            <select 
              value={method} 
              onChange={e => setMethod(e.target.value)}
              className={`text-sm font-bold bg-transparent border-none outline-none cursor-pointer ${
                method === "POST" ? "text-emerald-500" : "text-blue-500"
              }`}
            >
              <option>POST</option>
              <option>GET</option>
            </select>
            <input 
              type="text" 
              value={endpoint}
              onChange={e => setEndpoint(e.target.value)}
              className="flex-1 bg-transparent border-none outline-none font-mono text-sm"
              placeholder="/api/v1/events"
            />
            <button 
              onClick={executeRequest}
              disabled={loading}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md text-sm font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {loading ? <Activity className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Send
            </button>
          </div>
          
          <div className="p-4 flex-1 flex flex-col min-h-[400px]">
            <div className={`flex justify-between items-center mb-2 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider">
                <FileJson className="w-3.5 h-3.5" /> Request Body (JSON)
              </div>
            </div>
            <textarea
              value={requestBody}
              onChange={e => setRequestBody(e.target.value)}
              className={`flex-1 w-full p-4 font-mono text-sm rounded-lg border resize-none focus:ring-1 focus:ring-blue-500 outline-none transition-colors ${
                isDark 
                  ? "bg-black/50 border-white/5 text-zinc-300" 
                  : "bg-zinc-50 border-zinc-200 text-zinc-800"
              }`}
              spellCheck={false}
            />
          </div>
        </div>

        {/* Response Panel */}
        <div className={`ui-card flex flex-col ${isDark ? "bg-black/20" : "bg-white"}`}>
          <div className={`p-4 border-b flex items-center justify-between ${isDark ? "border-white/10" : "border-zinc-200"}`}>
            <div className="flex items-center gap-4">
              <span className={`text-sm font-semibold ${response ? "text-emerald-500" : isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                {response ? "200 OK" : "Waiting for request..."}
              </span>
              {latency !== null && (
                <div className={`flex items-center gap-1 text-xs ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
                  <Clock className="w-3.5 h-3.5" />
                  {latency}ms
                </div>
              )}
            </div>
            <button 
              onClick={copyCurl}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                isDark 
                  ? "bg-white/5 hover:bg-white/10 text-zinc-300" 
                  : "bg-zinc-100 hover:bg-zinc-200 text-zinc-700"
              }`}
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              cURL
            </button>
          </div>

          <div className="p-4 flex-1 flex flex-col min-h-[400px]">
            <div className={`flex items-center gap-2 text-xs font-semibold uppercase tracking-wider mb-2 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
              <FileJson className="w-3.5 h-3.5" /> Response
            </div>
            <div className={`flex-1 w-full p-4 font-mono text-sm rounded-lg border overflow-auto ${
              isDark 
                ? "bg-black/80 border-white/5 text-zinc-300" 
                : "bg-zinc-900 border-zinc-800 text-zinc-300"
            }`}>
              {loading ? (
                <div className="flex flex-col items-center justify-center h-full text-zinc-500 gap-3">
                  <Activity className="w-6 h-6 animate-spin text-blue-500" />
                  Processing Evaluation...
                </div>
              ) : response ? (
                <pre>{response}</pre>
              ) : (
                <div className="flex h-full items-center justify-center text-zinc-600">
                  Hit Send to evaluate the payload
                </div>
              )}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
