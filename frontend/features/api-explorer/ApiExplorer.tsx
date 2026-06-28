"use client";

import React, { useState } from "react";
import { Play, Copy, Check, Clock, Server, Terminal } from "lucide-react";

export default function ApiExplorer() {
  const [copied, setCopied] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [latency, setLatency] = useState(0);

  const payload = JSON.stringify({
    user_id: "api_test_user",
    event: {
      action_type: "login",
      ip_address: "192.168.1.1",
      device_id: "dev_terminal"
    }
  }, null, 2);

  const curlCommand = `curl -X POST https://api.sentinelmark.com/v1/evaluate \\
  -H "Authorization: Bearer sm_live_12345" \\
  -H "Content-Type: application/json" \\
  -d '${payload}'`;

  const copyCommand = () => {
    navigator.clipboard.writeText(curlCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const executeApi = () => {
    setExecuting(true);
    setResponse(null);
    const start = Date.now();
    
    // Simulate API call to local rust backend
    setTimeout(() => {
      setLatency(Date.now() - start);
      setResponse({
        trust_score: 98,
        decision: "ALLOW",
        risk_factors: [],
        session_id: "sess_xyz123",
        evaluated_at: new Date().toISOString()
      });
      setExecuting(false);
    }, 145);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-[700px]">
      
      {/* Left Pane - Request */}
      <div className="ui-card p-5 flex flex-col">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <span className="bg-emerald-500/10 text-emerald-400 font-mono text-xs font-bold px-2 py-1 rounded">POST</span>
            <span className="dark:text-white text-zinc-900 font-mono text-sm">/v1/evaluate</span>
          </div>
          <button 
            onClick={executeApi}
            disabled={executing}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-bold uppercase rounded-lg transition-colors"
          >
            {executing ? <span className="animate-pulse flex items-center gap-2"><Server className="w-4 h-4"/> Executing</span> : <><Play className="w-4 h-4"/> Execute Request</>}
          </button>
        </div>

        <div className="space-y-4 flex-1">
          <div>
            <h4 className="text-xs font-semibold text-zinc-500 uppercase mb-2">Headers</h4>
            <div className="ui-subcard font-mono text-xs space-y-1">
              <div><span className="text-blue-400">Authorization:</span> <span className="text-green-400">Bearer sm_live_12345</span></div>
              <div><span className="text-blue-400">Content-Type:</span> <span className="text-green-400">application/json</span></div>
            </div>
          </div>

          <div className="flex-1 flex flex-col min-h-[300px]">
            <h4 className="text-xs font-semibold text-zinc-500 uppercase mb-2">JSON Body</h4>
            <textarea 
              readOnly 
              value={payload}
              className="ui-subcard w-full flex-1 font-mono text-xs text-green-400 outline-none resize-none"
            />
          </div>
        </div>

        <div className="mt-4 pt-4 border-t dark:border-white/5 border-zinc-200 flex items-center justify-between">
          <span className="text-xs text-zinc-500 flex items-center gap-2"><Terminal className="w-4 h-4"/> Copy as cURL</span>
          <button onClick={copyCommand} className="p-2 dark:hover:bg-white/10 hover:bg-zinc-100 rounded-lg dark:text-zinc-400 text-zinc-500 hover:dark:text-white hover:text-zinc-900 transition-colors">
            {copied ? <Check className="w-4 h-4 text-emerald-400"/> : <Copy className="w-4 h-4"/>}
          </button>
        </div>
      </div>

      {/* Right Pane - Response */}
      <div className="ui-card p-5 flex flex-col">
        <div className="flex items-center justify-between mb-6 pb-2 border-b dark:border-white/5 border-zinc-200">
          <h3 className="font-semibold dark:text-white text-zinc-900">Response</h3>
          {response && (
            <div className="flex gap-4">
              <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded">200 OK</span>
              <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2 py-1 rounded flex items-center gap-1"><Clock className="w-3 h-3"/> {latency}ms</span>
            </div>
          )}
        </div>

        <div className="flex-1 ui-subcard !p-0 overflow-hidden relative">
          {executing ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="flex gap-2">
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce"></div>
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: "0.2s" }}></div>
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style={{ animationDelay: "0.4s" }}></div>
              </div>
            </div>
          ) : response ? (
            <pre className="p-4 font-mono text-xs text-green-400 overflow-auto h-full">
              {JSON.stringify(response, null, 2)}
            </pre>
          ) : (
            <div className="absolute inset-0 flex items-center justify-center text-zinc-600 text-xs font-mono">
              Hit "Execute Request" to test the API
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
