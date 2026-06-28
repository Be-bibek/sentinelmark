"use client";

import { useState } from "react";
import { SentinelAPI } from "@/lib/api";
import { ShieldAlert, Play, Send } from "lucide-react";
import { StarBorder } from "@/components/StarBorder";
import { Strands } from "@/components/Strands";

export default function Simulator() {
  const [payload, setPayload] = useState(JSON.stringify({
    user_id: "user-123",
    event: {
      device_id: "dev-abc",
      browser_fingerprint: "bf-987",
      ip_address: "192.168.1.1",
      geo_region: "US-West",
      action_type: "LOGIN",
      transaction_amount: 0,
      session_duration_secs: 10
    }
  }, null, 2));

  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const runSimulation = async () => {
    try {
      setLoading(true);
      const parsed = JSON.parse(payload);
      const res = await SentinelAPI.evaluate(parsed);
      setResponse(res);
    } catch (err: any) {
      setResponse({ error: err.message });
    } finally {
      setLoading(false);
    }
  };

  const loadScenario = (type: string) => {
    let newPayload = JSON.parse(payload);
    if (type === "impossible_travel") {
      newPayload.event.geo_region = "RU-Moscow";
      newPayload.event.ip_address = "45.12.34.56";
      newPayload.event.action_type = "WIRE_TRANSFER";
      newPayload.event.transaction_amount = 150000;
    } else if (type === "safe_login") {
      newPayload.event.geo_region = "US-West";
      newPayload.event.ip_address = "192.168.1.1";
      newPayload.event.action_type = "LOGIN";
      newPayload.event.transaction_amount = 0;
    }
    setPayload(JSON.stringify(newPayload, null, 2));
  };

  return (
    <div className="relative min-h-full">
      {/* Background Particles */}
      <div className="absolute inset-0 z-0 opacity-30 pointer-events-none">
        <Strands 
          colors={["#F97316", "#7C3AED", "#06B6D4"]}
          count={2}
          speed={0.5}
        />
      </div>

      <div className="p-8 max-w-5xl mx-auto relative z-10 space-y-6">
        <header className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight">Threat Simulator</h1>
          <p className="text-muted-foreground mt-1">Inject custom telemetry vectors into the Trust Engine</p>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div className="p-6 rounded-xl border bg-card/80 backdrop-blur-md shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-bold uppercase tracking-wider flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-orange-500" />
                  Telemetry Payload
                </h2>
                <div className="flex gap-2">
                  <button onClick={() => loadScenario("safe_login")} className="text-xs px-2 py-1 border rounded hover:bg-muted">Safe</button>
                  <button onClick={() => loadScenario("impossible_travel")} className="text-xs px-2 py-1 border rounded border-red-500/50 hover:bg-red-500/10 text-red-500">Attack</button>
                </div>
              </div>
              
              <textarea 
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="w-full h-[400px] bg-black/50 text-emerald-400 font-mono text-sm p-4 rounded-lg border focus:ring-1 focus:ring-emerald-500 outline-none"
                spellCheck={false}
              />

              <div className="mt-4 flex justify-end">
                <StarBorder
                  as="button"
                  color="#10b981"
                  speed="3s"
                  onClick={runSimulation}
                >
                  <span className="flex items-center gap-2 px-6 py-2 text-sm font-bold">
                    <Play className="w-4 h-4" />
                    {loading ? "Evaluating..." : "Run Evaluation"}
                  </span>
                </StarBorder>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <div className="p-6 rounded-xl border bg-card/80 backdrop-blur-md shadow-sm h-full flex flex-col">
              <h2 className="text-sm font-bold uppercase tracking-wider mb-4 flex items-center gap-2">
                <Send className="w-4 h-4 text-blue-500" />
                Engine Response
              </h2>
              
              <div className="flex-1 bg-black/50 rounded-lg border p-4 overflow-auto">
                {response ? (
                  <pre className="text-xs font-mono text-blue-400 whitespace-pre-wrap">
                    {JSON.stringify(response, null, 2)}
                  </pre>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground font-mono text-sm">
                    Awaiting transmission...
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
