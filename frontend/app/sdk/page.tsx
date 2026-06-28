"use client";

import { useState } from "react";
import { Terminal, Check, Copy } from "lucide-react";

const CODE_EXAMPLES = {
  rust: `// Cargo.toml: sentinelmark = "1.0"
import sentinelmark::{SentinelClient, Event};

let client = SentinelClient::new("API_KEY");

let event = Event::builder()
    .user_id("user-123")
    .action("LOGIN")
    .ip("192.168.1.1")
    .build();

let response = client.evaluate(event).await?;
println!("Decision: {}", response.decision);`,
  python: `# pip install sentinelmark
from sentinelmark import SentinelClient

client = SentinelClient(api_key="API_KEY")

response = client.evaluate(
    user_id="user-123",
    action="LOGIN",
    ip="192.168.1.1"
)

print(f"Decision: {response.decision}")`,
  javascript: `// npm install @sentinelmark/sdk
import { SentinelClient } from '@sentinelmark/sdk';

const client = new SentinelClient('API_KEY');

const response = await client.evaluate({
  userId: 'user-123',
  action: 'LOGIN',
  ip: '192.168.1.1'
});

console.log('Decision:', response.decision);`
};

type Language = keyof typeof CODE_EXAMPLES;

export default function SdkPlayground() {
  const [lang, setLang] = useState<Language>("rust");
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(CODE_EXAMPLES[lang]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <header className="mb-8">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          SDK Playground
        </h1>
        <p className="text-muted-foreground mt-1">Integrate SentinelMark natively into your application</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b pb-2">
            <div className="flex gap-4">
              {(Object.keys(CODE_EXAMPLES) as Language[]).map(l => (
                <button
                  key={l}
                  onClick={() => setLang(l)}
                  className={`text-sm font-bold uppercase tracking-wider pb-2 border-b-2 transition-colors ${
                    lang === l ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {l}
                </button>
              ))}
            </div>
            <button onClick={handleCopy} className="text-muted-foreground hover:text-foreground transition-colors">
              {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>

          <div className="bg-black/50 p-6 rounded-xl border font-mono text-sm shadow-sm relative overflow-hidden group">
            <pre className="text-blue-400">
              {CODE_EXAMPLES[lang]}
            </pre>
          </div>
        </div>

        <div className="space-y-4">
          <div className="border-b pb-2 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-emerald-500" />
            <h2 className="text-sm font-bold uppercase tracking-wider">Output Simulation</h2>
          </div>
          
          <div className="p-6 rounded-xl border bg-card shadow-sm font-mono text-sm">
            <div className="text-muted-foreground mb-4">$ cargo run --release</div>
            <div className="text-zinc-300 mb-2">Connecting to SentinelMark Engine...</div>
            <div className="text-zinc-300 mb-4">Evaluating transaction vector for user-123...</div>
            
            <div className="grid grid-cols-2 gap-4 mt-6 p-4 border rounded-lg bg-black/20">
              <div>
                <div className="text-xs text-muted-foreground uppercase">Trust Score</div>
                <div className="text-xl text-emerald-500 font-bold">0.81</div>
              </div>
              <div>
                <div className="text-xs text-muted-foreground uppercase">Risk Score</div>
                <div className="text-xl text-red-500 font-bold">0.19</div>
              </div>
              <div className="col-span-2 pt-4 border-t border-white/5">
                <div className="text-xs text-muted-foreground uppercase mb-1">Engine Decision</div>
                <div className="inline-flex px-2 py-1 rounded bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 font-bold">
                  ALLOW
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
