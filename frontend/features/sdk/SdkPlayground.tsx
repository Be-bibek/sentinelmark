"use client";

import React, { useState } from "react";
import { Check, Copy, Package } from "lucide-react";

const SDKS = {
  rust: {
    name: "Rust",
    install: "cargo add sentinelmark",
    code: `use sentinelmark::{Client, EvaluationRequest};\n\n#[tokio::main]\nasync fn main() -> Result<(), Box<dyn std::error::Error>> {\n    let client = Client::new("sm_live_12345");\n\n    let decision = client.evaluate(EvaluationRequest {\n        user_id: "user_42".to_string(),\n        action: "login".to_string(),\n        ip: "192.168.1.1".to_string(),\n    }).await?;\n\n    println!("Trust Score: {}", decision.trust_score);\n    Ok(())\n}`
  },
  python: {
    name: "Python",
    install: "pip install sentinelmark",
    code: `from sentinelmark import Client\n\nclient = Client(api_key="sm_live_12345")\n\ndecision = client.evaluate(\n    user_id="user_42",\n    action="login",\n    ip="192.168.1.1"\n)\n\nprint(f"Trust Score: {decision.trust_score}")`
  },
  node: {
    name: "Node.js",
    install: "npm install @sentinelmark/sdk",
    code: `import { SentinelClient } from '@sentinelmark/sdk';\n\nconst client = new SentinelClient('sm_live_12345');\n\nasync function main() {\n  const decision = await client.evaluate({\n    userId: 'user_42',\n    action: 'login',\n    ip: '192.168.1.1'\n  });\n\n  console.log(\`Trust Score: \${decision.trustScore}\`);\n}\n\nmain();`
  },
  go: {
    name: "Go",
    install: "go get github.com/sentinelmark/sdk-go",
    code: `package main\n\nimport (\n\t"fmt"\n\t"github.com/sentinelmark/sdk-go"\n)\n\nfunc main() {\n\tclient := sentinelmark.NewClient("sm_live_12345")\n\n\tres, _ := client.Evaluate(sentinelmark.EvaluationRequest{\n\t\tUserID: "user_42",\n\t\tAction: "login",\n\t\tIP:     "192.168.1.1",\n\t})\n\n\tfmt.Printf("Trust Score: %d\\n", res.TrustScore)\n}`
  }
};

type SdkLang = keyof typeof SDKS;

export default function SdkPlayground() {
  const [activeTab, setActiveTab] = useState<SdkLang>("python");
  const [copiedInstall, setCopiedInstall] = useState(false);
  const [copiedCode, setCopiedCode] = useState(false);

  const copyInstall = () => {
    navigator.clipboard.writeText(SDKS[activeTab].install);
    setCopiedInstall(true);
    setTimeout(() => setCopiedInstall(false), 2000);
  };

  const copyCode = () => {
    navigator.clipboard.writeText(SDKS[activeTab].code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="ui-card flex flex-col h-[700px] overflow-hidden">
      
      {/* Tabs */}
      <div className="flex border-b dark:border-white/5 border-zinc-200 dark:bg-black/40 bg-zinc-50/80 px-2 pt-2 gap-1 overflow-x-auto">
        {(Object.keys(SDKS) as SdkLang[]).map((lang) => (
          <button
            key={lang}
            onClick={() => setActiveTab(lang)}
            className={`px-6 py-3 text-sm font-semibold rounded-t-lg transition-colors border-b-2 ${
              activeTab === lang 
                ? 'dark:bg-white/10 bg-white dark:text-white text-zinc-900 border-blue-500' 
                : 'text-zinc-500 border-transparent hover:dark:text-zinc-300 hover:text-zinc-700 hover:dark:bg-white/5 hover:bg-zinc-100'
            }`}
          >
            {SDKS[lang].name}
          </button>
        ))}
      </div>

      <div className="p-8 flex-1 flex flex-col space-y-8">
        
        {/* Install Section */}
        <div>
          <h3 className="dark:text-white text-zinc-900 font-bold mb-3 flex items-center gap-2"><Package className="w-4 h-4 text-emerald-400"/> Installation</h3>
          <div className="ui-subcard flex items-center justify-between p-4">
            <code className="text-emerald-400 font-mono text-sm">{SDKS[activeTab].install}</code>
            <button onClick={copyInstall} className="p-2 dark:hover:bg-white/10 hover:bg-zinc-200 rounded dark:text-zinc-400 text-zinc-500 hover:dark:text-white hover:text-zinc-900 transition-colors">
              {copiedInstall ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Code Example Section */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex items-center justify-between mb-3">
            <h3 className="dark:text-white text-zinc-900 font-bold">Example Integration</h3>
            <button onClick={copyCode} className="flex items-center gap-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors bg-blue-500/10 px-3 py-1.5 rounded-lg border border-blue-500/20">
              {copiedCode ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              {copiedCode ? 'COPIED' : 'COPY CODE'}
            </button>
          </div>
          <div className="ui-subcard flex-1 !p-0 overflow-auto">
            <pre className="p-6 font-mono text-sm leading-relaxed text-blue-300">
              {SDKS[activeTab].code}
            </pre>
          </div>
        </div>

      </div>
    </div>
  );
}
