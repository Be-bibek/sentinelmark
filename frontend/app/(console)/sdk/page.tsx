"use client";

import React, { useState } from "react";
import { Terminal, Copy, Check, Code2 } from "lucide-react";
import { useTheme } from "next-themes";

const LANGUAGES = [
  { id: "python", name: "Python", icon: "🐍" },
  { id: "javascript", name: "Node.js", icon: "📦" },
  { id: "rust", name: "Rust", icon: "🦀" },
  { id: "go", name: "Go", icon: "🐹" },
];

export default function SdkPage() {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [activeLang, setActiveLang] = useState("python");
  const [copied, setCopied] = useState(false);

  // In a real app, fetch these from state/context
  const apiKey = "sm_live_aB3x9kLpM...";
  const projectId = "proj_8f92bd3a";

  const getSnippet = () => {
    switch(activeLang) {
      case "python":
        return `from sentinelmark import Client

# Initialize the SentinelMark client
client = Client(
    api_key="${apiKey}",
    project_id="${projectId}"
)

# Evaluate an event
response = client.evaluate(
    product="dicom-trace",
    event_type="Image Upload",
    payload={"file_hash": "a1b2c3d4"}
)

if response.decision == "BLOCK":
    print("Event blocked by policy!")
else:
    print(f"Trust score: {response.trust_score}")`;
      case "javascript":
        return `import { SentinelMark } from '@sentinelmark/sdk';

// Initialize the SentinelMark client
const client = new SentinelMark({
  apiKey: "${apiKey}",
  projectId: "${projectId}"
});

// Evaluate an event
const response = await client.evaluate({
  product: "dicom-trace",
  eventType: "Image Upload",
  payload: { file_hash: "a1b2c3d4" }
});

if (response.decision === "BLOCK") {
  console.log("Event blocked by policy!");
} else {
  console.log(\`Trust score: \${response.trustScore}\`);
}`;
      case "rust":
        return `use sentinelmark::{Client, Event};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the SentinelMark client
    let client = Client::new(
        "${apiKey}",
        "${projectId}"
    );

    // Evaluate an event
    let response = client.evaluate(Event {
        product: "dicom-trace".into(),
        event_type: "Image Upload".into(),
        payload: serde_json::json!({ "file_hash": "a1b2c3d4" }),
    }).await?;

    if response.decision == "BLOCK" {
        println!("Event blocked by policy!");
    } else {
        println!("Trust score: {}", response.trust_score);
    }

    Ok(())
}`;
      case "go":
        return `package main

import (
	"fmt"
	"log"

	"github.com/sentinelmark/sentinelmark-go"
)

func main() {
	// Initialize the SentinelMark client
	client := sentinelmark.NewClient(
		"${apiKey}",
		"${projectId}",
	)

	// Evaluate an event
	response, err := client.Evaluate(sentinelmark.Event{
		Product:   "dicom-trace",
		EventType: "Image Upload",
		Payload:   map[string]interface{}{"file_hash": "a1b2c3d4"},
	})
	if err != nil {
		log.Fatal(err)
	}

	if response.Decision == "BLOCK" {
		fmt.Println("Event blocked by policy!")
	} else {
		fmt.Printf("Trust score: %f\\n", response.TrustScore)
	}
}`;
      default:
        return "";
    }
  };

  const getInstallCmd = () => {
    switch(activeLang) {
      case "python": return "pip install sentinelmark";
      case "javascript": return "npm install @sentinelmark/sdk";
      case "rust": return "cargo add sentinelmark";
      case "go": return "go get github.com/sentinelmark/sentinelmark-go";
      default: return "";
    }
  };

  const copyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className={`text-2xl font-bold tracking-tight ${isDark ? "text-white" : "text-zinc-900"}`}>SDKs & Integrations</h1>
          <p className={`text-sm mt-1 ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>
            Integrate SentinelMark into your backend securely.
          </p>
        </div>
      </div>

      <div className={`ui-card overflow-hidden ${isDark ? "bg-black/20" : "bg-white"}`}>
        {/* Language Tabs */}
        <div className={`flex border-b overflow-x-auto ${isDark ? "border-white/10" : "border-zinc-200"}`}>
          {LANGUAGES.map(lang => (
            <button
              key={lang.id}
              onClick={() => setActiveLang(lang.id)}
              className={`flex items-center gap-2 px-6 py-4 text-sm font-medium transition-colors relative whitespace-nowrap ${
                activeLang === lang.id 
                  ? (isDark ? "text-blue-400 bg-white/5" : "text-blue-600 bg-zinc-50") 
                  : (isDark ? "text-zinc-400 hover:text-zinc-200 hover:bg-white/5" : "text-zinc-500 hover:text-zinc-900 hover:bg-zinc-50")
              }`}
            >
              <span className="text-lg">{lang.icon}</span>
              {lang.name}
              {activeLang === lang.id && (
                <div className="absolute bottom-0 left-0 w-full h-0.5 bg-blue-500 shadow-[0_-2px_10px_rgba(59,130,246,0.5)]"></div>
              )}
            </button>
          ))}
        </div>

        <div className="p-6 space-y-6">
          {/* Installation */}
          <div>
            <h3 className={`text-sm font-semibold mb-3 ${isDark ? "text-zinc-300" : "text-zinc-700"}`}>1. Installation</h3>
            <div className={`flex items-center justify-between p-3 rounded-lg border font-mono text-sm ${isDark ? "bg-black/50 border-white/10 text-zinc-300" : "bg-zinc-100 border-zinc-200 text-zinc-800"}`}>
              <div className="flex items-center gap-3">
                <Terminal className={`w-4 h-4 ${isDark ? "text-zinc-500" : "text-zinc-400"}`} />
                {getInstallCmd()}
              </div>
              <button 
                onClick={() => copyCode(getInstallCmd())}
                className={`p-1.5 rounded transition-colors ${isDark ? "text-zinc-400 hover:bg-white/10" : "text-zinc-500 hover:bg-white"}`}
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Integration */}
          <div>
            <div className="flex justify-between items-end mb-3">
              <h3 className={`text-sm font-semibold ${isDark ? "text-zinc-300" : "text-zinc-700"}`}>2. Quick Start</h3>
              <div className={`text-xs ${isDark ? "text-amber-400/80" : "text-amber-600"} flex items-center gap-1`}>
                <Code2 className="w-3.5 h-3.5" /> Code is configured for active project.
              </div>
            </div>
            
            <div className="relative group">
              <pre className={`p-4 rounded-lg border font-mono text-sm overflow-x-auto ${isDark ? "bg-[#0d1117] border-white/10 text-[#c9d1d9]" : "bg-zinc-900 border-zinc-800 text-zinc-300"}`}>
                <code>{getSnippet()}</code>
              </pre>
              <button 
                onClick={() => copyCode(getSnippet())}
                className={`absolute top-3 right-3 flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-opacity opacity-0 group-hover:opacity-100 ${
                  isDark ? "bg-white/10 hover:bg-white/20 text-white" : "bg-white/10 hover:bg-white/20 text-white backdrop-blur-md"
                }`}
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? "Copied!" : "Copy code"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
