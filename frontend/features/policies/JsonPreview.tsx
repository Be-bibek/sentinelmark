import React, { useState, useEffect } from "react";
import { PolicyDraft } from "./types";
import { Code2, Maximize2, Minimize2, Copy, Check } from "lucide-react";

interface Props {
  policy: PolicyDraft;
  onUpdate: (policy: PolicyDraft) => void;
}

export default function JsonPreview({ policy, onUpdate }: Props) {
  const [isOpen, setIsOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [jsonText, setJsonText] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Sync from props to local state when closed (or initially)
  useEffect(() => {
    if (!isOpen) {
      setJsonText(JSON.stringify(policy, null, 2));
    }
  }, [policy, isOpen]);

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(policy, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApply = () => {
    try {
      const parsed = JSON.parse(jsonText);
      onUpdate(parsed);
      setError(null);
      setIsOpen(false);
    } catch (e: any) {
      setError(e.message || "Invalid JSON");
    }
  };

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 p-4 bg-zinc-900 text-white rounded-full shadow-lg hover:bg-zinc-800 transition-all z-50 group flex items-center gap-2 overflow-hidden"
      >
        <Code2 className="w-5 h-5" />
        <span className="w-0 overflow-hidden group-hover:w-20 transition-all duration-300 text-sm font-semibold whitespace-nowrap">
          Live JSON
        </span>
      </button>
    );
  }

  return (
    <div className="fixed inset-y-0 right-0 w-full md:w-[500px] bg-zinc-950 border-l border-zinc-800 shadow-2xl z-50 flex flex-col transition-transform transform translate-x-0">
      <div className="flex items-center justify-between p-4 border-b border-zinc-800 bg-zinc-900/50">
        <h3 className="text-zinc-100 font-semibold flex items-center gap-2">
          <Code2 className="w-4 h-4 text-blue-400" /> Live AST Preview
        </h3>
        <div className="flex items-center gap-2">
          <button onClick={handleCopy} className="p-2 text-zinc-400 hover:text-white transition-colors">
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
          </button>
          <button onClick={() => setIsOpen(false)} className="p-2 text-zinc-400 hover:text-white transition-colors">
            <Minimize2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      
      <div className="flex-1 p-4 overflow-hidden flex flex-col relative">
        <textarea
          value={jsonText}
          onChange={(e) => {
            setJsonText(e.target.value);
            setError(null);
          }}
          className="flex-1 w-full bg-zinc-900/50 text-zinc-300 font-mono text-xs p-4 rounded-lg outline-none resize-none focus:ring-1 focus:ring-blue-500/50"
          spellCheck={false}
        />
        {error && (
          <div className="absolute bottom-20 left-8 right-8 bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded-md text-xs font-mono">
            {error}
          </div>
        )}
      </div>

      <div className="p-4 border-t border-zinc-800 bg-zinc-900/50">
        <button
          onClick={handleApply}
          className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-md transition-colors"
        >
          Apply JSON Changes
        </button>
      </div>
    </div>
  );
}
