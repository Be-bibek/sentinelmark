import React, { useRef } from "react";
import { PolicyDraft } from "./types";
import { GitCommit, Save, Upload, Download, Activity, Rocket } from "lucide-react";

interface Props {
  policy: PolicyDraft;
  onUpdate: (policy: PolicyDraft) => void;
  onSave: () => void;
  onPublish: () => void;
  onSimulate: () => void;
}

export default function PolicyHeader({ policy, onUpdate, onSave, onPublish, onSimulate }: Props) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(policy, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `policy_${policy.name.replace(/\s+/g, '_').toLowerCase()}_v${policy.version}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const json = JSON.parse(event.target?.result as string);
        onUpdate(json);
      } catch (err) {
        alert("Invalid Policy JSON file");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="flex flex-col gap-6 mb-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={policy.name}
            onChange={(e) => onUpdate({ ...policy, name: e.target.value })}
            className="text-2xl font-bold bg-transparent border-none outline-none focus:ring-0 px-0 max-w-sm"
          />
          <span className={`px-2.5 py-1 text-xs font-bold rounded-md ${
            policy.status === 'active' 
              ? 'bg-emerald-500/10 text-emerald-500' 
              : 'bg-amber-500/10 text-amber-500'
          }`}>
            {policy.status.toUpperCase()}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleImport} 
            accept="application/json" 
            className="hidden" 
          />
          <button 
            onClick={() => fileInputRef.current?.click()}
            className="p-2 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 bg-white dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-md transition-colors"
            title="Import JSON"
          >
            <Upload className="w-4 h-4" />
          </button>
          <button 
            onClick={handleExport}
            className="p-2 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 bg-white dark:bg-white/5 border border-zinc-200 dark:border-white/10 rounded-md transition-colors"
            title="Export JSON"
          >
            <Download className="w-4 h-4" />
          </button>
          <div className="w-px h-6 bg-zinc-200 dark:bg-zinc-800 mx-2"></div>
          <button
            onClick={onSimulate}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium bg-zinc-100 dark:bg-white/10 hover:bg-zinc-200 dark:hover:bg-white/20 text-zinc-900 dark:text-zinc-100 rounded-md transition-colors"
          >
            <Activity className="w-4 h-4 text-purple-500" />
            Simulate
          </button>
          <button
            onClick={onSave}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium bg-white dark:bg-white/5 hover:bg-zinc-50 dark:hover:bg-white/10 border border-zinc-200 dark:border-white/10 rounded-md transition-colors"
          >
            <Save className="w-4 h-4" />
            Save Draft
          </button>
          <button
            onClick={onPublish}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors shadow-lg shadow-blue-500/20"
          >
            <Rocket className="w-4 h-4" />
            Publish
          </button>
        </div>
      </div>

      {/* Version Timeline */}
      <div className="flex items-center gap-4 py-3 px-4 bg-zinc-50 dark:bg-black/20 border border-zinc-200 dark:border-zinc-800 rounded-lg overflow-x-auto">
        <div className="text-xs font-semibold text-zinc-500 uppercase tracking-wider whitespace-nowrap">Timeline</div>
        
        <div className="flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
          <GitCommit className="w-4 h-4 text-zinc-400" />
          <span className="line-through decoration-zinc-500">v{policy.version - 2}</span>
        </div>
        <div className="w-8 h-px bg-zinc-300 dark:bg-zinc-700"></div>
        <div className="flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
          <GitCommit className="w-4 h-4 text-zinc-400" />
          <span className="line-through decoration-zinc-500">v{policy.version - 1}</span>
          <button className="text-[10px] bg-zinc-200 dark:bg-zinc-800 px-1.5 rounded hover:bg-blue-500 hover:text-white transition-colors">Rollback</button>
        </div>
        <div className="w-8 h-px bg-zinc-300 dark:bg-zinc-700"></div>
        <div className="flex items-center gap-2 text-sm font-bold text-blue-600 dark:text-blue-400">
          <GitCommit className="w-5 h-5 text-blue-500" />
          <span>v{policy.version} (Active)</span>
        </div>
        <div className="w-8 h-px bg-zinc-300 dark:bg-zinc-700"></div>
        <div className="flex items-center gap-2 text-sm font-medium text-amber-600 dark:text-amber-400 border border-dashed border-amber-300 dark:border-amber-500/30 px-2 py-0.5 rounded">
          <GitCommit className="w-4 h-4 text-amber-500" />
          <span>v{policy.version + 1} (Draft)</span>
        </div>
      </div>
    </div>
  );
}
