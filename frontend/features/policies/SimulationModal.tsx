import React from "react";
import { X, Activity, ArrowRight } from "lucide-react";
import { PolicyDraft } from "./types";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  policy: PolicyDraft;
}

export default function SimulationModal({ isOpen, onClose, policy }: Props) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-white dark:bg-[#111] border border-zinc-200 dark:border-white/10 rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
        
        <div className="flex items-center justify-between p-4 border-b border-zinc-200 dark:border-white/10 bg-zinc-50 dark:bg-white/5">
          <div className="flex items-center gap-2 font-semibold text-zinc-900 dark:text-zinc-100">
            <Activity className="w-5 h-5 text-purple-500" />
            Dry Run Simulation
          </div>
          <button onClick={onClose} className="p-1 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 rounded-md">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div className="text-sm text-zinc-600 dark:text-zinc-400">
            Simulating <strong className="text-zinc-900 dark:text-white">v{policy.version + 1} (Draft)</strong> against the last 10,000 live events.
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20">
              <div className="text-xs font-semibold text-emerald-800 dark:text-emerald-400 uppercase tracking-wider mb-2">Allows</div>
              <div className="flex items-end gap-3">
                <span className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">8,450</span>
                <span className="flex items-center text-sm font-medium text-emerald-600 dark:text-emerald-400 mb-1">
                  <ArrowRight className="w-3 h-3 rotate-[-45deg]" /> +23
                </span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20">
              <div className="text-xs font-semibold text-red-800 dark:text-red-400 uppercase tracking-wider mb-2">Blocks</div>
              <div className="flex items-end gap-3">
                <span className="text-2xl font-bold text-red-600 dark:text-red-400">1,230</span>
                <span className="flex items-center text-sm font-medium text-red-600 dark:text-red-400 mb-1">
                  <ArrowRight className="w-3 h-3 rotate-[45deg]" /> -5
                </span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20">
              <div className="text-xs font-semibold text-amber-800 dark:text-amber-400 uppercase tracking-wider mb-2">MFA / Challenges</div>
              <div className="flex items-end gap-3">
                <span className="text-2xl font-bold text-amber-600 dark:text-amber-400">320</span>
                <span className="flex items-center text-sm font-medium text-amber-600 dark:text-amber-400 mb-1">
                  <ArrowRight className="w-3 h-3 rotate-[-45deg]" /> +18
                </span>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-800">
            <h4 className="text-sm font-semibold mb-2">Key Insights</h4>
            <ul className="text-sm text-zinc-600 dark:text-zinc-400 space-y-1 list-disc pl-4">
              <li>Traffic blocking decreased by 0.4%</li>
              <li>MFA challenges increased due to Rule "Block High Risk Geo"</li>
              <li>Simulation completed in 1.2s</li>
            </ul>
          </div>
        </div>

        <div className="p-4 border-t border-zinc-200 dark:border-white/10 bg-zinc-50 dark:bg-white/5 flex justify-end">
          <button onClick={onClose} className="px-4 py-2 bg-blue-600 text-white rounded-md font-semibold text-sm hover:bg-blue-700 transition-colors">
            Close Simulation
          </button>
        </div>
      </div>
    </div>
  );
}
