import React, { useState } from "react";
import { Play, Activity, ChevronDown, ChevronUp, Trash2, GripVertical } from "lucide-react";
import { Rule, PolicyAction, ConditionType, FlatCondition } from "./types";
import { Card } from "@/components/ui/Card";
import ConditionEditor from "./ConditionEditor";

interface Props {
  rule: Rule;
  onChange: (rule: Rule) => void;
  onDelete: () => void;
}

const ACTIONS: { value: PolicyAction; label: string; color: string }[] = [
  { value: "ALLOW", label: "ALLOW", color: "text-emerald-500 bg-emerald-50 dark:bg-emerald-500/10" },
  { value: "BLOCK", label: "BLOCK", color: "text-red-500 bg-red-50 dark:bg-red-500/10" },
  { value: "MFA", label: "MFA", color: "text-amber-500 bg-amber-50 dark:bg-amber-500/10" },
  { value: "CHALLENGE", label: "CHALLENGE", color: "text-blue-500 bg-blue-50 dark:bg-blue-500/10" },
];

export default function RuleCard({ rule, onChange, onDelete }: Props) {
  const [isTestOpen, setIsTestOpen] = useState(false);
  const [testPayload, setTestPayload] = useState("{\n  \"context\": {\n    \"country\": \"US\"\n  },\n  \"trust\": {\n    \"risk_score\": 0.9\n  }\n}");
  const [testResult, setTestResult] = useState<null | { matched: boolean; reason?: string }>(null);

  const handleTest = () => {
    // Basic mock evaluation logic for UI preview
    try {
      const data = JSON.parse(testPayload);
      // Dummy evaluation: if it has risk_score > 0.8, let's say it matches if the rule is BLOCK
      const isHighRisk = data?.trust?.risk_score > 0.8;
      
      setTestResult({
        matched: isHighRisk,
        reason: isHighRisk ? "Condition (trust.risk_score > 0.8) matched." : "Did not match conditions.",
      });
    } catch (e) {
      setTestResult({ matched: false, reason: "Invalid JSON format." });
    }
  };

  const update = (updates: Partial<Rule>) => onChange({ ...rule, ...updates });

  return (
    <Card className="overflow-hidden border border-zinc-200 dark:border-zinc-800 transition-all duration-200 hover:border-blue-500/30">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 bg-zinc-50 dark:bg-black/20 border-b border-zinc-200 dark:border-zinc-800">
        <div className="cursor-grab text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300">
          <GripVertical className="w-5 h-5" />
        </div>
        
        <div className="flex-1 flex flex-col sm:flex-row sm:items-center gap-3">
          <input
            type="text"
            value={rule.name}
            onChange={(e) => update({ name: e.target.value })}
            placeholder="Rule Name"
            className="font-semibold bg-transparent border-none outline-none focus:ring-0 px-0 text-base flex-1"
          />
          
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Priority</span>
            <input
              type="number"
              value={rule.priority}
              onChange={(e) => update({ priority: parseInt(e.target.value) || 0 })}
              className="ui-input w-20 text-center font-mono text-sm"
            />
          </div>

          <select
            value={rule.action}
            onChange={(e) => update({ action: e.target.value as PolicyAction })}
            className={`ui-input w-36 font-bold text-sm text-center ${
              ACTIONS.find((a) => a.value === rule.action)?.color
            }`}
          >
            {ACTIONS.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2 border-l border-zinc-200 dark:border-zinc-800 pl-4 ml-2">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={rule.enabled}
              onChange={(e) => update({ enabled: e.target.checked })}
              className="rounded border-zinc-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-zinc-600 dark:text-zinc-400">Enabled</span>
          </label>
          <button onClick={onDelete} className="p-1.5 text-zinc-400 hover:text-red-500 rounded-md transition-colors">
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Body: Conditions */}
      <div className="p-5">
        <ConditionEditor
          conditionType={rule.conditionType}
          conditions={rule.conditions}
          onTypeChange={(type) => update({ conditionType: type })}
          onConditionsChange={(conds) => update({ conditions: conds })}
        />
      </div>

      {/* Footer: Metrics & Test */}
      <div className="flex flex-col border-t border-zinc-100 dark:border-zinc-800/50 bg-zinc-50/50 dark:bg-black/10">
        <div className="flex items-center justify-between p-3 px-5">
          {/* Metrics Placeholder */}
          <div className="flex items-center gap-6 text-xs text-zinc-500 font-mono">
            <div className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" /> Matched: <span className="font-semibold text-zinc-700 dark:text-zinc-300">124</span></div>
            <div className="flex items-center gap-1.5">Actioned: <span className="font-semibold text-zinc-700 dark:text-zinc-300">35</span></div>
            <div className="flex items-center gap-1.5">Avg Latency: <span className="font-semibold text-zinc-700 dark:text-zinc-300">1.2ms</span></div>
          </div>
          
          <button
            onClick={() => setIsTestOpen(!isTestOpen)}
            className="flex items-center gap-1.5 text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline"
          >
            <Play className="w-3.5 h-3.5" />
            {isTestOpen ? "Hide Test" : "Test Rule"}
            {isTestOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Expanded Test Section */}
        {isTestOpen && (
          <div className="p-5 border-t border-zinc-100 dark:border-zinc-800/50 flex flex-col md:flex-row gap-4">
            <div className="flex-1 space-y-2">
              <label className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Example Event JSON</label>
              <textarea
                value={testPayload}
                onChange={(e) => setTestPayload(e.target.value)}
                className="ui-input w-full h-32 font-mono text-xs bg-zinc-900 text-zinc-300 border-zinc-800"
              />
              <button
                onClick={handleTest}
                className="w-full py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded transition-colors"
              >
                Evaluate Rule
              </button>
            </div>
            
            <div className="flex-1 space-y-2">
              <label className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Explainability Preview</label>
              <div className="h-32 ui-input bg-zinc-50 dark:bg-black/20 flex flex-col gap-2 overflow-y-auto">
                {!testResult ? (
                  <div className="text-zinc-400 text-sm flex-1 flex items-center justify-center italic">Run evaluation to see results</div>
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">Matched?</span>
                      {testResult.matched ? (
                        <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-500 text-xs font-bold rounded">YES</span>
                      ) : (
                        <span className="px-2 py-0.5 bg-zinc-500/10 text-zinc-500 text-xs font-bold rounded">NO</span>
                      )}
                    </div>
                    {testResult.matched && (
                      <div className="flex items-center justify-between border-t border-zinc-200 dark:border-zinc-800 pt-2">
                        <span className="text-sm font-medium">Action</span>
                        <span className={`text-xs font-bold ${ACTIONS.find(a => a.value === rule.action)?.color} px-2 py-0.5 rounded`}>
                          {rule.action}
                        </span>
                      </div>
                    )}
                    <div className="text-sm text-zinc-600 dark:text-zinc-400">
                      <strong>Reason:</strong> {testResult.reason}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}
