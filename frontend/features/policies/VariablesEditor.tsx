import React from "react";
import { Plus, Trash2, Key } from "lucide-react";
import { PolicyVariable } from "./types";
import { Card } from "@/components/ui/Card";

interface Props {
  variables: PolicyVariable[];
  onChange: (variables: PolicyVariable[]) => void;
}

export default function VariablesEditor({ variables, onChange }: Props) {
  const addVariable = () => {
    onChange([
      ...variables,
      { id: crypto.randomUUID(), key: "", value: "" },
    ]);
  };

  const updateVariable = (id: string, field: "key" | "value", val: string) => {
    onChange(
      variables.map((v) => (v.id === id ? { ...v, [field]: val } : v))
    );
  };

  const deleteVariable = (id: string) => {
    onChange(variables.filter((v) => v.id !== id));
  };

  return (
    <Card className="p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2 text-zinc-900 dark:text-zinc-100">
          <Key className="w-5 h-5 text-blue-500" />
          <h2 className="font-semibold text-lg">Policy Variables</h2>
        </div>
        <button
          onClick={addVariable}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Variable
        </button>
      </div>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
        Define project-level constants referenced by rules (e.g., {"HIGH_RISK_THRESHOLD"}).
      </p>

      {variables.length === 0 ? (
        <div className="text-center py-8 text-sm text-zinc-500 dark:text-zinc-400 border border-dashed border-zinc-300 dark:border-zinc-800 rounded-lg bg-zinc-50/50 dark:bg-black/20">
          No variables defined.
        </div>
      ) : (
        <div className="space-y-3">
          {variables.map((v) => (
            <div key={v.id} className="flex items-center gap-3">
              <input
                type="text"
                placeholder="VARIABLE_NAME"
                value={v.key}
                onChange={(e) => updateVariable(v.id, "key", e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, ""))}
                className="ui-input flex-1 font-mono text-sm"
              />
              <span className="text-zinc-400">=</span>
              <input
                type="text"
                placeholder="Value"
                value={v.value}
                onChange={(e) => updateVariable(v.id, "value", e.target.value)}
                className="ui-input flex-1 font-mono text-sm"
              />
              <button
                onClick={() => deleteVariable(v.id)}
                className="p-2 text-zinc-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-md transition-colors"
                title="Delete Variable"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
