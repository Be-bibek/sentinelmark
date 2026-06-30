import React from "react";
import { Plus, Trash2, Code } from "lucide-react";
import { ConditionType, FlatCondition, Operator } from "./types";

interface Props {
  conditionType: ConditionType;
  conditions: FlatCondition[];
  onTypeChange: (type: ConditionType) => void;
  onConditionsChange: (conditions: FlatCondition[]) => void;
}

const OPERATORS: { value: Operator; label: string }[] = [
  { value: "==", label: "Equals" },
  { value: "!=", label: "Not Equals" },
  { value: ">", label: "Greater Than" },
  { value: "<", label: "Less Than" },
  { value: "IN", label: "In List" },
  { value: "NOT_IN", label: "Not In List" },
];

export default function ConditionEditor({
  conditionType,
  conditions,
  onTypeChange,
  onConditionsChange,
}: Props) {
  const addCondition = () => {
    onConditionsChange([
      ...conditions,
      { id: crypto.randomUUID(), field: "", operator: "==", value: "" },
    ]);
  };

  const updateCondition = (id: string, updates: Partial<FlatCondition>) => {
    onConditionsChange(
      conditions.map((c) => (c.id === id ? { ...c, ...updates } : c))
    );
  };

  const removeCondition = (id: string) => {
    onConditionsChange(conditions.filter((c) => c.id !== id));
  };

  return (
    <div className="space-y-4">
      {/* Logic Gate Selector */}
      <div className="flex items-center gap-4 border-b border-zinc-200 dark:border-zinc-800 pb-4">
        <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300 flex items-center gap-2">
          <Code className="w-4 h-4" />
          Match:
        </span>
        <div className="flex bg-zinc-100 dark:bg-zinc-800 rounded-lg p-1">
          {(["AND", "OR"] as ConditionType[]).map((type) => (
            <button
              key={type}
              onClick={() => onTypeChange(type)}
              className={`px-4 py-1 text-xs font-semibold rounded-md transition-all ${
                conditionType === type
                  ? "bg-white dark:bg-zinc-700 shadow-sm text-blue-600 dark:text-blue-400"
                  : "text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              {type === "AND" ? "ALL (AND)" : "ANY (OR)"}
            </button>
          ))}
        </div>
      </div>

      {/* Conditions List */}
      <div className="space-y-2 relative">
        {conditions.map((cond, index) => (
          <div key={cond.id} className="flex flex-col sm:flex-row items-center gap-2 relative">
            {/* Logic Connector Line */}
            {index > 0 && (
              <div className="hidden sm:flex absolute -left-6 text-[10px] font-bold text-zinc-400">
                {conditionType}
              </div>
            )}
            
            <input
              type="text"
              placeholder="e.g. context.country"
              value={cond.field}
              onChange={(e) => updateCondition(cond.id, { field: e.target.value })}
              className="ui-input flex-1 font-mono text-sm"
            />
            
            <select
              value={cond.operator}
              onChange={(e) => updateCondition(cond.id, { operator: e.target.value as Operator })}
              className="ui-input w-36 bg-zinc-50 dark:bg-zinc-900 text-sm font-semibold text-center"
            >
              {OPERATORS.map((op) => (
                <option key={op.value} value={op.value}>
                  {op.label}
                </option>
              ))}
            </select>
            
            <input
              type="text"
              placeholder="e.g. US, CA or 0.8"
              value={cond.value as string}
              onChange={(e) => updateCondition(cond.id, { value: e.target.value })}
              className="ui-input flex-1 font-mono text-sm"
            />
            
            <button
              onClick={() => removeCondition(cond.id)}
              className="p-2 text-zinc-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-md transition-colors"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        ))}
      </div>

      <button
        onClick={addCondition}
        className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-500/10 rounded-md transition-colors"
      >
        <Plus className="w-3.5 h-3.5" />
        Add Condition
      </button>
    </div>
  );
}
