import React from "react";
import { AlertCircle, CheckCircle2 } from "lucide-react";
import { PolicyDraft, Rule } from "./types";

interface Props {
  policy: PolicyDraft;
}

export default function ValidationPanel({ policy }: Props) {
  const errors: string[] = [];

  // Check unique priorities
  const priorities = new Set<number>();
  let hasDuplicatePriority = false;
  
  // Check empty conditions & unique names
  const ruleNames = new Set<string>();
  let hasDuplicateNames = false;
  let hasEmptyConditions = false;

  policy.groups.forEach((g) => {
    g.rules.forEach((r) => {
      if (priorities.has(r.priority)) {
        hasDuplicatePriority = true;
      }
      priorities.add(r.priority);

      if (ruleNames.has(r.name)) {
        hasDuplicateNames = true;
      }
      ruleNames.add(r.name);

      if (r.conditions.length === 0) {
        hasEmptyConditions = true;
      }
    });
  });

  if (hasDuplicatePriority) errors.push("Multiple rules share the same Priority value.");
  if (hasDuplicateNames) errors.push("Rule names must be unique.");
  if (hasEmptyConditions) errors.push("One or more rules have empty conditions.");

  // Check for undefined variables in conditions (basic heuristic)
  const varKeys = new Set(policy.variables.map(v => v.key));
  let hasUndefinedVar = false;
  policy.groups.forEach(g => g.rules.forEach(r => r.conditions.forEach(c => {
    if (typeof c.value === 'string' && c.value.startsWith('${') && c.value.endsWith('}')) {
      const vName = c.value.slice(2, -1);
      if (!varKeys.has(vName)) hasUndefinedVar = true;
    }
  })));
  if (hasUndefinedVar) errors.push("A condition references an undefined Variable.");

  const isValid = errors.length === 0;

  return (
    <div className={`p-4 rounded-lg border flex items-start gap-3 ${
      isValid 
        ? "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20" 
        : "bg-red-50 dark:bg-red-500/10 border-red-200 dark:border-red-500/20"
    }`}>
      {isValid ? (
        <CheckCircle2 className="w-5 h-5 text-emerald-500 shrink-0" />
      ) : (
        <AlertCircle className="w-5 h-5 text-red-500 shrink-0" />
      )}
      
      <div>
        <h4 className={`text-sm font-semibold mb-1 ${isValid ? "text-emerald-800 dark:text-emerald-400" : "text-red-800 dark:text-red-400"}`}>
          {isValid ? "Policy Valid" : "Validation Errors"}
        </h4>
        {isValid ? (
          <p className="text-xs text-emerald-700 dark:text-emerald-500">
            AST looks good. Priorities are unique and conditions are well-formed.
          </p>
        ) : (
          <ul className="text-xs text-red-700 dark:text-red-400 list-disc pl-4 space-y-1">
            {errors.map((e, i) => (
              <li key={i}>{e}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
