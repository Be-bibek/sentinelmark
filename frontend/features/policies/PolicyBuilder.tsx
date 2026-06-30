"use client";

import React, { useState, useEffect } from "react";
import { PolicyDraft, RuleGroup } from "./types";
import { Plus, Search, Layers } from "lucide-react";
import PolicyHeader from "./PolicyHeader";
import VariablesEditor from "./VariablesEditor";
import ValidationPanel from "./ValidationPanel";
import RuleCard from "./RuleCard";
import JsonPreview from "./JsonPreview";
import SimulationModal from "./SimulationModal";

const DEFAULT_POLICY: PolicyDraft = {
  id: "00000000-0000-0000-0000-000000000000",
  name: "Production Security Policy",
  status: "draft",
  version: 3,
  variables: [
    { id: "1", key: "HIGH_RISK_THRESHOLD", value: "0.85" },
  ],
  groups: [
    {
      id: "group-1",
      name: "Fraud Prevention",
      rules: [
        {
          id: "rule-1",
          name: "Block High Risk Geo",
          priority: 100,
          enabled: true,
          action: "BLOCK",
          conditionType: "AND",
          conditions: [
            { id: "c1", field: "trust.risk_score", operator: ">", value: "${HIGH_RISK_THRESHOLD}" },
            { id: "c2", field: "context.country", operator: "IN", value: "[\"RU\", \"KP\"]" }
          ]
        }
      ]
    }
  ]
};

export default function PolicyBuilder() {
  const [policy, setPolicy] = useState<PolicyDraft>(DEFAULT_POLICY);
  const [searchQuery, setSearchQuery] = useState("");
  const [isSimModalOpen, setIsSimModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  // Simulate API load
  useEffect(() => {
    const loadPolicy = async () => {
      // try { const res = await fetch("/api/v1/projects/.../policies"); ... }
      // Mocking latency for MVP
      setTimeout(() => {
        setPolicy(DEFAULT_POLICY);
        setLoading(false);
      }, 500);
    };
    loadPolicy();
  }, []);

  const handleSave = async () => {
    // try { await fetch("/api/v1/projects/.../policies", { method: "POST", body: ... }); }
    console.log("Saving draft...", policy);
    alert("Draft saved locally!");
  };

  const handlePublish = async () => {
    console.log("Publishing...", policy);
    alert("Policy published successfully!");
  };

  const addRuleGroup = () => {
    setPolicy({
      ...policy,
      groups: [
        ...policy.groups,
        { id: crypto.randomUUID(), name: "New Rule Group", rules: [] }
      ]
    });
  };

  const updateGroup = (groupId: string, updates: Partial<RuleGroup>) => {
    setPolicy({
      ...policy,
      groups: policy.groups.map(g => g.id === groupId ? { ...g, ...updates } : g)
    });
  };

  const addRuleToGroup = (groupId: string) => {
    setPolicy({
      ...policy,
      groups: policy.groups.map(g => {
        if (g.id === groupId) {
          return {
            ...g,
            rules: [
              ...g.rules,
              {
                id: crypto.randomUUID(),
                name: "New Rule",
                priority: 10,
                enabled: true,
                action: "ALLOW",
                conditionType: "AND",
                conditions: []
              }
            ]
          };
        }
        return g;
      })
    });
  };

  if (loading) {
    return <div className="h-64 flex items-center justify-center text-zinc-500 animate-pulse">Loading Policy Engine...</div>;
  }

  // Filter logic
  const filteredGroups = policy.groups.map(g => ({
    ...g,
    rules: g.rules.filter(r => 
      r.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
      r.action.toLowerCase().includes(searchQuery.toLowerCase())
    )
  })).filter(g => g.rules.length > 0 || g.name.toLowerCase().includes(searchQuery.toLowerCase()));

  return (
    <div className="space-y-6 pb-20">
      <PolicyHeader 
        policy={policy} 
        onUpdate={setPolicy} 
        onSave={handleSave} 
        onPublish={handlePublish}
        onSimulate={() => setIsSimModalOpen(true)}
      />

      <ValidationPanel policy={policy} />

      <VariablesEditor 
        variables={policy.variables} 
        onChange={(vars) => setPolicy({ ...policy, variables: vars })}
      />

      {/* Global Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
        <input
          type="text"
          placeholder="Search rules by name, tag, action..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="ui-input pl-10 py-3 w-full"
        />
      </div>

      {/* Rule Groups */}
      <div className="space-y-6">
        {filteredGroups.map(group => (
          <div key={group.id} className="bg-white dark:bg-[#0A0A0A] rounded-xl border border-zinc-200 dark:border-white/5 overflow-hidden shadow-sm">
            <div className="flex items-center justify-between p-4 bg-zinc-50 dark:bg-white/5 border-b border-zinc-200 dark:border-white/5">
              <div className="flex items-center gap-3">
                <Layers className="w-5 h-5 text-blue-500" />
                <input 
                  type="text"
                  value={group.name}
                  onChange={(e) => updateGroup(group.id, { name: e.target.value })}
                  className="font-bold text-lg bg-transparent border-none outline-none focus:ring-0 px-0"
                />
              </div>
              <button 
                onClick={() => addRuleToGroup(group.id)}
                className="flex items-center gap-2 px-3 py-1.5 text-xs font-semibold bg-white dark:bg-black hover:bg-zinc-100 dark:hover:bg-white/10 border border-zinc-200 dark:border-white/10 rounded-md transition-colors"
              >
                <Plus className="w-4 h-4" />
                Add Rule
              </button>
            </div>
            
            <div className="p-4 space-y-4 bg-zinc-50/50 dark:bg-black/20">
              {group.rules.length === 0 ? (
                <div className="text-center py-8 text-sm text-zinc-500 border border-dashed border-zinc-300 dark:border-zinc-800 rounded-lg">
                  No rules in this group.
                </div>
              ) : (
                group.rules.map(rule => (
                  <RuleCard 
                    key={rule.id}
                    rule={rule}
                    onChange={(updatedRule) => {
                      updateGroup(group.id, {
                        rules: group.rules.map(r => r.id === rule.id ? updatedRule : r)
                      });
                    }}
                    onDelete={() => {
                      updateGroup(group.id, {
                        rules: group.rules.filter(r => r.id !== rule.id)
                      });
                    }}
                  />
                ))
              )}
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={addRuleGroup}
        className="w-full py-4 border-2 border-dashed border-zinc-300 dark:border-zinc-800 text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 hover:border-zinc-400 dark:hover:border-zinc-600 rounded-xl font-semibold transition-colors flex items-center justify-center gap-2"
      >
        <Plus className="w-5 h-5" />
        Create New Rule Group
      </button>

      <JsonPreview policy={policy} onUpdate={setPolicy} />
      <SimulationModal isOpen={isSimModalOpen} onClose={() => setIsSimModalOpen(false)} policy={policy} />
    </div>
  );
}
