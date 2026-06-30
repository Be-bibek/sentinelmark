import React from "react";
import PolicyBuilder from "@/features/policies/PolicyBuilder";

export default function PoliciesPage() {
  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Trust Policies</h1>
          <p className="text-zinc-500 dark:text-zinc-400">
            Define dynamic rules and variables to enforce trust across your platform.
          </p>
        </div>
      </div>
      <PolicyBuilder />
    </div>
  );
}
