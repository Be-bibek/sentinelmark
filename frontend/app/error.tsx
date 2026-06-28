"use client";

import { useEffect } from "react";
import { ServerCrash, RefreshCcw } from "lucide-react";
import { motion } from "motion/react";
import StarBorder from "@/components/StarBorder";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Dashboard Error:", error);
  }, [error]);

  return (
    <div className="flex h-screen w-full items-center justify-center bg-[#030303] text-zinc-100 p-6">
      <StarBorder as={motion.div} color="rgba(239, 68, 68, 0.4)" className="max-w-md p-8 rounded-[24px] bg-zinc-950 border border-white/5 shadow-2xl flex flex-col items-center text-center">
        <div className="w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mb-6">
          <ServerCrash className="w-8 h-8 text-red-500" />
        </div>
        
        <h2 className="text-xl font-bold tracking-tight mb-2">SOC Dashboard Offline</h2>
        <p className="text-sm text-zinc-400 mb-8 font-mono">
          {error.message || "A critical fault occurred in the Trust Evaluation engine."}
        </p>

        <button
          onClick={() => reset()}
          className="flex items-center gap-2 px-6 py-2.5 bg-zinc-100 text-zinc-900 rounded-full font-bold tracking-wide text-xs uppercase hover:bg-white transition-colors"
        >
          <RefreshCcw className="w-4 h-4" />
          Reboot System
        </button>
      </StarBorder>
    </div>
  );
}
