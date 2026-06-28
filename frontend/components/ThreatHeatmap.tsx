"use client";

import React, { useState } from "react";
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import { motion } from "motion/react";
import { Globe, MapPin, AlertCircle } from "lucide-react";
import StarBorder from "./StarBorder";

// Simplified topojson matching world
const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface ThreatHeatmapProps {
  threats: Array<{
    id: string;
    name: string;
    type: string;
    location: string;
    coordinates: [number, number];
    severity: "low" | "medium" | "high" | "critical";
  }>;
  theme?: "light" | "dark";
}

export default function ThreatHeatmap({ threats, theme = "dark" }: ThreatHeatmapProps) {
  const [selectedThreat, setSelectedThreat] = useState<typeof threats[0] | null>(null);
  const isDark = theme === "dark";

  const getSeverityColor = (sev: string) => {
    switch (sev) {
      case "critical":
        return isDark 
          ? "text-red-400 bg-red-500/10 border-red-500/20" 
          : "text-red-700 bg-red-50 border-red-200";
      case "high":
        return isDark 
          ? "text-orange-400 bg-orange-500/10 border-orange-500/20" 
          : "text-orange-700 bg-orange-50 border-orange-200";
      case "medium":
        return isDark 
          ? "text-amber-400 bg-amber-500/10 border-amber-500/20" 
          : "text-amber-700 bg-amber-50 border-amber-200";
      default:
        return isDark 
          ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" 
          : "text-emerald-700 bg-emerald-50 border-emerald-200";
    }
  };

  const getSeverityMarkerColor = (sev: string) => {
    switch (sev) {
      case "critical":
        return "#ef4444";
      case "high":
        return "#f97316";
      case "medium":
        return "#f59e0b";
      default:
        return "#10b981";
    }
  };

  return (
    <StarBorder
      as={motion.div}
      color={isDark ? "rgba(239, 68, 68, 0.5)" : "rgba(239, 68, 68, 0.8)"}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
      className={`rounded-[24px] p-6 flex flex-col h-[580px] justify-between border ${
        isDark
          ? "bg-zinc-950/40 border-white/5 text-zinc-100"
          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
      }`}
    >
      <div className={`flex items-center justify-between border-b pb-4 mb-4 ${
        isDark ? "border-white/5" : "border-zinc-200"
      }`}>
        <div>
          <h2 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 ${
            isDark ? "text-zinc-400" : "text-zinc-500"
          }`}>
            <Globe className="w-3.5 h-3.5 text-emerald-500" />
            Global Threat Heatmap
          </h2>
          <p className={`text-[10px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
            Real-Time Ingress & IP Geolocation Vector
          </p>
        </div>
        <span className={`text-[10px] font-mono ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
          LIVE HEATMAP ENGINE
        </span>
      </div>

      {/* Map visualizer container */}
      <div className={`flex-1 w-full rounded-2xl border relative overflow-hidden flex items-center justify-center min-h-[220px] ${
        isDark
          ? "bg-zinc-950/40 border-white/5"
          : "bg-zinc-50 border-zinc-200"
      }`}>
        <div className="w-full h-full max-h-[280px]">
          <ComposableMap projectionConfig={{ scale: 135 }}>
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={isDark ? "#18181b" : "#e4e4e7"}
                    stroke={isDark ? "#27272a" : "#d4d4d8"}
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { fill: isDark ? "#27272a" : "#cbd5e1", outline: "none" },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>

            {threats.map((threat) => (
              <Marker
                key={threat.id}
                coordinates={threat.coordinates}
                onClick={() => setSelectedThreat(threat)}
              >
                <circle
                  r={selectedThreat?.id === threat.id ? 6 : 4}
                  fill={getSeverityMarkerColor(threat.severity)}
                  className="cursor-pointer transition-all duration-300"
                />
                <circle
                  r={selectedThreat?.id === threat.id ? 12 : 8}
                  fill="none"
                  stroke={getSeverityMarkerColor(threat.severity)}
                  strokeWidth={1}
                  className="animate-ping cursor-pointer opacity-75"
                />
              </Marker>
            ))}
          </ComposableMap>
        </div>

        {/* Selected marker info panel */}
        {selectedThreat && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className={`absolute bottom-4 left-4 right-4 rounded-xl p-3 flex items-center justify-between border backdrop-blur-md ${
              isDark
                ? "bg-zinc-950/90 border-white/10 text-zinc-100"
                : "bg-white/95 border-zinc-300 shadow-[0_4px_12px_rgba(0,0,0,0.1)] text-zinc-800"
            }`}
          >
            <div className="flex items-center gap-3">
              <MapPin className="w-4 h-4 text-emerald-500" />
              <div>
                <div className={`text-xs font-semibold ${isDark ? "text-zinc-100" : "text-zinc-900"}`}>{selectedThreat.name}</div>
                <div className={`text-[9px] ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>{selectedThreat.location} • {selectedThreat.type}</div>
              </div>
            </div>
            <span className={`text-[9px] uppercase font-mono px-2 py-0.5 rounded border ${getSeverityColor(selectedThreat.severity)}`}>
              {selectedThreat.severity}
            </span>
          </motion.div>
        )}
      </div>

      <div className={`border-t pt-4 mt-4 ${isDark ? "border-white/5" : "border-zinc-200"}`}>
        <h3 className={`text-[10px] font-bold uppercase tracking-wider mb-3 flex items-center gap-1.5 ${
          isDark ? "text-zinc-500" : "text-zinc-400"
        }`}>
          <AlertCircle className="w-3 h-3 text-red-500" />
          Active Ingress Threats
        </h3>
        <div className="grid grid-cols-2 gap-2 max-h-[140px] overflow-y-auto no-scrollbar">
          {threats.map((threat) => (
            <div
              key={threat.id}
              onClick={() => setSelectedThreat(threat)}
              className={`p-3 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                selectedThreat?.id === threat.id
                  ? isDark
                    ? "bg-zinc-900 border-zinc-700 text-white"
                    : "bg-zinc-100 border-zinc-300 text-zinc-900 font-semibold"
                  : isDark
                  ? "bg-white/[0.01] border-white/5 hover:bg-zinc-900/30 text-zinc-300"
                  : "bg-transparent border-zinc-100 hover:bg-zinc-50 text-zinc-700"
              }`}
            >
              <div>
                <div className={`text-xs font-medium ${isDark ? "text-zinc-300" : "text-zinc-800"}`}>{threat.name}</div>
                <div className={`text-[10px] ${isDark ? "text-zinc-500" : "text-zinc-400"} mt-0.5`}>{threat.location}</div>
              </div>
              <span className={`text-[8px] font-mono uppercase px-1.5 py-0.5 rounded border ${getSeverityColor(threat.severity)}`}>
                {threat.severity}
              </span>
            </div>
          ))}
        </div>
      </div>
    </StarBorder>
  );
}
