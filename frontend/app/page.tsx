"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  Settings,
  Users,
  Grid,
  MapPin,
  Clock,
  Terminal,
  Activity,
  User,
  ExternalLink,
  ChevronRight,
  Menu,
  Fingerprint,
  Binary,
  Sliders,
  FileSignature,
  ArrowRight,
  Lock,
  BookOpen,
  Cpu,
  Workflow,
  Sparkles,
  Info,
  Layers,
  ArrowLeft,
  Sun,
  Moon
} from "lucide-react";

import ParticleBackground from "@/components/ParticleBackground";
import KPICards from "@/components/KPICards";
import TrustTimelineChart from "@/components/TrustTimelineChart";
import BehaviorProfile from "@/components/BehaviorProfile";
import ThreatHeatmap from "@/components/ThreatHeatmap";
import AttackReplay from "@/components/AttackReplay";
import TelemetryFeed from "@/components/TelemetryFeed";
import AuditLedger from "@/components/AuditLedger";
import TrustScoreCenterpiece from "@/components/TrustScoreCenterpiece";
import Strands from "@/components/Strands";
import { useMetrics, useBehaviorProfile, useAuditLogs } from "@/hooks/use-queries";
import { SentinelAPI } from "@/lib/api";
import { toast } from "sonner";

type PolicyState = "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";

interface LogEntry {
  id: string;
  timestamp: Date;
  event: string;
  type: "info" | "warning" | "error" | "success";
  source: string;
}

interface AuditRecord {
  id: string;
  timestamp: Date;
  user: string;
  trustScore: number;
  anomalies: string[];
  decision: PolicyState;
}

const threatScenarios = [
  { id: "NEW_DEVICE", label: "New Device Login 👤", color: "bg-amber-500", glow: "hover:shadow-[0_0_15px_rgba(245,158,11,0.25)]" },
  { id: "IMPOSSIBLE_TRAVEL", label: "Impossible Travel ✈️", color: "bg-orange-500", glow: "hover:shadow-[0_0_15px_rgba(249,115,22,0.25)]" },
  { id: "BRUTE_FORCE", label: "Brute Force Attempt ⚔️", color: "bg-red-500", glow: "hover:shadow-[0_0_15px_rgba(239,68,68,0.25)]" },
  { id: "API_LEAK", label: "API Key Leakage 🔑", color: "bg-red-500", glow: "hover:shadow-[0_0_15px_rgba(239,68,68,0.25)]" },
  { id: "RESET", label: "Normal Access Sync 🔄", color: "bg-emerald-500", glow: "hover:shadow-[0_0_15px_rgba(16,185,129,0.25)]" },
];

export default function Page() {
  // Page Navigation State
  const [currentView, setCurrentView] = useState<"landing" | "console">("landing");
  
  // Theme State
  const [theme, setTheme] = useState<"light" | "dark">("dark");

  // Console state
  const [policy, setPolicy] = useState<PolicyState>("ALLOW");
  const [score, setScore] = useState(98);
  const [anomalies, setAnomalies] = useState<string[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [scoreHistory, setScoreHistory] = useState<Array<{ timestamp: Date; score: number }>>([]);
  const [activeTab, setActiveTab] = useState("ops");

  // Interactive story-popup states
  const [activeBentoCard, setActiveBentoCard] = useState<string | null>(null);
  const [showArchModel, setShowArchModel] = useState(false);

  // --- Real Backend Integration (React Query) ---
  const { data: metrics } = useMetrics();
  const { data: behavior } = useBehaviorProfile("dev.ops@enterprise.com");
  const { data: auditData } = useAuditLogs();

  // Sync real backend data to UI state where possible, fallback to local state for fast UI updates
  useEffect(() => {
    if (behavior) {
      setScore(behavior.trust_score);
    }
  }, [behavior]);

  useEffect(() => {
    if (auditData?.records?.length) {
      // Map API audit records to UI audit records
      const mapped = auditData.records.map((r: any) => ({
        id: r.id,
        timestamp: new Date(r.timestamp),
        user: r.user_id,
        trustScore: r.trust_score,
        anomalies: r.anomalies || [],
        decision: r.decision as PolicyState,
      }));
      setAuditRecords(mapped);
    }
  }, [auditData]);

  const isDark = theme === "dark";

  // Initial Seed
  useEffect(() => {
    const initialLogs: LogEntry[] = [
      { id: "1", timestamp: new Date(Date.now() - 30000), event: "IAM session token validated successfully", type: "success", source: "Auth Engine" },
      { id: "2", timestamp: new Date(Date.now() - 25000), event: "Ingress sync stream initiated", type: "info", source: "API Gateway" },
      { id: "3", timestamp: new Date(Date.now() - 20000), event: "Device fingerprinting module active", type: "info", source: "Agent-02" },
    ];
    setLogs(initialLogs);

    const initialAudits: AuditRecord[] = [
      { id: "aud-1", timestamp: new Date(Date.now() - 15000), user: "alice.security@enterprise.com", trustScore: 98, anomalies: [], decision: "ALLOW" },
      { id: "aud-2", timestamp: new Date(Date.now() - 10000), user: "bob.admin@enterprise.com", trustScore: 96, anomalies: [], decision: "ALLOW" },
    ];
    setAuditRecords(initialAudits);

    // Initial timeline
    const history = Array.from({ length: 15 }, (_, i) => ({
      timestamp: new Date(Date.now() - (15 - i) * 60000),
      score: 95 + Math.floor(Math.random() * 4),
    }));
    setScoreHistory(history);
  }, []);

  // Periodic Logs generator
  useEffect(() => {
    const interval = setInterval(() => {
      const sources = ["Auth Engine", "API Gateway", "Agent-02", "WAF Edge", "Cognitive Model"];
      const events = [
        "Continuous behavioral sync completed",
        "Encrypted socket heartbeat confirmed",
        "Ingress packet signature verification pass",
        "API read access granted: Audit Log Data",
        "Identity authorization status recheck",
      ];
      const randomSource = sources[Math.floor(Math.random() * sources.length)];
      const randomEvent = events[Math.floor(Math.random() * events.length)];

      const newLog: LogEntry = {
        id: Math.random().toString(),
        timestamp: new Date(),
        event: randomEvent,
        type: "info",
        source: randomSource,
      };

      setLogs((prev) => [newLog, ...prev.slice(0, 20)]);
    }, 7000);

    return () => clearInterval(interval);
  }, []);

  const triggerScenario = async (scenarioId: string) => {
    const timestamp = new Date();
    const mockIp = `192.168.1.${Math.floor(Math.random() * 255)}`;
    let newScore = 98;
    let newPolicy: PolicyState = "ALLOW";
    let newAnomaliesList: string[] = [];
    let logEvent = "";
    let logType: "info" | "warning" | "error" | "success" = "info";

    switch (scenarioId) {
      case "NEW_DEVICE":
        newScore = 65;
        newPolicy = "MFA";
        newAnomaliesList = ["NEW_DEVICE_LOGIN"];
        logEvent = "MFA Challenge Enforced: Access attempt from unknown device browser fingerprint.";
        logType = "warning";
        break;
      case "IMPOSSIBLE_TRAVEL":
        newScore = 40;
        newPolicy = "MULTI-SIG";
        newAnomaliesList = ["IMPOSSIBLE_TRAVEL_SPEED"];
        logEvent = "Multi-Signature Authorization Requested: Double login velocity vector mismatch.";
        logType = "warning";
        break;
      case "BRUTE_FORCE":
        newScore = 15;
        newPolicy = "BLOCK";
        newAnomaliesList = ["CREDENTIAL_STUFFING", "VELOCITY_EXCEEDED"];
        logEvent = "Security Interdiction Active: Heavy brute force velocity signature blocked.";
        logType = "error";
        break;
      case "API_LEAK":
        newScore = 5;
        newPolicy = "BLOCK";
        newAnomaliesList = ["API_TOKEN_EXPOSED"];
        logEvent = "Automated Access Revocation: Private API token exposed in open public repository.";
        logType = "error";
        break;
      case "RESET":
      default:
        newScore = 98;
        newPolicy = "ALLOW";
        newAnomaliesList = [];
        logEvent = "Operational Status Restored: Administrative reset & behavioral baseline reset.";
        logType = "success";
        break;
    }

    try {
      // Call actual Rust backend
      const response = await SentinelAPI.evaluate({
        user_id: "dev.ops@enterprise.com",
        event: {
          action_type: scenarioId,
          ip_address: mockIp,
        }
      });
      
      // Override local prediction with REAL backend decision
      newScore = response.trust_score;
      newPolicy = response.decision as PolicyState;
      newAnomaliesList = response.risk_factors || newAnomaliesList;
      
      toast.success(`Evaluated by Axum Backend`, {
        description: `Score: ${newScore} | Decision: ${newPolicy}`
      });
    } catch (e) {
      console.error("Backend evaluation failed", e);
      // Fallback to local prediction handled above
    }

    setScore(newScore);
    setPolicy(newPolicy);
    setAnomalies(newAnomaliesList);

    // Append to logs
    const triggerLog: LogEntry = {
      id: Math.random().toString(),
      timestamp,
      event: logEvent,
      type: logType,
      source: "IAM Controller",
    };
    setLogs((prev) => [triggerLog, ...prev]);

    // Append to audit ledger
    const newAudit: AuditRecord = {
      id: `aud-${Math.random()}`,
      timestamp,
      user: "dev.ops@enterprise.com",
      trustScore: newScore,
      anomalies: newAnomaliesList,
      decision: newPolicy,
    };
    setAuditRecords((prev) => [newAudit, ...prev]);

    // Update history
    setScoreHistory((prev) => [...prev, { timestamp, score: newScore }].slice(-20));
  };

  const threatList = [
    { id: "t1", name: "Malicious Packet Flood", type: "DDoS Ingress Vector", location: "Frankfurt, DE", coordinates: [8.6821, 50.1109] as [number, number], severity: "high" as const },
    { id: "t2", name: "Exposed Access Key", type: "Auth Key Exposure", location: "San Francisco, US", coordinates: [-122.4194, 37.7749] as [number, number], severity: "critical" as const },
    { id: "t3", name: "Behavioral Speed Anomaly", type: "Geographic Velocity Drift", location: "Hong Kong, HK", coordinates: [114.1694, 22.3193] as [number, number], severity: "medium" as const },
    { id: "t4", name: "Brute Force Node", type: "SSH Dictionary Attack", location: "Reykjavik, IS", coordinates: [-21.8277, 64.1265] as [number, number], severity: "low" as const },
  ];

  return (
    <div className={`min-h-screen font-sans overflow-x-hidden flex relative transition-colors duration-500 ${
      isDark 
        ? "bg-[#030303] text-zinc-100 selection:bg-blue-500/20" 
        : "bg-[#FAFAFA] text-zinc-800 selection:bg-blue-500/10"
    }`}>
      {/* Dynamic Background */}
      <ParticleBackground policyState={currentView === "landing" ? "ALLOW" : policy} theme={theme} />
      
      {/* Background Particles */}
      <div className="absolute inset-0 z-0 opacity-30 pointer-events-none">
        <Strands 
          colors={["#F97316", "#7C3AED", "#06B6D4"]}
          count={2}
          speed={0.5}
        />
      </div>

      <AnimatePresence mode="wait">
        {currentView === "landing" ? (
          /* ================= LANDING VIEW (SentinelMark TrustOS) ================= */
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="flex-1 flex flex-col relative z-10 w-full"
          >
            {/* Sticky Header */}
            <header className={`sticky top-0 z-50 h-16 border-b backdrop-blur-xl px-6 md:px-12 flex items-center justify-between transition-all duration-300 ${
              isDark 
                ? "border-white/5 bg-black/45 text-white" 
                : "border-zinc-200/80 bg-white/75 text-zinc-800 shadow-[0_2px_12px_rgba(0,0,0,0.02)]"
            }`}>
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                  <Shield className="w-4.5 h-4.5 text-zinc-100" />
                </div>
                <div>
                  <h1 className={`text-sm font-extrabold tracking-tight flex items-center gap-1.5 font-mono ${
                    isDark ? "text-white" : "text-zinc-900"
                  }`}>
                    SENTINELMARK
                  </h1>
                  <span className="text-[8px] font-bold text-blue-400 tracking-widest block -mt-0.5">TRUSTOS</span>
                </div>
              </div>

              {/* Minimalist Middle Navigation Links */}
              <nav className={`hidden md:flex items-center gap-6 text-[11px] font-mono tracking-wider transition-colors ${
                isDark ? "text-zinc-400" : "text-zinc-600"
              }`}>
                <a href="#core-metrics" className="hover:text-blue-500 transition-colors">METRICS</a>
                <a href="#bento-story" className="hover:text-blue-500 transition-colors">CORE ENGINE</a>
                <span className={isDark ? "text-zinc-800" : "text-zinc-200"}>|</span>
                <span className="text-zinc-500 flex items-center gap-1 font-semibold">
                  <Sparkles className="w-3 h-3 text-emerald-500" />
                  Deterministic Policy
                </span>
              </nav>

              {/* Header Right Buttons */}
              <div className="flex items-center gap-4">
                {/* Theme Toggle */}
                <button
                  onClick={() => setTheme(isDark ? "light" : "dark")}
                  className={`p-2 rounded-xl border transition-all duration-300 cursor-pointer ${
                    isDark
                      ? "bg-white/5 border-white/10 text-zinc-300 hover:bg-white/10"
                      : "bg-white border-zinc-200 text-zinc-700 hover:bg-zinc-100 shadow-[0_2px_8px_rgba(0,0,0,0.04)]"
                  }`}
                  aria-label="Toggle theme"
                >
                  {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-blue-600" />}
                </button>

                <motion.button
                  whileHover={{ scale: 1.03, boxShadow: "0 0 15px rgba(59,130,246,0.2)" }}
                  whileTap={{ scale: 0.97 }}
                  onClick={() => setCurrentView("console")}
                  className="px-4 py-1.5 rounded-xl bg-blue-600 text-zinc-100 font-bold text-xs tracking-wide flex items-center gap-1.5 hover:bg-blue-500 transition-all cursor-pointer"
                >
                  Launch SOC Console 🖥️
                  <ArrowRight className="w-3.5 h-3.5" />
                </motion.button>
              </div>
            </header>

            {/* Hero Section Container */}
            <section className="relative px-6 md:px-12 py-16 md:py-24 max-w-7xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
              {/* Left Column Text details */}
              <div className="lg:col-span-7 flex flex-col items-start gap-6">
                <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border ${
                  isDark 
                    ? "bg-blue-500/10 border-blue-500/20 text-blue-400" 
                    : "bg-blue-50 border-blue-200 text-blue-700"
                }`}>
                  <Layers className="w-3.5 h-3.5" />
                  <span className="text-[10px] font-mono uppercase tracking-widest font-bold">
                    Continuous Zero-Trust Framework
                  </span>
                </div>

                <h1 className={`text-4xl md:text-6xl font-bold tracking-tight leading-[1.1] max-w-2xl ${
                  isDark ? "text-white" : "text-zinc-950"
                }`}>
                  Identity isn't static.<br />
                  <span className="bg-gradient-to-r from-blue-500 via-zinc-400 to-emerald-500 bg-clip-text text-transparent">
                    Trust shouldn't be either.
                  </span>
                </h1>

                <p className={`text-sm md:text-base leading-relaxed max-w-xl ${
                  isDark ? "text-zinc-400" : "text-zinc-600"
                }`}>
                  SentinelMark is a deterministic, Rust-powered continuous trust engine. 
                  By evaluating raw telemetry and cognitive behavioral signatures at the edge, 
                  we actively block session hijacks and credential theft 
                  <span className={isDark ? "text-blue-400 font-semibold" : "text-blue-600 font-semibold"}> before they can execute.</span>
                </p>

                {/* Call To Actions */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 w-full sm:w-auto mt-2">
                  <motion.button
                    whileHover={{ scale: 1.03, y: -1 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={() => setCurrentView("console")}
                    className="px-6 py-3 rounded-xl bg-blue-600 text-white font-bold text-sm tracking-wide shadow-lg shadow-blue-500/10 hover:bg-blue-500 transition-all text-center cursor-pointer flex items-center justify-center gap-2"
                  >
                    Start Live Demo ⚡
                  </motion.button>

                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={() => setShowArchModel(!showArchModel)}
                    className={`px-6 py-3 rounded-xl border font-semibold text-sm transition-all text-center cursor-pointer flex items-center justify-center gap-2 ${
                      isDark 
                        ? "bg-zinc-900 border-white/5 text-zinc-300 hover:bg-zinc-800" 
                        : "bg-white border-zinc-200 text-zinc-700 hover:bg-zinc-50 shadow-sm"
                    }`}
                  >
                    View Architecture 🗺️
                  </motion.button>
                </div>
              </div>

              {/* Right Column floating score centerpiece */}
              <div className="lg:col-span-5 flex justify-center items-center">
                <motion.div
                  animate={{ y: [0, -8, 0] }}
                  transition={{ duration: 6, repeat: Infinity, ease: "easeInOut" }}
                  className="w-full max-w-sm"
                >
                  <TrustScoreCenterpiece theme={theme} />
                </motion.div>
              </div>
            </section>

            {/* Architecture Slide-out / Accordion Block */}
            <AnimatePresence>
              {showArchModel && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="w-full max-w-5xl mx-auto px-6 overflow-hidden mb-12"
                >
                  <div className={`p-6 border rounded-[24px] ${
                    isDark 
                      ? "bg-[#0c0c0e]/90 border-white/5" 
                      : "bg-white border-zinc-200 shadow-[0_10px_30px_rgba(0,0,0,0.04)]"
                  }`}>
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <h3 className={`text-xs font-bold uppercase tracking-wider font-mono ${
                          isDark ? "text-blue-400" : "text-blue-600"
                        }`}>
                          SentinelMark Pipeline Flow Architecture ⚙️
                        </h3>
                        <p className={`text-[10px] mt-0.5 font-mono uppercase ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>DETERMINISTIC EVALUATION DIRECTED AT THE EDGE</p>
                      </div>
                      <button 
                        onClick={() => setShowArchModel(false)}
                        className={`text-xs font-mono font-bold cursor-pointer ${
                          isDark ? "text-zinc-500 hover:text-zinc-300" : "text-zinc-400 hover:text-zinc-700"
                        }`}
                      >
                        [ CLOSE ✕ ]
                      </button>
                    </div>

                    {/* Flow graph mockup using standard CSS */}
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-center">
                      <div className={`p-4 border rounded-xl text-center ${
                        isDark ? "bg-zinc-900/50 border-white/5" : "bg-zinc-50 border-zinc-200"
                      }`}>
                        <div className={`text-xs font-bold ${isDark ? "text-zinc-300" : "text-zinc-800"}`}>1. Raw Telemetry Ingress</div>
                        <p className={`text-[9px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Socks, TLS fingerprints, keyboard cadence.</p>
                      </div>
                      <div className="text-center text-zinc-400 font-bold hidden md:block">──▶</div>
                      <div className={`p-4 border rounded-xl text-center ${
                        isDark ? "bg-zinc-900/50 border-white/5" : "bg-zinc-50 border-zinc-200"
                      }`}>
                        <div className={`text-xs font-bold ${isDark ? "text-zinc-300" : "text-zinc-800"}`}>2. Deterministic Risk Parsing</div>
                        <p className={`text-[9px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Mathematical deviation calculation in Rust.</p>
                      </div>
                      <div className="text-center text-zinc-400 font-bold hidden md:block">──▶</div>
                      <div className={`p-4 border rounded-xl text-center ${
                        isDark ? "bg-zinc-900/50 border-white/5" : "bg-zinc-50 border-zinc-200"
                      }`}>
                        <div className={`text-xs font-bold ${isDark ? "text-zinc-300" : "text-zinc-800"}`}>3. Policy Gatekeeping</div>
                        <p className={`text-[9px] mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Enforce strict dynamic security thresholds.</p>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Metrics Bar */}
            <section id="core-metrics" className={`w-full py-10 my-8 border-y ${
              isDark 
                ? "bg-zinc-950/25 border-white/5" 
                : "bg-zinc-100/40 border-zinc-200/80"
            }`}>
              <div className="max-w-7xl mx-auto px-6 md:px-12 grid grid-cols-1 md:grid-cols-3 gap-8">
                {/* Metric 1 */}
                <div className="text-center md:text-left flex flex-col justify-center">
                  <span className={`text-3xl font-extrabold tracking-tight font-sans ${isDark ? "text-white" : "text-zinc-900"}`}>
                    Sub-10ms
                  </span>
                  <span className={`text-[10px] font-mono uppercase tracking-widest mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                    Evaluation Latency
                  </span>
                </div>
                {/* Metric 2 */}
                <div className={`text-center md:text-left flex flex-col justify-center border-t md:border-t-0 md:border-x pt-6 md:pt-0 md:px-12 ${
                  isDark ? "border-white/5" : "border-zinc-200"
                }`}>
                  <span className={`text-3xl font-extrabold tracking-tight font-sans ${isDark ? "text-blue-400" : "text-blue-600"}`}>
                    100%
                  </span>
                  <span className={`text-[10px] font-mono uppercase tracking-widest mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                    Deterministic Rust Engine
                  </span>
                </div>
                {/* Metric 3 */}
                <div className={`text-center md:text-left flex flex-col justify-center border-t md:border-t-0 pt-6 md:pt-0 ${
                  isDark ? "" : "border-zinc-200"
                }`}>
                  <span className={`text-3xl font-extrabold tracking-tight font-sans ${isDark ? "text-emerald-400" : "text-emerald-600"}`}>
                    0
                  </span>
                  <span className={`text-[10px] font-mono uppercase tracking-widest mt-1 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                    Core System Dependencies
                  </span>
                </div>
              </div>
            </section>

            {/* Bento Grid Storytelling Section */}
            <section id="bento-story" className="max-w-7xl mx-auto w-full px-6 md:px-12 py-16">
              <div className="mb-12 text-center md:text-left">
                <h2 className={`text-xs font-bold uppercase tracking-widest font-mono ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                  Engine Modules ⚙️
                </h2>
                <p className={`text-xl md:text-2xl font-bold mt-1.5 ${isDark ? "text-white" : "text-zinc-950"}`}>
                  Four core processes. One unified security envelope.
                </p>
              </div>

              {/* Grid block */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                {/* Card 1: Behavior Engine */}
                <motion.div
                  whileHover={{ y: -2, borderColor: "rgba(59, 130, 246, 0.25)", boxShadow: "0 10px 30px -5px rgba(59, 130, 246, 0.1)" }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setActiveBentoCard(activeBentoCard === "behavior" ? null : "behavior")}
                  className={`p-6 border rounded-[24px] flex flex-col justify-between h-[220px] transition-all duration-300 cursor-pointer group ${
                    isDark 
                      ? "bg-zinc-950/45 border-white/5 text-zinc-100" 
                      : "bg-white border-zinc-200 text-zinc-800 shadow-[0_4px_16px_rgba(0,0,0,0.02)]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                      <Fingerprint className="w-5 h-5" />
                    </div>
                    <span className="text-[14px] font-mono">👤</span>
                  </div>
                  <div>
                    <h3 className={`text-xs font-bold uppercase tracking-wide font-sans group-hover:text-blue-500 transition-colors ${
                      isDark ? "text-zinc-200" : "text-zinc-800"
                    }`}>
                      Behavior Engine
                    </h3>
                    <p className={`text-[11px] mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                      Establishes baseline profiles using device fingerprinting and workflow sequencing.
                    </p>
                  </div>
                </motion.div>

                {/* Card 2: Risk Engine */}
                <motion.div
                  whileHover={{ y: -2, borderColor: "rgba(16, 185, 129, 0.25)", boxShadow: "0 10px 30px -5px rgba(16, 185, 129, 0.1)" }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setActiveBentoCard(activeBentoCard === "risk" ? null : "risk")}
                  className={`p-6 border rounded-[24px] flex flex-col justify-between h-[220px] transition-all duration-300 cursor-pointer group ${
                    isDark 
                      ? "bg-zinc-950/45 border-white/5 text-zinc-100" 
                      : "bg-white border-zinc-200 text-zinc-800 shadow-[0_4px_16px_rgba(0,0,0,0.02)]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                      <Binary className="w-5 h-5" />
                    </div>
                    <span className="text-[14px] font-mono">🧮</span>
                  </div>
                  <div>
                    <h3 className={`text-xs font-bold uppercase tracking-wide font-sans group-hover:text-emerald-500 transition-colors ${
                      isDark ? "text-zinc-200" : "text-zinc-800"
                    }`}>
                      Risk Engine
                    </h3>
                    <p className={`text-[11px] mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                      Calculates mathematical deviations from normal behavior without unpredictable AI.
                    </p>
                  </div>
                </motion.div>

                {/* Card 3: Policy Engine */}
                <motion.div
                  whileHover={{ y: -2, borderColor: "rgba(245, 158, 11, 0.25)", boxShadow: "0 10px 30px -5px rgba(245, 158, 11, 0.1)" }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setActiveBentoCard(activeBentoCard === "policy" ? null : "policy")}
                  className={`p-6 border rounded-[24px] flex flex-col justify-between h-[220px] transition-all duration-300 cursor-pointer group ${
                    isDark 
                      ? "bg-zinc-950/45 border-white/5 text-zinc-100" 
                      : "bg-white border-zinc-200 text-zinc-800 shadow-[0_4px_16px_rgba(0,0,0,0.02)]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                      <Sliders className="w-5 h-5" />
                    </div>
                    <span className="text-[14px] font-mono">⚡</span>
                  </div>
                  <div>
                    <h3 className={`text-xs font-bold uppercase tracking-wide font-sans group-hover:text-amber-500 transition-colors ${
                      isDark ? "text-zinc-200" : "text-zinc-800"
                    }`}>
                      Policy Engine
                    </h3>
                    <p className={`text-[11px] mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                      Enforces strict access thresholds dynamically based on session confidence.
                    </p>
                  </div>
                </motion.div>

                {/* Card 4: Explainability Engine */}
                <motion.div
                  whileHover={{ y: -2, borderColor: "rgba(168, 85, 247, 0.25)", boxShadow: "0 10px 30px -5px rgba(168, 85, 247, 0.1)" }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => setActiveBentoCard(activeBentoCard === "explain" ? null : "explain")}
                  className={`p-6 border rounded-[24px] flex flex-col justify-between h-[220px] transition-all duration-300 cursor-pointer group ${
                    isDark 
                      ? "bg-zinc-950/45 border-white/5 text-zinc-100" 
                      : "bg-white border-zinc-200 text-zinc-800 shadow-[0_4px_16px_rgba(0,0,0,0.02)]"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                      <FileSignature className="w-5 h-5" />
                    </div>
                    <span className="text-[14px] font-mono">📜</span>
                  </div>
                  <div>
                    <h3 className={`text-xs font-bold uppercase tracking-wide font-sans group-hover:text-purple-500 transition-colors ${
                      isDark ? "text-zinc-200" : "text-zinc-800"
                    }`}>
                      Explainability Engine
                    </h3>
                    <p className={`text-[11px] mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                      Generates human-readable compliance narratives for enterprise SOC audits.
                    </p>
                  </div>
                </motion.div>
              </div>

              {/* Dynamic narrative overlay/story segment based on clicked Bento card */}
              <AnimatePresence>
                {activeBentoCard && (
                  <motion.div
                    initial={{ opacity: 0, y: 15 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 15 }}
                    className={`mt-8 p-6 border rounded-[24px] ${
                      isDark 
                        ? "bg-zinc-900/40 border-white/5" 
                        : "bg-white border-zinc-200 shadow-md text-zinc-800"
                    }`}
                  >
                    {activeBentoCard === "behavior" && (
                      <div>
                        <span className="text-[9px] font-mono uppercase text-blue-500 font-bold">Telemetry Breakdown 👤</span>
                        <h4 className={`text-sm font-bold mt-1 ${isDark ? "text-white" : "text-zinc-900"}`}>Real-Time Cognitive Fingerprinting</h4>
                        <p className={`text-xs mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                          Rather than simple IP addresses, the Behavior Engine maps keystroke flight times, mouse acceleration profiles, and workflow sequencing. When a session is hijacked, even if the session cookie is duplicated, the subtle physical interaction changes flag a mismatch within 3 HTTP packets.
                        </p>
                      </div>
                    )}
                    {activeBentoCard === "risk" && (
                      <div>
                        <span className="text-[9px] font-mono uppercase text-emerald-500 font-bold">Mathematical Rigor 🧮</span>
                        <h4 className={`text-sm font-bold mt-1 ${isDark ? "text-white" : "text-zinc-900"}`}>Pure Bayesian Calculation</h4>
                        <p className={`text-xs mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                          The Risk Engine avoids unstable deep-learning models. It calculates mathematical confidence scores directly in memory via an ultra-fast compiled Rust sequence. This delivers completely deterministic and predictable security actions, removing artificial hallucinations or unexpected access denials.
                        </p>
                      </div>
                    )}
                    {activeBentoCard === "policy" && (
                      <div>
                        <span className="text-[9px] font-mono uppercase text-amber-500 font-bold">Active Orchestration ⚡</span>
                        <h4 className={`text-sm font-bold mt-1 ${isDark ? "text-white" : "text-zinc-900"}`}>Adaptive Gates & Steps</h4>
                        <p className={`text-xs mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                          The Policy Engine maps raw risk levels into one of four actions: **ALLOW** (full access), **MFA** (trigger prompt), **MULTI-SIG** (require peer authorization), or **BLOCK** (hard lock). These rules compile to native Rust filters executing in microsecond ranges at edge points.
                        </p>
                      </div>
                    )}
                    {activeBentoCard === "explain" && (
                      <div>
                        <span className="text-[9px] font-mono uppercase text-purple-500 font-bold">Compliance Assurance 📜</span>
                        <h4 className={`text-sm font-bold mt-1 ${isDark ? "text-white" : "text-zinc-900"}`}>Deterministic Compliance Narratives</h4>
                        <p className={`text-xs mt-2 leading-relaxed ${isDark ? "text-zinc-400" : "text-zinc-600"}`}>
                          No black-box answers. For every action taken, the Explainability Engine generates structured, cryptographically signed narrative logs (e.g., *"Session score drifted from 95 to 40 due to speed-vector mismatch of 14,000km/h"*). Perfect for auditing and zero-trust documentation.
                        </p>
                      </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </section>

            {/* Footer with demo teaser */}
            <footer className={`mt-auto py-16 px-6 border-t flex flex-col items-center text-center transition-colors ${
              isDark 
                ? "border-white/5 bg-zinc-950/50" 
                : "border-zinc-200 bg-zinc-100/60"
            }`}>
              <h3 className={`text-lg font-bold ${isDark ? "text-white" : "text-zinc-900"}`}>Experience SentinelMark TrustOS in Action</h3>
              <p className={`text-xs mt-2 max-w-md ${isDark ? "text-zinc-500" : "text-zinc-600"}`}>
                Launch our interactive Security Operations Center (SOC) Console simulation and test real-world attack mitigation.
              </p>
              <motion.button
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
                onClick={() => setCurrentView("console")}
                className="mt-6 px-6 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs tracking-wider cursor-pointer"
              >
                Launch SOC Console 🖥️
              </motion.button>
              <p className={`text-[10px] font-mono mt-8 ${isDark ? "text-zinc-600" : "text-zinc-400"}`}>
                © 2026 SentinelMark & Resq.io. All rights reserved.
              </p>
            </footer>
          </motion.div>
        ) : (
          /* ================= ACTIVE LIVE SOC CONSOLE VIEW ================= */
          <motion.div
            key="console"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.5 }}
            className="flex-1 flex relative h-screen w-full overflow-hidden"
          >
            {/* Sidebar - Resq.io Styling */}
            <aside className={`w-64 border-r flex flex-col z-10 hidden md:flex transition-all duration-300 ${
              isDark 
                ? "bg-black/60 border-white/5 backdrop-blur-xl" 
                : "bg-white border-zinc-200 shadow-md text-zinc-800"
            }`}>
              <div className={`p-6 border-b flex items-center gap-3 ${isDark ? "border-white/5" : "border-zinc-200"}`}>
                <div className="w-8 h-8 bg-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)]">
                  <Shield className="w-4.5 h-4.5 text-zinc-100" />
                </div>
                <div>
                  <h1 className={`text-sm font-bold tracking-tight flex items-center gap-1.5 font-mono ${
                    isDark ? "text-white" : "text-zinc-900"
                  }`}>
                    SENTINELMARK
                  </h1>
                  <span className="text-[8px] font-bold text-blue-400 tracking-wider">SOC PORTAL</span>
                </div>
              </div>

              <nav className="flex-1 p-4 space-y-2.5">
                <button
                  onClick={() => setActiveTab("ops")}
                  className={`w-full flex items-center justify-between px-4 py-3 rounded-xl transition-all duration-300 font-bold text-xs text-left cursor-pointer ${
                    activeTab === "ops"
                      ? isDark 
                        ? "bg-white/5 text-blue-400 border border-white/5 shadow-[0_0_15px_rgba(255,255,255,0.02)]"
                        : "bg-blue-50 text-blue-600 border border-blue-100 shadow-[0_2px_8px_rgba(59,130,246,0.04)]"
                      : isDark
                      ? "text-zinc-400 hover:bg-white/[0.02] hover:text-white"
                      : "text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Grid className="w-4 h-4" />
                    Operations Center 🖥️
                  </div>
                  <ChevronRight className="w-3 h-3 opacity-50" />
                </button>

                <button
                  onClick={() => setActiveTab("behavior")}
                  className={`w-full flex items-center justify-between px-4 py-3 rounded-xl transition-all duration-300 font-bold text-xs text-left cursor-pointer ${
                    activeTab === "behavior"
                      ? isDark 
                        ? "bg-white/5 text-emerald-400 border border-white/5"
                        : "bg-emerald-50 text-emerald-600 border border-emerald-100"
                      : isDark
                      ? "text-zinc-400 hover:bg-white/[0.02] hover:text-white"
                      : "text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Users className="w-4 h-4" />
                    Behavior Profiles 👤
                  </div>
                  <ChevronRight className="w-3 h-3 opacity-50" />
                </button>

                {/* Back to Marketing Page Toggle */}
                <button
                  onClick={() => setCurrentView("landing")}
                  className={`w-full flex items-center justify-between px-4 py-3 rounded-xl transition-all duration-300 font-bold text-xs text-left cursor-pointer ${
                    isDark 
                      ? "text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.01]" 
                      : "text-zinc-500 hover:text-zinc-800 hover:bg-zinc-100/50"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <ArrowLeft className="w-4 h-4" />
                    Product Overview ✕
                  </div>
                  <span className="text-[9px] font-mono opacity-50">ESC</span>
                </button>
              </nav>

              <div className={`p-4 border-t ${isDark ? "border-white/5" : "border-zinc-200"}`}>
                <div className={`flex items-center gap-3 px-3 py-2.5 rounded-xl border ${
                  isDark ? "bg-white/[0.01] border-white/5" : "bg-zinc-50 border-zinc-200/80"
                }`}>
                  <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-xs font-bold text-white shadow-sm">
                    U
                  </div>
                  <div>
                    <div className={`text-xs font-bold ${isDark ? "text-zinc-200" : "text-zinc-800"}`}>User Session</div>
                    <p className={`text-[9px] font-mono mt-0.5 ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>SOC-CONSOLE-MGR</p>
                  </div>
                </div>
              </div>
            </aside>

            {/* Main Content Pane */}
            <main className="flex-1 flex flex-col h-screen z-10 overflow-hidden">
              {/* Header */}
              <header className={`h-[64px] border-b px-6 flex items-center justify-between shrink-0 sticky top-0 transition-colors ${
                isDark 
                  ? "bg-black/40 border-white/5 backdrop-blur-md" 
                  : "bg-white/80 border-zinc-200 backdrop-blur-md shadow-sm"
              }`}>
                <div className="flex items-center gap-3">
                  {/* Back to landing button for mobile screens */}
                  <button 
                    onClick={() => setCurrentView("landing")}
                    className={`p-1.5 rounded-lg border md:hidden transition-colors ${
                      isDark 
                        ? "bg-zinc-900 border-white/5 text-zinc-100 hover:bg-zinc-800" 
                        : "bg-white border-zinc-200 text-zinc-800 hover:bg-zinc-100"
                    }`}
                  >
                    <ArrowLeft className="w-4 h-4" />
                  </button>
                  <h1 className={`text-sm font-bold tracking-tight flex items-center gap-2 ${
                    isDark ? "text-white" : "text-zinc-900"
                  }`}>
                    SentinelMark Trust Operations Center
                  </h1>
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                </div>

                <div className="flex items-center gap-4">
                  {/* Active policy status */}
                  <div className="flex items-center gap-4">
                    <span className={`text-[10px] font-mono uppercase hidden sm:inline ${isDark ? "text-zinc-400" : "text-zinc-500"}`}>Active Policy:</span>
                    <span className={`px-2.5 py-0.5 rounded-full border text-[9px] font-mono uppercase font-extrabold tracking-wide ${
                      policy === "ALLOW" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                      policy === "MFA" ? "bg-amber-500/10 text-amber-400 border-amber-500/20" :
                      policy === "MULTI-SIG" ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                      "bg-red-500/10 text-red-400 border-red-500/20"
                    }`}>
                      {policy}
                    </span>
                  </div>

                  {/* Theme Toggle in console */}
                  <button
                    onClick={() => setTheme(isDark ? "light" : "dark")}
                    className={`p-1.5 rounded-lg border transition-all duration-300 cursor-pointer ${
                      isDark
                        ? "bg-white/5 border-white/10 text-zinc-300 hover:bg-white/10"
                        : "bg-white border-zinc-200 text-zinc-700 hover:bg-zinc-100"
                    }`}
                    aria-label="Toggle theme"
                  >
                    {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-blue-600" />}
                  </button>

                  <div className={`flex items-center gap-2 cursor-pointer transition-colors ${isDark ? "text-zinc-500 hover:text-white" : "text-zinc-400 hover:text-zinc-800"}`}>
                    <Settings className="w-4 h-4" />
                  </div>
                </div>
              </header>

              {/* Dash Content view */}
              <div className="flex-1 overflow-y-auto p-6 space-y-6 no-scrollbar">
                {/* KPI Row */}
                <KPICards score={score} anomaliesCount={anomalies.length} policy={policy} theme={theme} metrics={metrics} />

                {/* Conditional view rendering */}
                {activeTab === "ops" && (
                  <div className="space-y-6">
                    {/* Threat simulation controllers & timeline */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                      <div className={`lg:col-span-1 border rounded-[24px] p-5 flex flex-col justify-between h-[280px] ${
                        isDark 
                          ? "bg-zinc-950/40 border-white/5 text-zinc-100" 
                          : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
                      }`}>
                        <div>
                          <h2 className={`text-xs font-bold uppercase tracking-wider mb-2 flex items-center gap-2 ${
                            isDark ? "text-zinc-400" : "text-zinc-600"
                          }`}>
                            <ShieldCheck className="w-4 h-4 text-blue-500" />
                            Ingress Policy Triggers
                          </h2>
                          <p className={`text-[10px] ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>Inject raw behavioral vectors to test continuous access control.</p>
                        </div>

                        <div className="grid grid-cols-1 gap-2 my-4">
                          {threatScenarios.map((scenario) => (
                            <motion.button
                              key={scenario.id}
                              whileHover={{ scale: 1.02 }}
                              whileTap={{ scale: 0.98 }}
                              onClick={() => triggerScenario(scenario.id)}
                              className={`w-full py-2 px-3 text-left rounded-xl text-[10px] font-mono font-bold tracking-wide border transition-all duration-300 flex items-center gap-2.5 cursor-pointer ${
                                isDark 
                                  ? "border-white/5 bg-white/[0.01] hover:bg-white/[0.03] text-zinc-300" 
                                  : "border-zinc-200 bg-zinc-50 hover:bg-zinc-100/80 text-zinc-700 shadow-sm"
                              } ${scenario.glow}`}
                            >
                              <span className={`w-2 h-2 rounded-full ${scenario.color}`}></span>
                              {scenario.label}
                            </motion.button>
                          ))}
                        </div>
                      </div>

                      <div className="lg:col-span-2">
                        <TrustTimelineChart data={scoreHistory} theme={theme} />
                      </div>
                    </div>

                    {/* World Maps / Playback widgets */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <ThreatHeatmap threats={threatList} theme={theme} />
                      <AttackReplay theme={theme} />
                    </div>

                    {/* Feed Console / Audit tabular logs */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <TelemetryFeed logs={logs} theme={theme} />
                      <AuditLedger records={auditRecords} theme={theme} />
                    </div>
                  </div>
                )}

                {activeTab === "behavior" && (
                  <div className="grid grid-cols-1 gap-6">
                    <BehaviorProfile score={score} theme={theme} profile={behavior} />
                  </div>
                )}
              </div>
            </main>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
