"use client";

import React, { useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import ParticleBackground from "@/components/ParticleBackground";
import Strands from "@/components/Strands";
import { 
  Shield, 
  Activity, 
  Search, 
  Bell, 
  User, 
  LayoutDashboard,
  Clock,
  Settings,
  Fingerprint,
  FileText,
  Terminal,
  Wifi,
  HeartPulse,
  Sun,
  Moon
} from "lucide-react";
import { useWebSocketStore, initializeWebSocket } from "@/stores/websocket-store";

export default function EnterpriseLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { status, lastPing } = useWebSocketStore();
  const { theme, setTheme } = useTheme();
  const isDark = theme === "dark";
  const currentTheme = (theme === "dark" || theme === "light") ? theme : "dark";

  useEffect(() => {
    initializeWebSocket();
  }, []);

  const navigation = [
    { name: "Dashboard",         href: "/dashboard",     icon: LayoutDashboard },
    { name: "Active Sessions",   href: "/sessions",      icon: Clock },
    { name: "Behavior Profiler", href: "/behavior",      icon: Fingerprint },
    { name: "Explainability",    href: "/explainability", icon: Search },
    { name: "Audit Ledger",      href: "/audit",         icon: FileText },
    { name: "API Explorer",      href: "/api",           icon: Terminal },
    { name: "SDKs & Integrations", href: "/sdk",         icon: Settings },
    { name: "System Health",     href: "/health",        icon: HeartPulse },
  ];

  return (
    <div className={`flex h-screen overflow-hidden font-sans relative transition-colors duration-500 ${
      isDark 
        ? "bg-[#030303] text-zinc-100" 
        : "bg-[#FAFAFA] text-zinc-800"
    }`}>
      {/* Dynamic Backgrounds */}
      <ParticleBackground policyState="ALLOW" theme={currentTheme as "light" | "dark"} />
      <div className="absolute inset-0 z-0 opacity-30 pointer-events-none">
        <Strands colors={["#F97316", "#7C3AED", "#06B6D4"]} count={2} speed={0.5} />
      </div>

      <div className="relative z-10 flex w-full h-full">
      {/* Sidebar */}
      <aside className={`w-64 border-r flex flex-col transition-colors duration-300 ${isDark ? "border-white/5 bg-black/40" : "border-zinc-200/80 bg-white/60 backdrop-blur-xl"}`}>
        <div className={`h-16 flex items-center px-6 border-b transition-colors duration-300 ${isDark ? "border-white/5" : "border-zinc-200"}`}>
          <div className="w-8 h-8 bg-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)] mr-3">
            <Shield className="w-4.5 h-4.5 text-zinc-100" />
          </div>
          <div>
            <h1 className={`text-sm font-extrabold tracking-tight font-mono ${isDark ? "text-white" : "text-zinc-900"}`}>SENTINELMARK</h1>
            <span className="text-[8px] font-bold text-blue-400 tracking-widest block -mt-0.5">TRUSTOS</span>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto py-6 px-3 space-y-1">
          {navigation.map((item) => {
            const isActive = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link 
                key={item.name} 
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-200 ${
                  isActive 
                    ? (isDark ? "bg-blue-600/10 text-blue-400 font-medium" : "bg-blue-50 text-blue-600 font-medium") 
                    : (isDark ? "text-zinc-400 hover:text-zinc-100 hover:bg-white/5" : "text-zinc-500 hover:text-zinc-900 hover:bg-zinc-100")
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? (isDark ? "text-blue-400" : "text-blue-600") : "text-zinc-500"}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>

        <div className={`p-4 border-t ${isDark ? "border-white/5" : "border-zinc-200"}`}>
          <Link href="/settings" className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all ${isDark ? "text-zinc-400 hover:text-zinc-100 hover:bg-white/5" : "text-zinc-500 hover:text-zinc-900 hover:bg-zinc-100"}`}>
            <Settings className="w-4 h-4 text-zinc-500" />
            Settings
          </Link>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Navbar */}
        <header className={`h-16 border-b flex items-center justify-between px-6 backdrop-blur-xl transition-colors duration-300 ${isDark ? "border-white/5 bg-black/20" : "border-zinc-200 bg-white/40"}`}>
          <div className="flex items-center flex-1">
            <div className="relative w-64">
              <Search className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${isDark ? "text-zinc-500" : "text-zinc-400"}`} />
              <input 
                type="text" 
                placeholder="Search events, IP, user..." 
                className="ui-input pl-10"
              />
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            {/* WebSocket Status Indicator */}
            <div className={`hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full border ${isDark ? "bg-white/5 border-white/10" : "bg-white border-zinc-200 shadow-sm"}`}>
              <Wifi className={`w-3.5 h-3.5 ${
                status === 'CONNECTED' ? 'text-emerald-400' :
                status === 'CONNECTING' ? 'text-amber-400 animate-pulse' : 'text-red-400'
              }`} />
              <span className="text-[10px] font-mono tracking-wider text-zinc-400">
                {status}
              </span>
            </div>

            
            <button
              onClick={() => setTheme(isDark ? "light" : "dark")}
              className={`p-2 rounded-full border transition-all duration-300 ${
                isDark
                  ? "bg-white/5 border-white/10 text-zinc-300 hover:bg-white/10"
                  : "bg-white border-zinc-200 text-zinc-500 hover:bg-zinc-100"
              }`}
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-blue-600" />}
            </button>

            <button className={`p-2 transition-colors relative ${isDark ? "text-zinc-400 hover:text-white" : "text-zinc-500 hover:text-zinc-900"}`}>
              <Bell className="w-5 h-5" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>
            <div className={`w-px h-6 ${isDark ? "bg-white/10" : "bg-zinc-200"}`}></div>
            <button className="flex items-center gap-2">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center border ${isDark ? "bg-zinc-800 border-white/10" : "bg-zinc-100 border-zinc-200"}`}>
                <User className="w-4 h-4 text-zinc-400" />
              </div>
            </button>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
      </div>
    </div>
  );
}
