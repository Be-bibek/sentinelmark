"use client";

import React, { useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
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
  HeartPulse
} from "lucide-react";
import { useWebSocketStore, initializeWebSocket } from "@/stores/websocket-store";

export default function EnterpriseLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { status, lastPing } = useWebSocketStore();

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
    <div className="flex h-screen bg-[#030303] text-zinc-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/5 flex flex-col bg-black/40">
        <div className="h-16 flex items-center px-6 border-b border-white/5">
          <div className="w-8 h-8 bg-blue-600 rounded-xl flex items-center justify-center shadow-[0_0_15px_rgba(59,130,246,0.3)] mr-3">
            <Shield className="w-4.5 h-4.5 text-zinc-100" />
          </div>
          <div>
            <h1 className="text-sm font-extrabold tracking-tight font-mono text-white">SENTINELMARK</h1>
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
                    ? "bg-blue-600/10 text-blue-400 font-medium" 
                    : "text-zinc-400 hover:text-zinc-100 hover:bg-white/5"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-zinc-500"}`} />
                {item.name}
              </Link>
            );
          })}
        </nav>

        <div className="p-4 border-t border-white/5">
          <Link href="/settings" className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-zinc-400 hover:text-zinc-100 hover:bg-white/5 transition-all">
            <Settings className="w-4 h-4 text-zinc-500" />
            Settings
          </Link>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Navbar */}
        <header className="h-16 border-b border-white/5 flex items-center justify-between px-6 bg-black/20 backdrop-blur-xl">
          <div className="flex items-center flex-1">
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
              <input 
                type="text" 
                placeholder="Search events, IP, user..." 
                className="w-full bg-white/5 border border-white/10 rounded-lg pl-10 pr-4 py-1.5 text-sm text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 transition-colors"
              />
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            {/* WebSocket Status Indicator */}
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/5 border border-white/10">
              <Wifi className={`w-3.5 h-3.5 ${
                status === 'CONNECTED' ? 'text-emerald-400' :
                status === 'CONNECTING' ? 'text-amber-400 animate-pulse' : 'text-red-400'
              }`} />
              <span className="text-[10px] font-mono tracking-wider text-zinc-400">
                {status}
              </span>
            </div>

            <button className="p-2 text-zinc-400 hover:text-white transition-colors relative">
              <Bell className="w-5 h-5" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>
            <div className="w-px h-6 bg-white/10"></div>
            <button className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center border border-white/10">
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
  );
}
