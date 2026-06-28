"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, ShieldAlert, Activity, FileText, Code2, Terminal } from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const links = [
    { href: "/", label: "SOC Dashboard", icon: LayoutDashboard },
    { href: "/simulator", label: "Threat Simulator", icon: ShieldAlert },
    { href: "/behavior", label: "Behavior Explorer", icon: Activity },
    { href: "/audit", label: "Audit Explorer", icon: FileText },
    { href: "/api-explorer", label: "API Explorer", icon: Code2 },
    { href: "/sdk", label: "SDK Playground", icon: Terminal },
  ];

  return (
    <aside className="w-64 border-r border-border bg-card/50 backdrop-blur-xl hidden md:flex flex-col">
      <div className="h-16 flex items-center px-6 border-b border-border">
        <h1 className="font-mono font-bold tracking-tight text-primary">SentinelMark.</h1>
      </div>
      <nav className="flex-1 p-4 flex flex-col gap-2">
        {links.map((link) => {
          const isActive = pathname === link.href;
          const Icon = link.icon;
          return (
            <Link 
              key={link.href} 
              href={link.href}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive 
                  ? "bg-primary/10 text-primary" 
                  : "text-muted-foreground hover:bg-muted hover:text-foreground"
              }`}
            >
              <Icon className="w-4 h-4" />
              {link.label}
            </Link>
          );
        })}
      </nav>
      <div className="p-4 border-t border-border">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs text-muted-foreground font-mono">System Online</span>
        </div>
      </div>
    </aside>
  );
}
