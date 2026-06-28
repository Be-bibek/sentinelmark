import { create } from 'zustand';
import { Activity, Globe, Lock, Shield, Bot, Zap, Landmark, Fingerprint } from "lucide-react";
import { PolicyDecision } from './trust-store';

export interface AttackScenario {
  id: string;
  title: string;
  description: string;
  icon: any;
  expectedPolicy: PolicyDecision;
  payload: {
    deviceId: string;
    ip: string;
    location: string;
    userAgent: string;
    action: string;
    timestamp: string;
  };
}

export interface SimulatorStore {
  activeScenarioId: string | null;
  isSimulating: boolean;
  
  // Actions
  setActiveScenario: (id: string | null) => void;
  setSimulating: (isSimulating: boolean) => void;
}

export const useSimulatorStore = create<SimulatorStore>((set) => ({
  activeScenarioId: null,
  isSimulating: false,

  setActiveScenario: (id) => set({ activeScenarioId: id }),
  setSimulating: (isSimulating) => set({ isSimulating })
}));

export const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: "normal-activity",
    title: "Normal Activity",
    description: "Standard login from a known device in the user's home region.",
    icon: Activity,
    expectedPolicy: "ALLOW",
    payload: { deviceId: "dev_macbook_primary", ip: "104.28.19.1", location: "San Francisco, CA, US", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", action: "login", timestamp: "" }
  },
  {
    id: "unknown-device",
    title: "Unknown Device",
    description: "First time login from a new device fingerprint.",
    icon: Shield,
    expectedPolicy: "MFA",
    payload: { deviceId: "dev_unknown_windows", ip: "104.28.19.1", location: "San Francisco, CA, US", userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", action: "login", timestamp: "" }
  },
  {
    id: "impossible-travel",
    title: "Impossible Travel",
    description: "Login from Tokyo 15 minutes after a login in San Francisco.",
    icon: Globe,
    expectedPolicy: "BLOCK",
    payload: { deviceId: "dev_macbook_primary", ip: "133.32.4.1", location: "Tokyo, JP", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", action: "login", timestamp: "" }
  },
  {
    id: "session-hijack",
    title: "Session Hijack",
    description: "Cookie reuse from a completely different IP subnet and ASN mid-session.",
    icon: Lock,
    expectedPolicy: "BLOCK",
    payload: { deviceId: "dev_macbook_primary", ip: "185.15.22.4", location: "Moscow, RU", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", action: "api_call", timestamp: "" }
  },
  {
    id: "bot-activity",
    title: "Bot Activity",
    description: "Superhuman typing speed and linear mouse movements.",
    icon: Bot,
    expectedPolicy: "BLOCK",
    payload: { deviceId: "dev_macbook_primary", ip: "104.28.19.1", location: "San Francisco, CA, US", userAgent: "HeadlessChrome/120.0.0.0", action: "bulk_download", timestamp: "" }
  },
  {
    id: "api-abuse",
    title: "API Abuse",
    description: "1,500 requests per minute to sensitive endpoints.",
    icon: Zap,
    expectedPolicy: "BLOCK",
    payload: { deviceId: "dev_server_1", ip: "45.33.2.1", location: "Newark, NJ, US", userAgent: "python-requests/2.31.0", action: "enumerate_users", timestamp: "" }
  },
  {
    id: "large-transfer",
    title: "Large Treasury Transfer",
    description: "Attempting a $500,000 outgoing wire transfer.",
    icon: Landmark,
    expectedPolicy: "MULTI-SIG",
    payload: { deviceId: "dev_macbook_primary", ip: "104.28.19.1", location: "San Francisco, CA, US", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", action: "wire_transfer_500k", timestamp: "" }
  },
  {
    id: "browser-fingerprint",
    title: "Browser Fingerprint Change",
    description: "Canvas hash and installed fonts changed dynamically.",
    icon: Fingerprint,
    expectedPolicy: "MFA",
    payload: { deviceId: "dev_macbook_primary", ip: "104.28.19.1", location: "San Francisco, CA, US", userAgent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0", action: "login", timestamp: "" }
  }
];
