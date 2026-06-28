"use client";

import React, { useEffect, useRef } from "react";
import { motion, useMotionValue, useSpring, useTransform, animate } from "motion/react";
import { Shield, ShieldAlert, Zap, Activity } from "lucide-react";
import StarBorder from "./StarBorder";

interface KPICardsProps {
  score: number;
  anomaliesCount: number;
  policy: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
  theme?: "light" | "dark";
}

// Sub-component to smoothly animate integer numbers
function AnimatedNumber({ value, suffix = "" }: { value: number; suffix?: string }) {
  const motionValue = useMotionValue(value);
  const springValue = useSpring(motionValue, { stiffness: 50, damping: 15 });
  const displayValue = useTransform(springValue, (latest) => Math.round(latest));

  useEffect(() => {
    motionValue.set(value);
  }, [value, motionValue]);

  const containerRef = useRef<HTMLSpanElement>(null);

  // Spark a quick pulse animation on update for visual confirmation
  useEffect(() => {
    if (containerRef.current) {
      animate(containerRef.current, 
        { 
          scale: [1, 1.15, 1],
          filter: [
            "brightness(1)", 
            "brightness(1.5) drop-shadow(0 0 8px currentColor)", 
            "brightness(1)"
          ] 
        }, 
        { duration: 0.45, ease: "easeOut" }
      );
    }
  }, [value]);

  return (
    <motion.span ref={containerRef} className="inline-block">
      <motion.span>{displayValue}</motion.span>
      {suffix}
    </motion.span>
  );
}

// Sub-component to smoothly animate floats
function AnimatedFloat({ value, suffix = "" }: { value: number; suffix?: string }) {
  const motionValue = useMotionValue(value - 0.05);
  const springValue = useSpring(motionValue, { stiffness: 40, damping: 14 });
  const displayValue = useTransform(springValue, (latest) => latest.toFixed(2));

  useEffect(() => {
    motionValue.set(value);
  }, [value, motionValue]);

  const containerRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      animate(containerRef.current, 
        { scale: [1, 1.08, 1] }, 
        { duration: 0.4, ease: "easeOut" }
      );
    }
  }, [value]);

  return (
    <motion.span ref={containerRef} className="inline-block">
      <motion.span>{displayValue}</motion.span>
      {suffix}
    </motion.span>
  );
}

// Sub-component to pulse non-numeric text values on update
function AnimatedText({ value }: { value: string }) {
  const containerRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      animate(containerRef.current, 
        { 
          scale: [1, 1.08, 1],
          filter: [
            "brightness(1)", 
            "brightness(1.4) drop-shadow(0 0 6px currentColor)", 
            "brightness(1)"
          ] 
        }, 
        { duration: 0.45, ease: "easeOut" }
      );
    }
  }, [value]);

  return (
    <motion.span ref={containerRef} className="inline-block">
      {value}
    </motion.span>
  );
}

export default function KPICards({ score, anomaliesCount, policy, theme = "dark" }: KPICardsProps) {
  const isDark = theme === "dark";

  // Accent colors for different states depending on the active mode (Light vs Dark)
  const getTrustScoreColor = () => {
    if (score >= 80) return isDark ? "text-emerald-400" : "text-emerald-600";
    if (score >= 50) return isDark ? "text-amber-400" : "text-amber-600";
    return isDark ? "text-red-400" : "text-red-600";
  };

  const getAnomaliesColor = () => {
    if (anomaliesCount > 0) return isDark ? "text-amber-400" : "text-amber-600";
    return isDark ? "text-zinc-500" : "text-zinc-400";
  };

  const getPolicyColor = () => {
    if (policy === "ALLOW") return isDark ? "text-emerald-400" : "text-emerald-600";
    if (policy === "BLOCK") return isDark ? "text-red-400" : "text-red-600";
    return isDark ? "text-orange-400" : "text-orange-600";
  };

  const cards = [
    {
      id: "trust-score",
      title: "Real-Time Trust Score",
      element: <AnimatedNumber value={score} suffix="%" />,
      icon: Shield,
      color: getTrustScoreColor(),
      glowColor: score >= 80 ? "rgba(16, 185, 129, 0.12)" : score >= 50 ? "rgba(245, 158, 11, 0.12)" : "rgba(239, 68, 68, 0.12)",
      desc: "Continuous evaluation index",
    },
    {
      id: "active-anomalies",
      title: "Active Anomalies",
      element: <AnimatedNumber value={anomaliesCount} />,
      icon: ShieldAlert,
      color: getAnomaliesColor(),
      glowColor: anomaliesCount > 0 ? "rgba(245, 158, 11, 0.12)" : "rgba(255, 255, 255, 0.02)",
      desc: "Flagged cognitive exceptions",
    },
    {
      id: "active-policy",
      title: "Active Core Policy",
      element: <AnimatedText value={policy} />,
      icon: Zap,
      color: getPolicyColor(),
      glowColor: policy === "ALLOW" ? "rgba(16, 185, 129, 0.12)" : "rgba(249, 115, 22, 0.12)",
      desc: "Security enforcement model",
    },
    {
      id: "system-health",
      title: "System Health",
      element: <AnimatedFloat value={99.98} suffix="%" />,
      icon: Activity,
      color: isDark ? "text-emerald-400" : "text-emerald-600",
      glowColor: "rgba(16, 185, 129, 0.1)",
      desc: "Continuous ingress uptime",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <StarBorder
            as={motion.div}
            color="rgba(16, 185, 129, 0.4)"
            key={card.id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, delay: idx * 0.05 }}
            whileHover={{ 
              y: -5, 
              borderColor: isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(0, 0, 0, 0.1)",
              boxShadow: isDark 
                ? `0 10px 30px -5px ${card.glowColor}`
                : `0 10px 30px -5px rgba(0, 0, 0, 0.05)`
            }}
            className={`rounded-[22px] p-5 flex items-center justify-between transition-all duration-300 cursor-pointer border ${
              isDark 
                ? "bg-zinc-950/40 border-white/5 text-zinc-100" 
                : "bg-white border-zinc-200/80 text-zinc-800 shadow-[0_4px_20px_-4px_rgba(0,0,0,0.05)]"
            }`}
          >
            <div>
              <span className={`text-[10px] font-bold uppercase tracking-wider ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                {card.title}
              </span>
              <div className={`text-2xl font-bold tracking-tight mt-1.5 ${card.color}`}>
                {card.element}
              </div>
              <p className={`text-[9px] mt-1 font-mono uppercase ${isDark ? "text-zinc-500" : "text-zinc-400"}`}>
                {card.desc}
              </p>
            </div>
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${card.color} ${
              isDark 
                ? "bg-white/[0.02] border-white/5" 
                : "bg-zinc-100 border-zinc-200"
            }`}>
              <Icon className="w-5 h-5" />
            </div>
          </StarBorder>
        );
      })}
    </div>
  );
}
