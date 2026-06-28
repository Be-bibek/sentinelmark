"use client";

import React, { useEffect, useRef } from "react";

interface ParticleBackgroundProps {
  policyState: "ALLOW" | "MFA" | "MULTI-SIG" | "BLOCK";
  theme?: "light" | "dark";
}

export default function ParticleBackground({ policyState, theme = "dark" }: ParticleBackgroundProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const isDark = theme === "dark";

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    let particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      alpha: number;
    }> = [];

    // Observe size
    const resizeObserver = new ResizeObserver((entries) => {
      for (let entry of entries) {
        const { width, height } = entry.contentRect;
        canvas.width = width;
        canvas.height = height;
        initParticles(width, height);
      }
    });

    resizeObserver.observe(canvas.parentElement || document.body);

    const initParticles = (w: number, h: number) => {
      particles = [];
      const count = Math.min(Math.floor((w * h) / 15000), 100);
      for (let i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          vx: (Math.random() - 0.5) * 0.4,
          vy: (Math.random() - 0.5) * 0.4,
          radius: Math.random() * 1.5 + (isDark ? 0.5 : 1.0),
          alpha: Math.random() * (isDark ? 0.5 : 0.35) + (isDark ? 0.1 : 0.25),
        });
      }
    };

    const getParticleColor = () => {
      switch (policyState) {
        case "ALLOW":
          return "16, 185, 129"; // emerald
        case "MFA":
          return "245, 158, 11"; // amber
        case "MULTI-SIG":
          return "249, 115, 22"; // orange
        case "BLOCK":
          return "239, 68, 68"; // red
        default:
          return "16, 185, 129";
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const colorStr = getParticleColor();

      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;

        // Bounce
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${colorStr}, ${p.alpha})`;
        ctx.fill();
      });

      // Draw faint lines between close particles
      ctx.strokeStyle = isDark ? `rgba(${colorStr}, 0.05)` : `rgba(${colorStr}, 0.12)`;
      ctx.lineWidth = isDark ? 0.5 : 0.8;
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
    };
  }, [policyState, isDark]);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 pointer-events-none z-0"
      style={{ mixBlendMode: isDark ? "screen" : "multiply" }}
    />
  );
}
