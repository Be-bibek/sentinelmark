import { useQuery } from "@tanstack/react-query";
import { SentinelAPI } from "@/lib/api";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => SentinelAPI.getHealth(),
    refetchInterval: 30000, // Background poll every 30s
    retry: 3,
  });
}

export function useMetrics() {
  return useQuery({
    queryKey: ["metrics"],
    queryFn: () => SentinelAPI.getMetrics(),
    refetchInterval: 5000, // Poll every 5s for the dashboard
  });
}

export function useBehaviorProfile(userId: string) {
  return useQuery({
    queryKey: ["behavior", userId],
    queryFn: () => SentinelAPI.getBehaviorProfile(userId),
    enabled: !!userId,
  });
}

export function useAuditLogs(userId?: string, page = 1, limit = 50) {
  return useQuery({
    queryKey: ["audit", userId, page, limit],
    queryFn: () => SentinelAPI.getAuditLogs(userId, page, limit),
    staleTime: 1000 * 60, // Data stays fresh for 1 min unless invalidated
  });
}
