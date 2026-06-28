import { useQuery } from "@tanstack/react-query";
import { SentinelAPI } from "@/lib/api";

export function useHealthReady() {
  return useQuery({
    queryKey: ["health", "ready"],
    queryFn: () => SentinelAPI.getHealthReady(),
    refetchInterval: 10000,
    retry: 1,
  });
}

/** @deprecated use useHealthReady */
export const useHealth = useHealthReady;

export function useMetrics() {
  return useQuery({
    queryKey: ["metrics"],
    queryFn: () => SentinelAPI.getMetricsRaw(),
    refetchInterval: 10000,
    retry: 1,
  });
}

/** @deprecated alias for useMetrics */
export const useMetricsRaw = useMetrics;

export function useBehaviorProfile(userId: string) {
  return useQuery({
    queryKey: ["behavior-profile", userId],
    queryFn: () => SentinelAPI.getBehaviorProfile(userId),
    enabled: !!userId,
    retry: 1,
  });
}

export function useAuditLogs(userId?: string, page = 1, perPage = 50) {
  return useQuery({
    queryKey: ["audit", userId, page, perPage],
    queryFn: () => SentinelAPI.getAuditLogs(userId ?? "dev.ops@enterprise.com", page, perPage),
    staleTime: 30000,
    enabled: !!userId,
    retry: 1,
  });
}
