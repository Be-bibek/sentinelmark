"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider as NextThemesProvider } from "next-themes";
import { useEffect, useState } from "react";
import { connectWebSocket, disconnectWebSocket } from "../lib/ws";
import { Toaster } from "sonner";

const queryClient = new QueryClient();

export function Providers({ children }: { children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    // Connect WS on app mount and pass queryClient for cache invalidation
    connectWebSocket(queryClient);
    return () => disconnectWebSocket();
  }, []);

  if (!mounted) {
    return null;
  }

  return (
    <QueryClientProvider client={queryClient}>
      <NextThemesProvider attribute="class" defaultTheme="dark" enableSystem={false}>
        {children}
        <Toaster theme="dark" position="bottom-right" richColors />
      </NextThemesProvider>
    </QueryClientProvider>
  );
}
