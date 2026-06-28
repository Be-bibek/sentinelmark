import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-sans",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-mono",
});

import { Providers } from "@/components/Providers";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "SentinelMark SOC Console",
  description: "Continuous adaptive trust evaluation & incident response panel",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body className="bg-background text-foreground antialiased selection:bg-emerald-500/20 selection:text-emerald-300 h-screen w-screen overflow-hidden flex">
        <Providers>
          <Sidebar />
          <main className="flex-1 h-full overflow-y-auto bg-background/50">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}
