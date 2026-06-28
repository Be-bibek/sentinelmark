"use client";

import React, { Component, ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallbackLabel?: string;
}
interface State {
  hasError: boolean;
  error?: Error;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error("[ErrorBoundary]", error);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center py-12 text-center gap-4">
          <div className="p-4 bg-red-500/10 rounded-full border border-red-500/20">
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
          <div>
            <p className="text-white font-bold mb-1">{this.props.fallbackLabel ?? "Component Error"}</p>
            <p className="text-zinc-500 text-sm">{this.state.error?.message ?? "An unexpected error occurred."}</p>
          </div>
          <button
            onClick={() => this.setState({ hasError: false, error: undefined })}
            className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-zinc-300 text-sm rounded-lg border border-white/10 transition-colors"
          >
            <RefreshCw className="w-4 h-4" /> Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
