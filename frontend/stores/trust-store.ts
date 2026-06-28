import { create } from 'zustand';

export type PolicyDecision = 'ALLOW' | 'MFA' | 'MULTI-SIG' | 'BLOCK';

export interface EvaluationState {
  score: number;
  risk: number;
  decision: PolicyDecision;
  anomalies: string[];
}

export interface TrustStore {
  currentScore: number;
  risk: number;
  decision: PolicyDecision;
  anomalies: string[];
  sessionHistory: Array<{ timestamp: Date; score: number; risk: number }>;
  
  // Actions
  setEvaluation: (evaluation: EvaluationState) => void;
  resetTrust: () => void;
}

export const useTrustStore = create<TrustStore>((set) => ({
  currentScore: 98,
  risk: 0.02,
  decision: 'ALLOW',
  anomalies: [],
  sessionHistory: [],

  setEvaluation: (evaluation) => set((state) => {
    const timestamp = new Date();
    return {
      currentScore: evaluation.score,
      risk: evaluation.risk,
      decision: evaluation.decision,
      anomalies: evaluation.anomalies,
      sessionHistory: [...state.sessionHistory, { timestamp, score: evaluation.score, risk: evaluation.risk }].slice(-50)
    };
  }),

  resetTrust: () => set((state) => {
    const timestamp = new Date();
    return {
      currentScore: 98,
      risk: 0.02,
      decision: 'ALLOW',
      anomalies: [],
      sessionHistory: [...state.sessionHistory, { timestamp, score: 98, risk: 0.02 }].slice(-50)
    };
  })
}));
