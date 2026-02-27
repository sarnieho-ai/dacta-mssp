export type AIFeedback = "accepted" | "modified" | "rejected" | null;

export interface AIReasoningStep {
  step: number;
  text: string;
  evidence: string | null;
}

export interface AIRecommendedAction {
  action: string;
  target: string;
  system: string;
  impact?: string;
  reversible: boolean;
  priority: number;
}

export interface AIInvestigationBrief {
  id: string;
  ticket_id: string;
  verdict: string;
  confidence_score: number;
  reasoning_chain: AIReasoningStep[];
  correlated_ticket_ids: string[];
  enrichment_summary: Record<string, unknown>;
  recommended_actions: AIRecommendedAction[];
  playbook_steps: string[];
  escalation_draft: string | null;
  model_used: string;
  prompt_tokens: number;
  completion_tokens: number;
  latency_ms: number;
  cost_usd: number;
  analyst_feedback: AIFeedback;
  feedback_notes: string | null;
  created_at: string;
}
