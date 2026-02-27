export const PRIORITY_CONFIG = {
  P1: { label: "Critical", color: "#ef4444", bg: "rgba(239,68,68,0.1)", sla_response: 15, sla_resolution: 240 },
  P2: { label: "High", color: "#f97316", bg: "rgba(249,115,22,0.1)", sla_response: 60, sla_resolution: 480 },
  P3: { label: "Medium", color: "#eab308", bg: "rgba(234,179,8,0.1)", sla_response: 240, sla_resolution: 1440 },
  P4: { label: "Low", color: "#22d3ee", bg: "rgba(34,211,238,0.1)", sla_response: 480, sla_resolution: 4320 },
} as const;

export const STATUS_CONFIG = {
  new: { label: "New", color: "#a78bfa" },
  open: { label: "Open", color: "#f97316" },
  in_progress: { label: "In Progress", color: "#3b82f6" },
  awaiting_client: { label: "Awaiting Client", color: "#eab308" },
  escalated: { label: "Escalated", color: "#a78bfa" },
  resolved: { label: "Resolved", color: "#22c55e" },
  closed: { label: "Closed", color: "#5a6478" },
  false_positive: { label: "False Positive", color: "#5a6478" },
} as const;

export const SOURCE_CONFIG = {
  elastic_siem: { label: "Elastic SIEM", color: "#00bfb3" },
  trend_vision_one: { label: "Trend Vision One", color: "#ff6154" },
  heimdal: { label: "Heimdal", color: "#7c3aed" },
  threatlocker: { label: "ThreatLocker", color: "#2563eb" },
  microsoft_365: { label: "Microsoft 365", color: "#f97316" },
  fortinet: { label: "FortiGate", color: "#ee3124" },
  crowdstrike: { label: "CrowdStrike", color: "#ff2d20" },
  manual: { label: "Manual", color: "#5a6478" },
  api: { label: "API", color: "#3b82f6" },
} as const;

export const VERDICT_CONFIG = {
  true_positive: { label: "True Positive", color: "#ef4444", icon: "TP" },
  false_positive: { label: "False Positive", color: "#22c55e", icon: "FP" },
  benign_true_positive: { label: "Benign TP", color: "#eab308", icon: "BTP" },
} as const;

export const CLOSED_STATUSES = ["closed", "resolved", "false_positive"] as const;

export function isOpenStatus(status: string): boolean {
  return !CLOSED_STATUSES.includes(status as any);
}
