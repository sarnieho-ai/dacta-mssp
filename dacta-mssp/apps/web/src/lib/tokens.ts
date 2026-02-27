export const T = {
  bg: "#060a12",
  bgCard: "#0c1220",
  bgHover: "#111a2e",
  bgDeep: "#080d18",
  border: "#1a2540",
  borderLight: "#243050",
  text: "#e2e8f0",
  textSec: "#8892a8",
  textMuted: "#5a6478",
  accent: "#3b82f6",
  red: "#ef4444",
  orange: "#f97316",
  yellow: "#eab308",
  green: "#22c55e",
  purple: "#a78bfa",
  cyan: "#22d3ee",
  font: "'JetBrains Mono', monospace",
  fontUI: "'Inter', -apple-system, sans-serif",
};

export const PRI: Record<string, { l: string; c: string; bg: string }> = {
  P1: { l: "Critical", c: T.red, bg: "rgba(239,68,68,0.1)" },
  P2: { l: "High", c: T.orange, bg: "rgba(249,115,22,0.1)" },
  P3: { l: "Medium", c: T.yellow, bg: "rgba(234,179,8,0.1)" },
  P4: { l: "Low", c: T.cyan, bg: "rgba(34,211,238,0.1)" },
};

export const STS: Record<string, { l: string; c: string }> = {
  new: { l: "New", c: T.purple },
  open: { l: "Open", c: T.orange },
  in_progress: { l: "In Progress", c: T.accent },
  awaiting_client: { l: "Awaiting", c: T.yellow },
  escalated: { l: "Escalated", c: T.purple },
  resolved: { l: "Resolved", c: T.green },
  closed: { l: "Closed", c: T.textMuted },
  false_positive: { l: "False Positive", c: T.textMuted },
};

export const SRC: Record<string, { l: string; c: string }> = {
  elastic_siem: { l: "Elastic SIEM", c: "#00bfb3" },
  trend_vision_one: { l: "Trend V1", c: "#ff6154" },
  heimdal: { l: "Heimdal", c: "#7c3aed" },
  threatlocker: { l: "ThreatLocker", c: "#2563eb" },
  microsoft_365: { l: "M365", c: T.orange },
  fortinet: { l: "FortiGate", c: "#ee3124" },
  manual: { l: "Manual", c: T.textMuted },
  other: { l: "Other", c: T.textMuted },
};

export function ago(d: string): string {
  var n = Date.now();
  var m = Math.floor((n - new Date(d).getTime()) / 60000);
  if (m < 1) return "now";
  if (m < 60) return m + "m";
  var h = Math.floor(m / 60);
  if (h < 24) return h + "h";
  return Math.floor(h / 24) + "d";
}

export function statusColor(s: string): string {
  var map: Record<string, string> = { healthy: T.green, warning: T.orange, error: T.red, compromised: T.red, configured: T.textMuted };
  return map[s] || T.textMuted;
}
