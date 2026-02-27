export type TicketPriority = "P1" | "P2" | "P3" | "P4";

export type TicketStatus =
  | "new"
  | "open"
  | "in_progress"
  | "awaiting_client"
  | "escalated"
  | "resolved"
  | "closed"
  | "false_positive";

export type TicketSource =
  | "elastic_siem"
  | "trend_vision_one"
  | "heimdal"
  | "threatlocker"
  | "microsoft_365"
  | "fortinet"
  | "crowdstrike"
  | "manual"
  | "api";

export type TicketVerdict =
  | "true_positive"
  | "false_positive"
  | "benign_true_positive"
  | null;

export interface Ticket {
  id: string;
  external_key: string | null;
  org_id: string;
  summary: string;
  description: string | null;
  priority: TicketPriority;
  status: TicketStatus;
  source: TicketSource;
  verdict: TicketVerdict;
  assignee_id: string | null;
  reporter_id: string | null;
  labels: string[];
  mitre_techniques: string[];
  affected_assets: string[];
  affected_hostname: string | null;
  affected_ip: string | null;
  affected_user: string | null;
  raw_payload: Record<string, unknown> | null;
  enrichment_data: Record<string, unknown> | null;
  sla_response_target: string | null;
  sla_resolution_target: string | null;
  sla_breached: boolean;
  parent_ticket_id: string | null;
  external_url: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  // Computed (joined)
  org_name?: string;
  org_short_name?: string;
  org_color?: string;
  assignee_name?: string;
}

export interface TicketFilters {
  org_id?: string;
  priority?: TicketPriority;
  status?: TicketStatus;
  source?: TicketSource;
  assignee_id?: string;
  search?: string;
  page?: number;
  limit?: number;
}

export interface TicketTimelineEntry {
  id: string;
  ticket_id: string;
  event_type: string;
  actor_id: string | null;
  actor_name: string | null;
  old_value: string | null;
  new_value: string | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface TicketComment {
  id: string;
  ticket_id: string;
  author_id: string;
  author_name?: string;
  body: string;
  is_internal: boolean;
  external_comment_id: string | null;
  created_at: string;
  updated_at: string;
}
