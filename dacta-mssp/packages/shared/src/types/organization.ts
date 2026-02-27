export type OrgStatus = "active" | "onboarding" | "inactive" | "offboarded";
export type ContractType = "mssp" | "retainer" | "project" | "internal";

export interface Organization {
  id: string;
  name: string;
  short_name: string;
  color: string;
  logo_url: string | null;
  status: OrgStatus;
  contract_type: ContractType;
  sla_tier: string;
  jira_project_key: string | null;
  primary_contact_email: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  // Computed (joined)
  open_ticket_count?: number;
  critical_ticket_count?: number;
  total_endpoints?: number;
}
