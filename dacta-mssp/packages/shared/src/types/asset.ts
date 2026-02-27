export type AssetType = "workstation" | "server" | "network_device" | "cloud_resource" | "mobile" | "iot" | "other";
export type AssetStatus = "active" | "inactive" | "decommissioned" | "compromised";

export interface Asset {
  id: string;
  hostname: string;
  org_id: string;
  asset_type: AssetType;
  os: string | null;
  ip_address: string | null;
  mac_address: string | null;
  agent_installed: boolean;
  agent_version: string | null;
  last_seen: string | null;
  status: AssetStatus;
  criticality: string;
  risk_score: number;
  department: string | null;
  owner: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}
