export type UserRole =
  | "platform_admin"
  | "soc_manager"
  | "soc_analyst_l1"
  | "soc_analyst_l2"
  | "soc_engineer"
  | "threat_hunter"
  | "client_viewer"
  | "management";

export type UserStatus = "active" | "inactive" | "suspended";

export interface User {
  id: string;
  auth_id: string | null;
  email: string;
  name: string;
  avatar_url: string | null;
  role: UserRole;
  status: UserStatus;
  org_id: string | null;
  shift: string | null;
  preferences: Record<string, unknown>;
  last_active_at: string | null;
  created_at: string;
  updated_at: string;
}

export function isInternalRole(role: UserRole): boolean {
  return role !== "client_viewer";
}

export function canTriage(role: UserRole): boolean {
  return [
    "platform_admin",
    "soc_manager",
    "soc_analyst_l1",
    "soc_analyst_l2",
    "soc_engineer",
    "threat_hunter",
  ].includes(role);
}

export function canManage(role: UserRole): boolean {
  return ["platform_admin", "soc_manager"].includes(role);
}
