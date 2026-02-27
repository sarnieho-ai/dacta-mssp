import { Context, Next } from "hono";
import type { UserRole } from "@dacta/shared";
import type { AuthContext } from "./auth.js";

/**
 * Creates a middleware that checks if the authenticated user
 * has one of the allowed roles.
 *
 * Usage: app.get("/admin", requireRole(["platform_admin", "soc_manager"]), handler)
 */
export function requireRole(allowedRoles: UserRole[]) {
  return async (c: Context<AuthContext>, next: Next) => {
    const user = c.get("user");
    if (!user) {
      return c.json({ error: "Not authenticated", code: "UNAUTHORIZED" }, 401);
    }

    if (!allowedRoles.includes(user.role as UserRole)) {
      return c.json(
        {
          error: "Insufficient permissions. Required: " + allowedRoles.join(", "),
          code: "FORBIDDEN",
        },
        403
      );
    }

    await next();
  };
}

/**
 * Restricts client_viewer users to only see their own org's data.
 * Returns the org_id to filter by, or null if user can see everything.
 */
export function getOrgScope(c: Context<AuthContext>): string | null {
  const user = c.get("user");
  if (user.role === "client_viewer") {
    return user.org_id;
  }
  return null; // Internal users can see all orgs
}

// Convenience role groups
export const SOC_ROLES: UserRole[] = [
  "platform_admin",
  "soc_manager",
  "soc_analyst_l1",
  "soc_analyst_l2",
  "soc_engineer",
  "threat_hunter",
];

export const MANAGER_ROLES: UserRole[] = ["platform_admin", "soc_manager"];

export const ALL_INTERNAL: UserRole[] = [...SOC_ROLES, "management"];

export const ALL_ROLES: UserRole[] = [...ALL_INTERNAL, "client_viewer"];
