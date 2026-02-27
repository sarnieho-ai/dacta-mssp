import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware, type AuthContext } from "../middleware/auth.js";
import { requireRole, SOC_ROLES } from "../middleware/rbac.js";

const users = new Hono<AuthContext>();
users.use("*", authMiddleware);

/**
 * GET /users - List users (SOC team members)
 * Query: role, status, shift
 */
users.get("/", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const q = c.req.query();

  let query = db
    .from("users")
    .select("id, name, email, role, status, shift, avatar_url, last_active_at, org_id")
    .order("name", { ascending: true });

  if (q.role) query = query.eq("role", q.role);
  if (q.status) query = query.eq("status", q.status || "active");
  if (q.shift) query = query.eq("shift", q.shift);

  const { data, error } = await query;

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  return c.json({ data: data || [] });
});

/**
 * GET /users/analysts - Get analysts with their current ticket counts
 * Used for the Analyst Workload dashboard panel
 */
users.get("/analysts", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();

  // Get all SOC analysts
  const { data: analysts } = await db
    .from("users")
    .select("id, name, role, shift, avatar_url, status, last_active_at")
    .in("role", ["soc_analyst_l1", "soc_analyst_l2", "soc_engineer", "threat_hunter"])
    .eq("status", "active")
    .order("name");

  // Get open ticket counts per assignee
  const { data: tickets } = await db
    .from("tickets")
    .select("assignee_id, priority")
    .in("status", ["new", "open", "in_progress", "escalated"]);

  const enriched = (analysts || []).map((a: any) => {
    const assigned = (tickets || []).filter((t: any) => t.assignee_id === a.id);
    return {
      ...a,
      ticket_count: assigned.length,
      p1_count: assigned.filter((t: any) => t.priority === "P1").length,
      // Consider "online" if last_active within 10 minutes
      is_online: a.last_active_at
        ? Date.now() - new Date(a.last_active_at).getTime() < 600_000
        : false,
    };
  });

  return c.json({ data: enriched });
});

export default users;
