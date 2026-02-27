import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware } from "../middleware/auth.js";
import { requireRole, SOC_ROLES } from "../middleware/rbac.js";

const users = new Hono();
users.use("*", authMiddleware);

// GET /users
users.get("/", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const { data, error } = await db
    .from("users")
    .select("id, name, email, role, status, shift, avatar_url, last_active_at, org_id")
    .order("name", { ascending: true });
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  return c.json({ data: data || [] });
});

// GET /users/analysts
users.get("/analysts", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();

  const { data: analysts } = await db
    .from("users")
    .select("id, name, role, shift, avatar_url, status, last_active_at")
    .in("role", ["soc_analyst_l1", "soc_analyst_l2", "soc_engineer", "threat_hunter"])
    .eq("status", "active")
    .order("name");

  const { data: tickets } = await db
    .from("tickets")
    .select("assignee_id, priority")
    .in("status", ["new", "open", "in_progress", "escalated"]);

  const enriched = (analysts || []).map((a) => {
    const assigned = (tickets || []).filter((t) => t.assignee_id === a.id);
    return {
      ...a,
      ticket_count: assigned.length,
      p1_count: assigned.filter((t) => t.priority === "P1").length,
      is_online: a.last_active_at
        ? Date.now() - new Date(a.last_active_at).getTime() < 600000
        : false,
    };
  });

  return c.json({ data: enriched });
});

export default users;
