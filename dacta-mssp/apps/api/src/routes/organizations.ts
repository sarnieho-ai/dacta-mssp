import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware } from "../middleware/auth.js";
import { requireRole, getOrgScope, ALL_ROLES } from "../middleware/rbac.js";

const orgs = new Hono();
orgs.use("*", authMiddleware);

// GET /organizations
orgs.get("/", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const orgScope = getOrgScope(c);

  let query = db.from("organizations").select("*").order("name", { ascending: true });
  if (orgScope) query = query.eq("id", orgScope);

  const { data: organizations, error } = await query;
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);

  // Get ticket counts
  const { data: allTickets } = await db.from("tickets").select("org_id, status, priority");
  const openStatuses = ["new", "open", "in_progress", "awaiting_client", "escalated"];

  const enriched = (organizations || []).map((org) => {
    const orgTickets = (allTickets || []).filter((t) => t.org_id === org.id);
    const openTickets = orgTickets.filter((t) => openStatuses.includes(t.status));
    return {
      ...org,
      open_ticket_count: openTickets.length,
      critical_ticket_count: openTickets.filter((t) => t.priority === "P1").length,
      total_ticket_count: orgTickets.length,
    };
  });

  return c.json({ data: enriched });
});

// GET /organizations/:id
orgs.get("/:id", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const { data: org, error } = await db.from("organizations").select("*").eq("id", id).single();
  if (error) return c.json({ error: "Organization not found", code: "NOT_FOUND" }, 404);
  return c.json({ data: org });
});

export default orgs;
