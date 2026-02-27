import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware, type AuthContext } from "../middleware/auth.js";
import { requireRole, getOrgScope, ALL_ROLES, MANAGER_ROLES } from "../middleware/rbac.js";

const orgs = new Hono<AuthContext>();
orgs.use("*", authMiddleware);

/**
 * GET /organizations - List all organizations
 * Client viewers only see their own org
 */
orgs.get("/", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const orgScope = getOrgScope(c);

  let query = db
    .from("organizations")
    .select("*")
    .order("name", { ascending: true });

  if (orgScope) {
    query = query.eq("id", orgScope);
  }

  const { data: organizations, error } = await query;

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  // Get ticket counts per org
  const { data: ticketCounts } = await db
    .from("tickets")
    .select("org_id, status, priority");

  const enriched = (organizations || []).map((org: any) => {
    const orgTickets = (ticketCounts || []).filter(
      (t: any) => t.org_id === org.id
    );
    const openStatuses = ["new", "open", "in_progress", "awaiting_client", "escalated"];
    const openTickets = orgTickets.filter((t: any) => openStatuses.includes(t.status));

    return {
      ...org,
      open_ticket_count: openTickets.length,
      critical_ticket_count: openTickets.filter((t: any) => t.priority === "P1").length,
      total_ticket_count: orgTickets.length,
    };
  });

  return c.json({ data: enriched });
});

/**
 * GET /organizations/:id - Get single organization with stats
 */
orgs.get("/:id", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const orgScope = getOrgScope(c);

  // Client viewers can only see their own org
  if (orgScope && orgScope !== id) {
    return c.json({ error: "Access denied", code: "FORBIDDEN" }, 403);
  }

  const { data: org, error } = await db
    .from("organizations")
    .select("*")
    .eq("id", id)
    .single();

  if (error) {
    if (error.code === "PGRST116") {
      return c.json({ error: "Organization not found", code: "NOT_FOUND" }, 404);
    }
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  // Get ticket stats
  const { data: tickets } = await db
    .from("tickets")
    .select("status, priority")
    .eq("org_id", id);

  const openStatuses = ["new", "open", "in_progress", "awaiting_client", "escalated"];
  const openTickets = (tickets || []).filter((t: any) => openStatuses.includes(t.status));

  // Get asset count
  const { count: assetCount } = await db
    .from("assets")
    .select("id", { count: "exact", head: true })
    .eq("org_id", id);

  // Get users assigned to this org
  const { data: users } = await db
    .from("users")
    .select("id, name, role, status")
    .eq("org_id", id);

  return c.json({
    data: {
      ...org,
      open_ticket_count: openTickets.length,
      critical_ticket_count: openTickets.filter((t: any) => t.priority === "P1").length,
      total_ticket_count: (tickets || []).length,
      total_endpoints: assetCount || 0,
      users: users || [],
    },
  });
});

export default orgs;
