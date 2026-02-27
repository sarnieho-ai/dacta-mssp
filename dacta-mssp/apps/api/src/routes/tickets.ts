import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware } from "../middleware/auth.js";
import { requireRole, getOrgScope, ALL_ROLES, SOC_ROLES } from "../middleware/rbac.js";

const tickets = new Hono();
tickets.use("*", authMiddleware);

// GET /tickets
tickets.get("/", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const orgScope = getOrgScope(c);
  const q = c.req.query();
  const page = Math.max(1, parseInt(q.page || "1"));
  const limit = Math.min(100, Math.max(1, parseInt(q.limit || "50")));
  const offset = (page - 1) * limit;

  let query = db
    .from("tickets")
    .select("*", { count: "exact" })
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (orgScope) query = query.eq("org_id", orgScope);
  if (q.org_id && !orgScope) query = query.eq("org_id", q.org_id);
  if (q.priority) query = query.eq("priority", q.priority);
  if (q.status) query = query.eq("status", q.status);
  if (q.source) query = query.eq("source", q.source);
  if (q.assignee_id) query = query.eq("assignee_id", q.assignee_id);
  if (q.search) query = query.or(`summary.ilike.%${q.search}%,external_key.ilike.%${q.search}%`);

  const { data: rawTickets, error, count } = await query;
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);

  // Enrich with org info
  const orgIds = [...new Set((rawTickets || []).map((t) => t.org_id).filter(Boolean))];
  let orgMap = {};
  if (orgIds.length > 0) {
    const { data: orgsData } = await db.from("organizations").select("id, name, short_name, color").in("id", orgIds);
    orgMap = (orgsData || []).reduce((m, o) => { m[o.id] = o; return m; }, {});
  }

  const tickets = (rawTickets || []).map((t) => {
    const org = orgMap[t.org_id] || {};
    return {
      ...t,
      org_name: org.name || null,
      org_short_name: org.short_name || null,
      org_color: org.color || null,
    };
  });

  return c.json({
    data: tickets,
    meta: { page, limit, total: count || 0, total_pages: Math.ceil((count || 0) / limit) },
  });
});

// GET /tickets/:id
tickets.get("/:id", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const { data, error } = await db.from("tickets").select("*").eq("id", id).single();
  if (error) return c.json({ error: "Ticket not found", code: "NOT_FOUND" }, 404);

  // Get org info
  if (data.org_id) {
    const { data: org } = await db.from("organizations").select("name, short_name, color").eq("id", data.org_id).single();
    if (org) {
      data.org_name = org.name;
      data.org_short_name = org.short_name;
      data.org_color = org.color;
    }
  }

  return c.json({ data });
});

// PATCH /tickets/:id
tickets.patch("/:id", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");
  const body = await c.req.json();

  const allowed = ["priority", "status", "verdict", "assignee_id", "assignee_name", "summary", "description", "labels", "mitre_techniques", "affected_hostname", "affected_ip", "affected_user"];
  const updates = { updated_at: new Date().toISOString() };
  for (const key of allowed) {
    if (key in body) updates[key] = body[key];
  }

  if (updates.status === "resolved") updates.resolved_at = new Date().toISOString();

  const { data, error } = await db.from("tickets").update(updates).eq("id", id).select().single();
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  return c.json({ data });
});

// GET /tickets/:id/timeline
tickets.get("/:id/timeline", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const { data, error } = await db.from("ticket_timeline").select("*").eq("ticket_id", id).order("created_at", { ascending: true });
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  return c.json({ data: data || [] });
});

// GET /tickets/:id/comments
tickets.get("/:id/comments", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");
  let query = db.from("ticket_comments").select("*").eq("ticket_id", id).order("created_at", { ascending: true });
  if (user.role === "client_viewer") query = query.eq("is_internal", false);
  const { data, error } = await query;
  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  return c.json({ data: data || [] });
});

// POST /tickets/:id/comments
tickets.post("/:id/comments", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");
  const body = await c.req.json();
  if (!body.body) return c.json({ error: "Comment body required", code: "VALIDATION" }, 400);

  const { data, error } = await db.from("ticket_comments").insert({
    ticket_id: id,
    author_id: user.id,
    author_name: user.name,
    body: body.body,
    is_internal: body.is_internal !== false,
  }).select().single();

  if (error) return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  return c.json({ data }, 201);
});

export default tickets;
