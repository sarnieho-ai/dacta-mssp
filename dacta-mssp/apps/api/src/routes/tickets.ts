import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware, type AuthContext } from "../middleware/auth.js";
import { requireRole, getOrgScope, ALL_ROLES, SOC_ROLES } from "../middleware/rbac.js";
import type { TicketFilters } from "@dacta/shared";

const tickets = new Hono<AuthContext>();

// All ticket routes require auth
tickets.use("*", authMiddleware);

/**
 * GET /tickets - List tickets with filters and pagination
 *
 * Query params: org_id, priority, status, source, assignee_id, search, page, limit
 * Client viewers are auto-scoped to their org.
 */
tickets.get("/", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const orgScope = getOrgScope(c);

  // Parse query params
  const q = c.req.query();
  const page = Math.max(1, parseInt(q.page || "1"));
  const limit = Math.min(100, Math.max(1, parseInt(q.limit || "50")));
  const offset = (page - 1) * limit;

  // Build query with joins for org and assignee names
  let query = db
    .from("tickets")
    .select(
      `
      *,
      organizations!tickets_org_id_fkey(name, short_name, color),
      assignee:users!tickets_assignee_id_fkey(name)
      `,
      { count: "exact" }
    )
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  // Apply org scope for client viewers
  if (orgScope) {
    query = query.eq("org_id", orgScope);
  }

  // Apply filters
  if (q.org_id && !orgScope) {
    query = query.eq("org_id", q.org_id);
  }
  if (q.priority) {
    query = query.eq("priority", q.priority);
  }
  if (q.status) {
    query = query.eq("status", q.status);
  }
  if (q.source) {
    query = query.eq("source", q.source);
  }
  if (q.assignee_id) {
    query = query.eq("assignee_id", q.assignee_id);
  }
  if (q.search) {
    query = query.or(
      `summary.ilike.%${q.search}%,external_key.ilike.%${q.search}%`
    );
  }

  const { data, error, count } = await query;

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  // Flatten joined fields
  const tickets = (data || []).map((t: any) => ({
    ...t,
    org_name: t.organizations?.name || null,
    org_short_name: t.organizations?.short_name || null,
    org_color: t.organizations?.color || null,
    assignee_name: t.assignee?.name || null,
    organizations: undefined,
    assignee: undefined,
  }));

  return c.json({
    data: tickets,
    meta: {
      page,
      limit,
      total: count || 0,
      total_pages: Math.ceil((count || 0) / limit),
    },
  });
});

/**
 * GET /tickets/:id - Get single ticket with full details
 */
tickets.get("/:id", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const orgScope = getOrgScope(c);

  let query = db
    .from("tickets")
    .select(
      `
      *,
      organizations!tickets_org_id_fkey(name, short_name, color),
      assignee:users!tickets_assignee_id_fkey(name, email, role)
      `
    )
    .eq("id", id)
    .single();

  if (orgScope) {
    query = query.eq("org_id", orgScope);
  }

  const { data, error } = await query;

  if (error) {
    if (error.code === "PGRST116") {
      return c.json({ error: "Ticket not found", code: "NOT_FOUND" }, 404);
    }
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  const ticket = {
    ...data,
    org_name: data.organizations?.name || null,
    org_short_name: data.organizations?.short_name || null,
    org_color: data.organizations?.color || null,
    assignee_name: data.assignee?.name || null,
    organizations: undefined,
    assignee: undefined,
  };

  return c.json({ data: ticket });
});

/**
 * PATCH /tickets/:id - Update ticket fields
 * SOC roles only (client viewers can't modify)
 */
tickets.patch("/:id", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");
  const body = await c.req.json();

  // Whitelist of updatable fields
  const allowed = [
    "priority", "status", "verdict", "assignee_id", "summary",
    "description", "labels", "mitre_techniques", "affected_hostname",
    "affected_ip", "affected_user",
  ];

  const updates: Record<string, unknown> = { updated_at: new Date().toISOString() };
  for (const key of allowed) {
    if (key in body) {
      updates[key] = body[key];
    }
  }

  // Fetch current ticket for timeline
  const { data: current } = await db
    .from("tickets")
    .select("status, priority, assignee_id, verdict")
    .eq("id", id)
    .single();

  // Set resolved_at / closed_at timestamps
  if (updates.status === "resolved" && current?.status !== "resolved") {
    updates.resolved_at = new Date().toISOString();
  }
  if (updates.status === "closed" && current?.status !== "closed") {
    updates.closed_at = new Date().toISOString();
  }

  const { data, error } = await db
    .from("tickets")
    .update(updates)
    .eq("id", id)
    .select()
    .single();

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  // Write timeline entries for tracked field changes
  const trackedFields = ["status", "priority", "assignee_id", "verdict"];
  for (const field of trackedFields) {
    if (field in body && current && body[field] !== current[field]) {
      await db.from("ticket_timeline").insert({
        ticket_id: id,
        event_type: field + "_change",
        actor_id: user.id,
        old_value: String(current[field] || ""),
        new_value: String(body[field] || ""),
        details: {},
      });
    }
  }

  return c.json({ data });
});

/**
 * GET /tickets/:id/timeline - Get ticket timeline
 */
tickets.get("/:id/timeline", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");

  const { data, error } = await db
    .from("ticket_timeline")
    .select("*, actor:users!ticket_timeline_actor_id_fkey(name)")
    .eq("ticket_id", id)
    .order("created_at", { ascending: true });

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  const timeline = (data || []).map((e: any) => ({
    ...e,
    actor_name: e.actor?.name || null,
    actor: undefined,
  }));

  return c.json({ data: timeline });
});

/**
 * GET /tickets/:id/comments - Get ticket comments
 * Client viewers only see non-internal comments
 */
tickets.get("/:id/comments", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");

  let query = db
    .from("ticket_comments")
    .select("*, author:users!ticket_comments_author_id_fkey(name)")
    .eq("ticket_id", id)
    .order("created_at", { ascending: true });

  // Client viewers can't see internal comments
  if (user.role === "client_viewer") {
    query = query.eq("is_internal", false);
  }

  const { data, error } = await query;

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  const comments = (data || []).map((c: any) => ({
    ...c,
    author_name: c.author?.name || null,
    author: undefined,
  }));

  return c.json({ data: comments });
});

/**
 * POST /tickets/:id/comments - Add comment
 */
tickets.post("/:id/comments", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const user = c.get("user");
  const body = await c.req.json<{ body: string; is_internal?: boolean }>();

  if (!body.body || body.body.trim().length === 0) {
    return c.json({ error: "Comment body required", code: "VALIDATION" }, 400);
  }

  const { data, error } = await db
    .from("ticket_comments")
    .insert({
      ticket_id: id,
      author_id: user.id,
      body: body.body,
      is_internal: body.is_internal !== false, // Default to internal
    })
    .select()
    .single();

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  // Also write to timeline
  await db.from("ticket_timeline").insert({
    ticket_id: id,
    event_type: "comment",
    actor_id: user.id,
    details: { is_internal: body.is_internal !== false },
  });

  return c.json({ data }, 201);
});

export default tickets;
