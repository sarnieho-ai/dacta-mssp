import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware, type AuthContext } from "../middleware/auth.js";
import { requireRole, getOrgScope, ALL_ROLES } from "../middleware/rbac.js";

const assets = new Hono<AuthContext>();
assets.use("*", authMiddleware);

/**
 * GET /assets - List assets with filters
 * Query: org_id, asset_type, status, search, page, limit
 */
assets.get("/", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const orgScope = getOrgScope(c);
  const q = c.req.query();
  const page = Math.max(1, parseInt(q.page || "1"));
  const limit = Math.min(100, Math.max(1, parseInt(q.limit || "50")));
  const offset = (page - 1) * limit;

  let query = db
    .from("assets")
    .select("*, organizations!assets_org_id_fkey(name, short_name, color)", {
      count: "exact",
    })
    .order("hostname", { ascending: true })
    .range(offset, offset + limit - 1);

  if (orgScope) {
    query = query.eq("org_id", orgScope);
  } else if (q.org_id) {
    query = query.eq("org_id", q.org_id);
  }

  if (q.asset_type) query = query.eq("asset_type", q.asset_type);
  if (q.status) query = query.eq("status", q.status);
  if (q.search) query = query.ilike("hostname", `%${q.search}%`);

  const { data, error, count } = await query;

  if (error) {
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  const assets = (data || []).map((a: any) => ({
    ...a,
    org_name: a.organizations?.name || null,
    org_short_name: a.organizations?.short_name || null,
    organizations: undefined,
  }));

  return c.json({
    data: assets,
    meta: { page, limit, total: count || 0, total_pages: Math.ceil((count || 0) / limit) },
  });
});

/**
 * GET /assets/:id - Single asset
 */
assets.get("/:id", requireRole(ALL_ROLES), async (c) => {
  const db = getAdminClient();
  const id = c.req.param("id");
  const orgScope = getOrgScope(c);

  let query = db
    .from("assets")
    .select("*, organizations!assets_org_id_fkey(name, short_name, color)")
    .eq("id", id)
    .single();

  if (orgScope) query = query.eq("org_id", orgScope);

  const { data, error } = await query;

  if (error) {
    if (error.code === "PGRST116") {
      return c.json({ error: "Asset not found", code: "NOT_FOUND" }, 404);
    }
    return c.json({ error: error.message, code: "DB_ERROR" }, 500);
  }

  return c.json({ data });
});

export default assets;
