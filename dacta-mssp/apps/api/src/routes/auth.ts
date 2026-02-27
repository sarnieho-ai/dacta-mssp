import { Hono } from "hono";
import { createClient } from "@supabase/supabase-js";
import { getAdminClient } from "../db.js";
import { authMiddleware, type AuthContext } from "../middleware/auth.js";

const auth = new Hono<AuthContext>();

// POST /auth/login - email/password login
auth.post("/login", async (c) => {
  const body = await c.req.json<{ email: string; password: string }>();
  if (!body.email || !body.password) {
    return c.json({ error: "Email and password required", code: "VALIDATION" }, 400);
  }

  const supabase = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_ANON_KEY!,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  const { data, error } = await supabase.auth.signInWithPassword({
    email: body.email,
    password: body.password,
  });

  if (error) {
    return c.json({ error: error.message, code: "AUTH_FAILED" }, 401);
  }

  // Load user profile
  const admin = getAdminClient();
  const { data: user } = await admin
    .from("users")
    .select("*")
    .eq("auth_id", data.user.id)
    .single();

  return c.json({
    data: {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at,
      user: user,
    },
  });
});

// POST /auth/refresh - refresh access token
auth.post("/refresh", async (c) => {
  const body = await c.req.json<{ refresh_token: string }>();
  if (!body.refresh_token) {
    return c.json({ error: "refresh_token required", code: "VALIDATION" }, 400);
  }

  const supabase = createClient(
    process.env.SUPABASE_URL!,
    process.env.SUPABASE_ANON_KEY!,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  const { data, error } = await supabase.auth.refreshSession({
    refresh_token: body.refresh_token,
  });

  if (error || !data.session) {
    return c.json({ error: "Refresh failed", code: "AUTH_FAILED" }, 401);
  }

  return c.json({
    data: {
      access_token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      expires_at: data.session.expires_at,
    },
  });
});

// GET /auth/me - get current user profile (requires auth)
auth.get("/me", authMiddleware, async (c) => {
  const user = c.get("user");

  // Also load their org info if they belong to one
  let org = null;
  if (user.org_id) {
    const admin = getAdminClient();
    const { data } = await admin
      .from("organizations")
      .select("id, name, short_name, color, status")
      .eq("id", user.org_id)
      .single();
    org = data;
  }

  return c.json({ data: { ...user, organization: org } });
});

// POST /auth/logout - invalidate session (optional, mostly client-side)
auth.post("/logout", async (c) => {
  // Supabase JWT is stateless, so logout is mainly client-side token removal.
  // But we can sign out server-side if we have the token.
  return c.json({ data: { message: "Logged out" } });
});

export default auth;
