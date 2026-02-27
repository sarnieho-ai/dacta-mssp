import { Context, Next } from "hono";
import { getAdminClient } from "../db.js";
import type { User } from "@dacta/shared";

// Extends Hono context with typed user
export type AuthContext = {
  Variables: {
    user: User;
    accessToken: string;
  };
};

/**
 * Auth middleware: extracts Bearer token, verifies with Supabase,
 * loads user profile from our users table, attaches to context.
 */
export async function authMiddleware(c: Context<AuthContext>, next: Next) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({ error: "Missing or invalid Authorization header", code: "UNAUTHORIZED" }, 401);
  }

  const token = authHeader.slice(7);

  // Verify token with Supabase Auth
  const admin = getAdminClient();
  const { data: authData, error: authError } = await admin.auth.getUser(token);

  if (authError || !authData.user) {
    return c.json({ error: "Invalid or expired token", code: "UNAUTHORIZED" }, 401);
  }

  // Load user profile from our users table
  const { data: user, error: userError } = await admin
    .from("users")
    .select("*")
    .eq("auth_id", authData.user.id)
    .single();

  if (userError || !user) {
    return c.json(
      { error: "User profile not found. Contact admin.", code: "USER_NOT_FOUND" },
      403
    );
  }

  if (user.status !== "active") {
    return c.json(
      { error: "Account is " + user.status, code: "ACCOUNT_DISABLED" },
      403
    );
  }

  // Update last_active_at (fire-and-forget, don't block request)
  admin
    .from("users")
    .update({ last_active_at: new Date().toISOString() })
    .eq("id", user.id)
    .then(() => {});

  // Attach to context
  c.set("user", user as User);
  c.set("accessToken", token);

  await next();
}
