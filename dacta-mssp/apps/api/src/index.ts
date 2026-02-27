import "dotenv/config";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";

import authRoutes from "./routes/auth.js";
import ticketRoutes from "./routes/tickets.js";
import orgRoutes from "./routes/organizations.js";
import assetRoutes from "./routes/assets.js";
import userRoutes from "./routes/users.js";
import dashboardRoutes from "./routes/dashboard.js";

const app = new Hono();

// ─── Global middleware ───────────────────────────────────────────
app.use("*", logger());

app.use(
  "*",
  cors({
    origin: (origin) => origin || "*",
    allowHeaders: ["Authorization", "Content-Type"],
    allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    credentials: true,
  })
);

// ─── Health check ────────────────────────────────────────────────
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    service: "dacta-mssp-api",
    timestamp: new Date().toISOString(),
  });
});

// ─── Routes ──────────────────────────────────────────────────────
app.route("/auth", authRoutes);
app.route("/tickets", ticketRoutes);
app.route("/organizations", orgRoutes);
app.route("/assets", assetRoutes);
app.route("/users", userRoutes);
app.route("/dashboard", dashboardRoutes);

// ─── 404 handler ─────────────────────────────────────────────────
app.notFound((c) => {
  return c.json({ error: "Not found", code: "NOT_FOUND" }, 404);
});

// ─── Global error handler ────────────────────────────────────────
app.onError((err, c) => {
  console.error("[API Error]", err);
  return c.json(
    { error: "Internal server error", code: "INTERNAL_ERROR" },
    500
  );
});

// ─── Start server ────────────────────────────────────────────────
const port = parseInt(process.env.PORT || "3001");

serve({ fetch: app.fetch, port }, () => {
  console.log("");
  console.log("  DACTA MSSP API");
  console.log("  ──────────────────────────");
  console.log("  Port:    " + port);
  console.log("  Env:     " + (process.env.NODE_ENV || "development"));
  console.log("  Health:  http://localhost:" + port + "/health");
  console.log("");
});

export default app;
