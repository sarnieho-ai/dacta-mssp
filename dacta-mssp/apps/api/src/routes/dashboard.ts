import { Hono } from "hono";
import { getAdminClient } from "../db.js";
import { authMiddleware } from "../middleware/auth.js";
import { requireRole, SOC_ROLES } from "../middleware/rbac.js";

const dashboard = new Hono();
dashboard.use("*", authMiddleware);

// GET /dashboard/kpis
dashboard.get("/kpis", requireRole(SOC_ROLES), async (c) => {
  const db = getAdminClient();

  const { data: allTickets } = await db.from("tickets").select("id, priority, status, org_id, source, assignee_id, created_at, resolved_at, sla_breached");

  const tickets = allTickets || [];
  const openStatuses = ["new", "open", "in_progress", "awaiting_client", "escalated"];
  const open = tickets.filter((t) => openStatuses.includes(t.status));

  const p1 = open.filter((t) => t.priority === "P1").length;
  const p2 = open.filter((t) => t.priority === "P2").length;
  const p3 = open.filter((t) => t.priority === "P3").length;
  const p4 = open.filter((t) => t.priority === "P4").length;
  const unassigned = open.filter((t) => !t.assignee_id).length;

  // By org
  const byOrg = {};
  open.forEach((t) => {
    if (!byOrg[t.org_id]) byOrg[t.org_id] = { open: 0, p1: 0 };
    byOrg[t.org_id].open++;
    if (t.priority === "P1") byOrg[t.org_id].p1++;
  });

  // By source
  const bySource = {};
  open.forEach((t) => {
    bySource[t.source] = (bySource[t.source] || 0) + 1;
  });

  // MTTR
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const resolvedThisMonth = tickets.filter((t) => t.resolved_at && t.resolved_at >= monthStart);
  let mttrMinutes = 0;
  if (resolvedThisMonth.length > 0) {
    const totalMinutes = resolvedThisMonth.reduce((sum, t) => {
      return sum + (new Date(t.resolved_at).getTime() - new Date(t.created_at).getTime()) / 60000;
    }, 0);
    mttrMinutes = Math.round(totalMinutes / resolvedThisMonth.length);
  }

  // SLA
  const monthTickets = tickets.filter((t) => t.created_at >= monthStart);
  const slaBreach = monthTickets.filter((t) => t.sla_breached).length;
  const slaCompliance = monthTickets.length > 0
    ? Math.round(((monthTickets.length - slaBreach) / monthTickets.length) * 1000) / 10
    : 100;

  return c.json({
    data: {
      open_tickets: open.length,
      p1_count: p1,
      p2_count: p2,
      p3_count: p3,
      p4_count: p4,
      unassigned,
      mttr_minutes: mttrMinutes,
      sla_compliance: slaCompliance,
      resolved_this_month: resolvedThisMonth.length,
      tickets_this_month: monthTickets.length,
      by_org: byOrg,
      by_source: bySource,
    },
  });
});

export default dashboard;
