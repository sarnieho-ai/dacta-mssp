import React, { useState, useEffect, useCallback } from "react";
import { useAuth } from "../stores/auth";
import { api, ApiClientError } from "../lib/api";
import { T, PRI, STS, SRC, ago } from "../lib/tokens";

// ─── Types ────────────────────────────────────────────────────────
interface KPIs {
  open_tickets: number;
  p1_count: number;
  p2_count: number;
  p3_count: number;
  p4_count: number;
  unassigned: number;
  mttr_minutes: number;
  sla_compliance: number;
  resolved_this_month: number;
  tickets_this_month: number;
  by_org: Record<string, { open: number; p1: number }>;
  by_source: Record<string, number>;
}

interface Ticket {
  id: string;
  external_key: string;
  summary: string;
  priority: string;
  status: string;
  source: string;
  org_name: string;
  org_short_name: string;
  org_color: string;
  assignee_name: string | null;
  affected_hostname: string | null;
  affected_ip: string | null;
  mitre_techniques: string[];
  created_at: string;
}

interface Org {
  id: string;
  name: string;
  short_name: string;
  color: string;
  open_ticket_count: number;
  critical_ticket_count: number;
  total_ticket_count: number;
  endpoints_count: number;
  status: string;
}

interface Analyst {
  id: string;
  name: string;
  role: string;
  shift: string;
  ticket_count: number;
  p1_count: number;
  is_online: boolean;
}

// ─── Styles ───────────────────────────────────────────────────────
var s = {
  page: { background: T.bg, color: T.text, fontFamily: T.fontUI, minHeight: "100vh", padding: "0" } as React.CSSProperties,
  header: { display: "flex", alignItems: "center", justifyContent: "space-between", padding: "16px 24px", borderBottom: "1px solid " + T.border, background: T.bgCard } as React.CSSProperties,
  logo: { display: "flex", alignItems: "center", gap: "12px" } as React.CSSProperties,
  logoIcon: { width: 36, height: 36, borderRadius: 10, background: "linear-gradient(135deg, #3b82f6, #a78bfa)", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 16, color: "#fff" } as React.CSSProperties,
  logoText: { fontWeight: 700, fontSize: 16, letterSpacing: "-0.02em" } as React.CSSProperties,
  body: { padding: "20px 24px", maxWidth: 1600, margin: "0 auto" } as React.CSSProperties,
  grid4: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 20 } as React.CSSProperties,
  grid3: { display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: 16, marginBottom: 20 } as React.CSSProperties,
  grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 } as React.CSSProperties,
  card: { background: T.bgCard, border: "1px solid " + T.border, borderRadius: 12, padding: "16px 20px" } as React.CSSProperties,
  cardTitle: { fontSize: 11, fontWeight: 600, color: T.textMuted, textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 12 },
  kpiVal: { fontSize: 32, fontWeight: 700, fontFamily: T.font, lineHeight: 1 } as React.CSSProperties,
  kpiLabel: { fontSize: 11, color: T.textMuted, marginTop: 4 } as React.CSSProperties,
  badge: (c: string, bg: string) => ({ display: "inline-block", padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 600, color: c, background: bg }) as React.CSSProperties,
  dot: (c: string) => ({ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: c, marginRight: 6 }) as React.CSSProperties,
  tableRow: { display: "flex", alignItems: "center", padding: "10px 12px", borderBottom: "1px solid " + T.border, fontSize: 13, gap: 12 } as React.CSSProperties,
  btn: { padding: "6px 14px", background: "transparent", border: "1px solid " + T.border, borderRadius: 8, color: T.textSec, fontSize: 12, cursor: "pointer" } as React.CSSProperties,
};

// ─── KPI Card ─────────────────────────────────────────────────────
function KPI(p: { label: string; value: string | number; color?: string; sub?: string }) {
  return (
    <div style={s.card}>
      <div style={s.cardTitle}>{p.label}</div>
      <div style={{ ...s.kpiVal, color: p.color || T.text }}>{p.value}</div>
      {p.sub && <div style={s.kpiLabel}>{p.sub}</div>}
    </div>
  );
}

// ─── Priority Badge ───────────────────────────────────────────────
function PriBadge(p: { pri: string }) {
  var cfg = PRI[p.pri] || PRI.P3;
  return <span style={s.badge(cfg.c, cfg.bg)}>{p.pri}</span>;
}

// ─── Status Badge ─────────────────────────────────────────────────
function StsBadge(p: { status: string }) {
  var cfg = STS[p.status] || { l: p.status, c: T.textMuted };
  return <span style={{ ...s.badge(cfg.c, "rgba(255,255,255,0.05)"), border: "1px solid " + cfg.c + "33" }}>{cfg.l}</span>;
}

// ─── Org Badge ────────────────────────────────────────────────────
function OrgBadge(p: { name: string; color: string }) {
  return <span style={{ ...s.badge(p.color, p.color + "18"), border: "1px solid " + p.color + "33" }}>{p.name}</span>;
}

// ─── Ticket Row ───────────────────────────────────────────────────
function TicketRow(p: { t: Ticket }) {
  var t = p.t;
  return (
    <div style={s.tableRow}>
      <div style={{ width: 90, fontFamily: T.font, fontSize: 12, color: T.textSec }}>{t.external_key}</div>
      <div style={{ width: 50 }}><PriBadge pri={t.priority} /></div>
      <div style={{ flex: 1, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>{t.summary}</div>
      <div style={{ width: 90 }}><OrgBadge name={t.org_short_name || "?"} color={t.org_color || T.accent} /></div>
      <div style={{ width: 100 }}><StsBadge status={t.status} /></div>
      <div style={{ width: 80, fontSize: 11, color: T.textSec }}>{t.assignee_name || "—"}</div>
      <div style={{ width: 50, fontSize: 11, color: T.textMuted, textAlign: "right" as const }}>{ago(t.created_at)}</div>
    </div>
  );
}

// ─── Source Bar ───────────────────────────────────────────────────
function SourceBar(p: { sources: Record<string, number> }) {
  var total = Object.values(p.sources).reduce(function(a, b) { return a + b; }, 0) || 1;
  var sorted = Object.entries(p.sources).sort(function(a, b) { return b[1] - a[1]; });
  return (
    <div>
      {sorted.map(function(entry) {
        var key = entry[0];
        var count = entry[1];
        var cfg = SRC[key] || { l: key, c: T.textMuted };
        var pct = Math.round((count / total) * 100);
        return (
          <div key={key} style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <div style={{ width: 80, fontSize: 11, color: T.textSec }}>{cfg.l}</div>
            <div style={{ flex: 1, height: 6, background: T.border, borderRadius: 3, overflow: "hidden" }}>
              <div style={{ width: pct + "%", height: "100%", background: cfg.c, borderRadius: 3 }}></div>
            </div>
            <div style={{ width: 30, fontSize: 11, color: T.textMuted, textAlign: "right" as const }}>{count}</div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Org Health Row ───────────────────────────────────────────────
function OrgRow(p: { org: Org }) {
  var o = p.org;
  return (
    <div style={s.tableRow}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, width: 140 }}>
        <span style={s.dot(o.color)}></span>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{o.short_name}</span>
        <span style={{ fontSize: 11, color: T.textMuted }}>{o.name}</span>
      </div>
      <div style={{ width: 60, textAlign: "center" as const }}>
        <span style={{ fontFamily: T.font, fontSize: 14, fontWeight: 600 }}>{o.open_ticket_count}</span>
      </div>
      <div style={{ width: 50, textAlign: "center" as const }}>
        {o.critical_ticket_count > 0 && <span style={s.badge(T.red, "rgba(239,68,68,0.15)")}>{o.critical_ticket_count} P1</span>}
      </div>
      <div style={{ width: 60, textAlign: "center" as const, fontSize: 12, color: T.textSec }}>{o.endpoints_count}</div>
      <div style={{ flex: 1 }}></div>
    </div>
  );
}

// ─── Analyst Row ──────────────────────────────────────────────────
function AnalystRow(p: { a: Analyst }) {
  var a = p.a;
  return (
    <div style={s.tableRow}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
        <span style={s.dot(a.is_online ? T.green : T.textMuted)}></span>
        <span style={{ fontWeight: 500 }}>{a.name}</span>
        <span style={{ fontSize: 11, color: T.textMuted }}>{a.role.replace("soc_", "").replace("_", " ")}</span>
      </div>
      <div style={{ width: 50, textAlign: "center" as const }}>
        <span style={{ fontFamily: T.font, fontWeight: 600 }}>{a.ticket_count}</span>
      </div>
      <div style={{ width: 40, textAlign: "center" as const }}>
        {a.p1_count > 0 && <span style={s.badge(T.red, "rgba(239,68,68,0.15)")}>{a.p1_count}</span>}
      </div>
      <div style={{ width: 60, fontSize: 11, color: T.textMuted }}>{a.shift || "—"}</div>
    </div>
  );
}

// ─── Priority Ring ────────────────────────────────────────────────
function PriorityRing(p: { kpis: KPIs }) {
  var k = p.kpis;
  var items = [
    { l: "P1", v: k.p1_count, c: T.red },
    { l: "P2", v: k.p2_count, c: T.orange },
    { l: "P3", v: k.p3_count, c: T.yellow },
    { l: "P4", v: k.p4_count, c: T.cyan },
  ];
  return (
    <div style={{ display: "flex", gap: 16 }}>
      {items.map(function(it) {
        return (
          <div key={it.l} style={{ textAlign: "center" as const }}>
            <div style={{ width: 48, height: 48, borderRadius: "50%", border: "3px solid " + it.c, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: T.font, fontWeight: 700, fontSize: 16, color: it.c }}>{it.v}</div>
            <div style={{ fontSize: 10, color: T.textMuted, marginTop: 4 }}>{it.l}</div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────
export default function Dashboard() {
  var auth = useAuth();
  var [kpis, setKpis] = useState<KPIs | null>(null);
  var [tickets, setTickets] = useState<Ticket[]>([]);
  var [orgs, setOrgs] = useState<Org[]>([]);
  var [analysts, setAnalysts] = useState<Analyst[]>([]);
  var [loading, setLoading] = useState(true);
  var [lastRefresh, setLastRefresh] = useState(new Date());

  var fetchAll = useCallback(async function() {
    try {
      var results = await Promise.allSettled([
        api.get<KPIs>("/dashboard/kpis"),
        api.get<Ticket[]>("/tickets?limit=20"),
        api.get<Org[]>("/organizations"),
        api.get<Analyst[]>("/users/analysts"),
      ]);

      if (results[0].status === "fulfilled") setKpis(results[0].value.data);
      if (results[1].status === "fulfilled") setTickets(results[1].value.data);
      if (results[2].status === "fulfilled") setOrgs(results[2].value.data);
      if (results[3].status === "fulfilled") setAnalysts(results[3].value.data);

      setLastRefresh(new Date());
    } catch (e) {
      console.error("Fetch error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(function() {
    fetchAll();
    var iv = setInterval(fetchAll, 30000);
    return function() { clearInterval(iv); };
  }, [fetchAll]);

  if (loading) {
    return (
      <div style={{ ...s.page, display: "flex", alignItems: "center", justifyContent: "center", height: "100vh" }}>
        <div style={{ color: T.textMuted, fontSize: 14 }}>Loading SOC data...</div>
      </div>
    );
  }

  var k = kpis || { open_tickets: 0, p1_count: 0, p2_count: 0, p3_count: 0, p4_count: 0, unassigned: 0, mttr_minutes: 0, sla_compliance: 100, resolved_this_month: 0, tickets_this_month: 0, by_org: {}, by_source: {} };

  return (
    <div style={s.page}>
      {/* ─── Header ──────────────────────────────────────── */}
      <div style={s.header}>
        <div style={s.logo}>
          <div style={s.logoIcon}>D</div>
          <div>
            <div style={s.logoText}>DACTA SOC</div>
            <div style={{ fontSize: 10, color: T.textMuted }}>Command Center</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ fontSize: 11, color: T.textMuted }}>
            Last refresh: {lastRefresh.toLocaleTimeString()}
          </div>
          <button onClick={fetchAll} style={s.btn}>⟳ Refresh</button>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: T.accent, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#fff" }}>
              {(auth.user?.name || "A").charAt(0)}
            </div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 600 }}>{auth.user?.name}</div>
              <div style={{ fontSize: 10, color: T.textMuted }}>{auth.user?.role}</div>
            </div>
          </div>
          <button onClick={auth.logout} style={{ ...s.btn, color: T.red, borderColor: "rgba(239,68,68,0.3)" }}>Sign Out</button>
        </div>
      </div>

      {/* ─── Body ────────────────────────────────────────── */}
      <div style={s.body}>
        {/* KPI Row */}
        <div style={s.grid4}>
          <KPI label="Open Tickets" value={k.open_tickets} color={k.p1_count > 0 ? T.red : T.text} sub={k.p1_count + " critical, " + k.unassigned + " unassigned"} />
          <KPI label="MTTR" value={k.mttr_minutes > 0 ? Math.round(k.mttr_minutes / 60) + "h " + (k.mttr_minutes % 60) + "m" : "—"} color={T.cyan} sub="Mean time to resolve" />
          <KPI label="SLA Compliance" value={k.sla_compliance + "%"} color={k.sla_compliance >= 95 ? T.green : k.sla_compliance >= 90 ? T.yellow : T.red} sub={k.tickets_this_month + " tickets this month"} />
          <KPI label="Resolved (MTD)" value={k.resolved_this_month} color={T.green} sub="Month to date" />
        </div>

        {/* Priority + Sources */}
        <div style={s.grid3}>
          <div style={s.card}>
            <div style={s.cardTitle}>Priority Breakdown</div>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <PriorityRing kpis={k} />
              <div style={{ textAlign: "right" as const }}>
                <div style={{ fontSize: 40, fontWeight: 700, fontFamily: T.font, color: T.text }}>{k.open_tickets}</div>
                <div style={{ fontSize: 11, color: T.textMuted }}>total open</div>
              </div>
            </div>
          </div>
          <div style={s.card}>
            <div style={s.cardTitle}>By Source</div>
            <SourceBar sources={k.by_source} />
          </div>
          <div style={s.card}>
            <div style={s.cardTitle}>Unassigned</div>
            <div style={{ ...s.kpiVal, color: k.unassigned > 3 ? T.orange : T.text, marginBottom: 8 }}>{k.unassigned}</div>
            <div style={{ fontSize: 12, color: T.textMuted }}>tickets need attention</div>
          </div>
        </div>

        {/* Ticket Queue + Sidebar */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 360px", gap: 16, marginBottom: 20 }}>
          {/* Ticket Queue */}
          <div style={s.card}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={s.cardTitle}>Ticket Queue</div>
              <div style={{ fontSize: 11, color: T.textMuted }}>{tickets.length} tickets</div>
            </div>
            {/* Header */}
            <div style={{ ...s.tableRow, borderBottom: "1px solid " + T.borderLight, fontSize: 11, color: T.textMuted, fontWeight: 600 }}>
              <div style={{ width: 90 }}>ID</div>
              <div style={{ width: 50 }}>PRI</div>
              <div style={{ flex: 1 }}>Summary</div>
              <div style={{ width: 90 }}>Org</div>
              <div style={{ width: 100 }}>Status</div>
              <div style={{ width: 80 }}>Assignee</div>
              <div style={{ width: 50, textAlign: "right" as const }}>Age</div>
            </div>
            {/* Rows */}
            {tickets.map(function(t) {
              return <TicketRow key={t.id} t={t} />;
            })}
            {tickets.length === 0 && (
              <div style={{ padding: 40, textAlign: "center" as const, color: T.textMuted, fontSize: 13 }}>No tickets found</div>
            )}
          </div>

          {/* Right sidebar */}
          <div style={{ display: "flex", flexDirection: "column" as const, gap: 16 }}>
            {/* Org Health */}
            <div style={s.card}>
              <div style={s.cardTitle}>Client Health</div>
              {/* Header */}
              <div style={{ ...s.tableRow, fontSize: 10, color: T.textMuted, fontWeight: 600, padding: "6px 12px" }}>
                <div style={{ width: 140 }}>Organization</div>
                <div style={{ width: 60, textAlign: "center" as const }}>Open</div>
                <div style={{ width: 50, textAlign: "center" as const }}>Crit</div>
                <div style={{ width: 60, textAlign: "center" as const }}>EP</div>
                <div style={{ flex: 1 }}></div>
              </div>
              {orgs.map(function(o) {
                return <OrgRow key={o.id} org={o} />;
              })}
            </div>

            {/* Analyst Workload */}
            <div style={s.card}>
              <div style={s.cardTitle}>Analyst Workload</div>
              {/* Header */}
              <div style={{ ...s.tableRow, fontSize: 10, color: T.textMuted, fontWeight: 600, padding: "6px 12px" }}>
                <div style={{ flex: 1 }}>Analyst</div>
                <div style={{ width: 50, textAlign: "center" as const }}>Load</div>
                <div style={{ width: 40, textAlign: "center" as const }}>P1</div>
                <div style={{ width: 60 }}>Shift</div>
              </div>
              {analysts.map(function(a) {
                return <AnalystRow key={a.id} a={a} />;
              })}
              {analysts.length === 0 && (
                <div style={{ padding: 20, textAlign: "center" as const, color: T.textMuted, fontSize: 12 }}>No analyst data</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
