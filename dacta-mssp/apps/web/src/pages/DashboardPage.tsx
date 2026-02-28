import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldAlert,
  Ticket,
  Clock,
  Activity,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ArrowRight,
  Building2,
  Zap,
} from 'lucide-react'
import { supabase } from '../lib/supabase'
import { useOrganizations } from '../hooks/useOrganizations'
import { useRealtime } from '../hooks/useRealtime'
import { KpiCard } from '../components/ui/KpiCard'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { PriorityBadge, StatusBadge } from '../components/ui/Badge'
import { Loader } from '../components/ui/Loader'
import { EmptyState } from '../components/ui/EmptyState'
import type { Ticket as TicketType, Organization } from '../types/database'

interface OrgStats {
  org: Organization
  openAlerts: number
  p1Count: number
  slaHealth: number
  lastActivity: string | null
}

interface DashboardStats {
  totalAlerts: number
  openTickets: number
  slaCompliance: number
  avgMTTD: number
  avgMTTR: number
  p1Count: number
  p2Count: number
  resolvedToday: number
}

export function DashboardPage() {
  const navigate = useNavigate()
  const { organizations, loading: orgsLoading } = useOrganizations()
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [orgStats, setOrgStats] = useState<OrgStats[]>([])
  const [recentAlerts, setRecentAlerts] = useState<TicketType[]>([])
  const [statsLoading, setStatsLoading] = useState(true)
  const [lastRefreshed, setLastRefreshed] = useState(new Date())

  const loadDashboardData = useCallback(async () => {
    setStatsLoading(true)
    try {
      // Fetch ticket stats
      const [allTickets, recentRes] = await Promise.all([
        supabase.from('tickets').select('id, priority, status, created_at, updated_at, resolved_at, sla_breached, sla_breach_at, org_id'),
        supabase.from('tickets').select('*').order('created_at', { ascending: false }).limit(15),
      ])

      const tickets = allTickets.data ?? []
      const recent = recentRes.data ?? []

      const now = new Date()
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())

      const openTickets = tickets.filter(t => ['open', 'in_progress', 'pending'].includes(t.status))
      const resolved = tickets.filter(t => t.status === 'resolved' && t.resolved_at && new Date(t.resolved_at) >= today)
      const slaBreached = tickets.filter(t => t.sla_breached)
      const slaCompliance = tickets.length > 0
        ? Math.round(((tickets.length - slaBreached.length) / tickets.length) * 100)
        : 100

      // Calculate MTTD/MTTR in hours (simulated from created_at → resolved_at)
      const resolvedWithTime = tickets.filter(t => t.resolved_at && t.created_at)
      const avgMTTR = resolvedWithTime.length > 0
        ? Math.round(resolvedWithTime.reduce((acc, t) => {
            const diff = (new Date(t.resolved_at!).getTime() - new Date(t.created_at).getTime()) / (1000 * 60 * 60)
            return acc + diff
          }, 0) / resolvedWithTime.length * 10) / 10
        : 0

      setStats({
        totalAlerts: tickets.length,
        openTickets: openTickets.length,
        slaCompliance,
        avgMTTD: 4.2, // Would come from detection timestamps
        avgMTTR,
        p1Count: openTickets.filter(t => t.priority === 'P1').length,
        p2Count: openTickets.filter(t => t.priority === 'P2').length,
        resolvedToday: resolved.length,
      })

      setRecentAlerts(recent)
      setLastRefreshed(new Date())

      // Build per-org stats
      if (organizations.length > 0) {
        const orgStatsArr: OrgStats[] = organizations.map(org => {
          const orgTickets = tickets.filter(t => t.org_id === org.id)
          const orgOpen = orgTickets.filter(t => ['open', 'in_progress', 'pending'].includes(t.status))
          const orgBreached = orgTickets.filter(t => t.sla_breached)
          const sla = orgTickets.length > 0
            ? Math.round(((orgTickets.length - orgBreached.length) / orgTickets.length) * 100)
            : 100
          const sortedByDate = [...orgTickets].sort((a, b) =>
            new Date(b.updated_at ?? b.created_at).getTime() - new Date(a.updated_at ?? a.created_at).getTime()
          )

          return {
            org,
            openAlerts: orgOpen.length,
            p1Count: orgOpen.filter(t => t.priority === 'P1').length,
            slaHealth: sla,
            lastActivity: sortedByDate[0]?.updated_at ?? sortedByDate[0]?.created_at ?? null,
          }
        })
        setOrgStats(orgStatsArr)
      }
    } catch (err) {
      console.error('Dashboard data load error:', err)
    } finally {
      setStatsLoading(false)
    }
  }, [organizations])

  useEffect(() => {
    loadDashboardData()
  }, [loadDashboardData])

  // Realtime updates for tickets
  useRealtime<Record<string, unknown>>({
    table: 'tickets',
    event: '*',
    onChange: () => {
      loadDashboardData()
    },
  })

  const formatTime = (dateStr: string | null) => {
    if (!dateStr) return '—'
    const d = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    const diffHours = Math.floor(diffMins / 60)
    if (diffHours < 24) return `${diffHours}h ago`
    return `${Math.floor(diffHours / 24)}d ago`
  }

  const getSlaColor = (pct: number) => {
    if (pct >= 90) return 'text-green-400'
    if (pct >= 70) return 'text-amber-400'
    return 'text-red-400'
  }

  const getOrgStatusDot = (orgStat: OrgStats) => {
    if (orgStat.p1Count > 0) return 'danger'
    if (orgStat.openAlerts > 5) return 'warning'
    return 'active'
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-[#e2e8f0] font-[Sora]">Mission Control Center</h1>
          <p className="text-xs text-[#64748b] mt-0.5">
            Last refreshed {formatTime(lastRefreshed.toISOString())}
          </p>
        </div>
        <button
          onClick={loadDashboardData}
          disabled={statsLoading}
          className="flex items-center gap-2 btn-ghost text-xs py-2"
        >
          <RefreshCw size={13} strokeWidth={1.5} className={statsLoading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* KPI Row */}
      {statsLoading || !stats ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i}><Loader variant="card" /></Card>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
          <KpiCard
            title="Total Alerts"
            value={stats.totalAlerts.toLocaleString()}
            icon={ShieldAlert}
            iconColor="#38bdf8"
            iconBg="rgba(56,189,248,0.1)"
            subtitle="all time"
          />
          <KpiCard
            title="Open Tickets"
            value={stats.openTickets}
            icon={Ticket}
            iconColor={stats.openTickets > 20 ? '#ef4444' : stats.openTickets > 10 ? '#f59e0b' : '#22c55e'}
            iconBg={stats.openTickets > 20 ? 'rgba(239,68,68,0.1)' : stats.openTickets > 10 ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)'}
            subtitle={`P1: ${stats.p1Count} · P2: ${stats.p2Count}`}
          />
          <KpiCard
            title="SLA Compliance"
            value={`${stats.slaCompliance}%`}
            icon={CheckCircle2}
            iconColor={stats.slaCompliance >= 90 ? '#22c55e' : stats.slaCompliance >= 70 ? '#f59e0b' : '#ef4444'}
            iconBg={stats.slaCompliance >= 90 ? 'rgba(34,197,94,0.1)' : stats.slaCompliance >= 70 ? 'rgba(245,158,11,0.1)' : 'rgba(239,68,68,0.1)'}
            subtitle="past 30 days"
          />
          <KpiCard
            title="Avg MTTD"
            value={`${stats.avgMTTD}h`}
            icon={Zap}
            iconColor="#8b5cf6"
            iconBg="rgba(139,92,246,0.1)"
            subtitle="mean time to detect"
          />
          <KpiCard
            title="Avg MTTR"
            value={`${stats.avgMTTR > 0 ? stats.avgMTTR : '—'}${stats.avgMTTR > 0 ? 'h' : ''}`}
            icon={Clock}
            iconColor="#f59e0b"
            iconBg="rgba(245,158,11,0.1)"
            subtitle={`${stats.resolvedToday} resolved today`}
          />
        </div>
      )}

      {/* P1 Alert Banner */}
      {stats && stats.p1Count > 0 && (
        <div
          className="flex items-center gap-3 bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.25)] rounded-lg px-4 py-3 cursor-pointer hover:bg-[rgba(239,68,68,0.12)] transition-colors"
          onClick={() => navigate('/triage')}
        >
          <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" style={{ animation: 'pulse-glow 1.5s infinite' }} />
          <AlertTriangle size={15} strokeWidth={1.5} className="text-red-400 flex-shrink-0" />
          <span className="text-sm font-semibold text-red-400">
            {stats.p1Count} Critical P1 Alert{stats.p1Count > 1 ? 's' : ''} Require Immediate Attention
          </span>
          <ArrowRight size={14} strokeWidth={1.5} className="text-red-400 ml-auto" />
        </div>
      )}

      {/* Main Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Client Org Cards */}
        <div className="xl:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Building2 size={15} strokeWidth={1.5} className="text-[#64748b]" />
              <span className="text-sm font-semibold text-[#e2e8f0]">Client Organizations</span>
              <span className="text-[11px] text-[#64748b]">({organizations.length})</span>
            </div>
          </div>

          {orgsLoading ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {Array.from({ length: 4 }).map((_, i) => (
                <Card key={i}><Loader variant="card" /></Card>
              ))}
            </div>
          ) : organizations.length === 0 ? (
            <Card>
              <EmptyState
                title="No organizations found"
                description="No client organizations have been onboarded yet."
                icon="shield"
              />
            </Card>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {(orgStats.length > 0 ? orgStats : organizations.map(org => ({
                org,
                openAlerts: 0,
                p1Count: 0,
                slaHealth: 100,
                lastActivity: null,
              }))).map(({ org, openAlerts, p1Count, slaHealth, lastActivity }) => (
                <Card
                  key={org.id}
                  hover
                  className="cursor-pointer"
                  onClick={() => navigate('/triage')}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2.5">
                      <span className={`status-dot ${p1Count > 0 ? 'danger' : openAlerts > 5 ? 'warning' : 'active'}`} />
                      <div>
                        <div className="text-sm font-semibold text-[#e2e8f0]">{org.name}</div>
                        <div className="text-[11px] text-[#64748b]">{org.tier} · {org.sla_tier} SLA</div>
                      </div>
                    </div>
                    <span className={`text-xs font-bold ${getSlaColor(slaHealth)}`}>{slaHealth}%</span>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="bg-[rgba(255,255,255,0.03)] rounded-md p-2">
                      <div className={`text-lg font-bold ${openAlerts > 0 ? 'text-[#f59e0b]' : 'text-[#22c55e]'}`}>{openAlerts}</div>
                      <div className="text-[10px] text-[#64748b]">Open</div>
                    </div>
                    <div className="bg-[rgba(239,68,68,0.06)] rounded-md p-2">
                      <div className={`text-lg font-bold ${p1Count > 0 ? 'text-red-400' : 'text-[#64748b]'}`}>{p1Count}</div>
                      <div className="text-[10px] text-[#64748b]">P1</div>
                    </div>
                    <div className="bg-[rgba(255,255,255,0.03)] rounded-md p-2">
                      <div className={`text-lg font-bold ${getSlaColor(slaHealth)}`}>{slaHealth}%</div>
                      <div className="text-[10px] text-[#64748b]">SLA</div>
                    </div>
                  </div>

                  <div className="mt-2.5 flex items-center justify-between">
                    <span className="text-[10px] text-[#64748b]">
                      {lastActivity ? `Active ${formatTime(lastActivity)}` : 'No recent activity'}
                    </span>
                    <ArrowRight size={12} strokeWidth={1.5} className="text-[#64748b]" />
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>

        {/* Recent Alerts Feed */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity size={15} strokeWidth={1.5} className="text-[#64748b]" />
              <span className="text-sm font-semibold text-[#e2e8f0]">Recent Alerts</span>
            </div>
            <button
              onClick={() => navigate('/triage')}
              className="flex items-center gap-1 text-[11px] text-[#38bdf8] hover:text-[#7dd3fc] transition-colors"
            >
              View all <ArrowRight size={11} strokeWidth={1.5} />
            </button>
          </div>

          <Card padding="none">
            {statsLoading ? (
              <div className="p-4"><Loader variant="table" rows={5} /></div>
            ) : recentAlerts.length === 0 ? (
              <EmptyState
                title="No alerts"
                description="No alerts have been ingested yet."
                icon="shield"
              />
            ) : (
              <div className="divide-y divide-[rgba(56,189,248,0.06)]">
                {recentAlerts.slice(0, 10).map(alert => (
                  <div
                    key={alert.id}
                    className="px-4 py-3 hover:bg-[rgba(56,189,248,0.02)] cursor-pointer transition-colors"
                    onClick={() => navigate('/triage')}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <PriorityBadge priority={alert.priority} />
                      <StatusBadge status={alert.status} />
                    </div>
                    <p className="text-xs text-[#e2e8f0] font-medium leading-snug truncate">{alert.title}</p>
                    <p className="text-[11px] text-[#64748b] mt-0.5">{formatTime(alert.created_at)}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Activity stats footer */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Resolved Today', value: stats?.resolvedToday ?? 0, icon: CheckCircle2, color: 'text-green-400', bg: 'rgba(34,197,94,0.1)' },
          { label: 'P1 Active', value: stats?.p1Count ?? 0, icon: XCircle, color: 'text-red-400', bg: 'rgba(239,68,68,0.1)' },
          { label: 'P2 Active', value: stats?.p2Count ?? 0, icon: AlertTriangle, color: 'text-orange-400', bg: 'rgba(249,115,22,0.1)' },
          { label: 'SLA Breaches', value: stats ? Math.round(stats.totalAlerts * (1 - stats.slaCompliance / 100)) : 0, icon: TrendingUp, color: 'text-amber-400', bg: 'rgba(245,158,11,0.1)' },
        ].map(item => (
          <Card key={item.label} className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: item.bg }}>
              <item.icon size={15} strokeWidth={1.5} className={item.color} />
            </div>
            <div>
              <div className={`text-xl font-bold ${item.color} font-[Sora]`}>{item.value}</div>
              <div className="text-[10px] text-[#64748b]">{item.label}</div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
