import React, { useState, useEffect, useCallback } from 'react'
import {
  Search,
  RefreshCw,
  ChevronRight,
  Brain,
  CheckCircle2,
  AlertCircle,
  Clock,
  User,
  Building2,
  Tag,
  Zap,
  ShieldCheck,
  Edit3,
  ExternalLink,
} from 'lucide-react'
import { supabase } from '../lib/supabase'
import { useOrganizations } from '../hooks/useOrganizations'
import { useRealtime } from '../hooks/useRealtime'
import { Panel } from '../components/ui/Modal'
import { PriorityBadge, VerdictBadge, StatusBadge } from '../components/ui/Badge'
import { FilterChip, FilterChipGroup } from '../components/ui/FilterChip'
import { Card } from '../components/ui/Card'
import { Loader } from '../components/ui/Loader'
import { EmptyState } from '../components/ui/EmptyState'
import type { Ticket, AIInvestigationBrief, Organization } from '../types/database'

type Priority = 'P1' | 'P2' | 'P3' | 'P4'
type TicketStatus = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed' | 'false_positive'
type VerdictType = 'true_positive' | 'false_positive' | 'benign' | 'under_review'

interface TicketWithOrg extends Ticket {
  org?: Organization
}

interface Filters {
  search: string
  priority: Priority | ''
  status: TicketStatus | ''
  orgId: string
  assignee: string
  verdict: VerdictType | ''
}

const defaultFilters: Filters = {
  search: '',
  priority: '',
  status: '',
  orgId: '',
  assignee: '',
  verdict: '',
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100)
  const color = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f59e0b' : '#22c55e'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] text-[#64748b]">Confidence</span>
        <span className="text-xs font-bold" style={{ color }}>{pct}%</span>
      </div>
      <div className="confidence-bar">
        <div className="confidence-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

interface InvestigationPanelProps {
  ticket: TicketWithOrg | null
  open: boolean
  onClose: () => void
  onVerdictOverride: (ticketId: string, verdict: VerdictType, note: string) => Promise<void>
}

function InvestigationPanel({ ticket, open, onClose, onVerdictOverride }: InvestigationPanelProps) {
  const [briefs, setBriefs] = useState<AIInvestigationBrief[]>([])
  const [briefsLoading, setBriefsLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'ai' | 'details' | 'timeline'>('ai')
  const [overrideVote, setOverrideVote] = useState<VerdictType | ''>('')
  const [overrideNote, setOverrideNote] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (ticket && open) {
      setBriefsLoading(true)
      supabase
        .from('ai_investigation_briefs')
        .select('*')
        .eq('ticket_id', ticket.id)
        .order('round', { ascending: true })
        .then(({ data }) => {
          setBriefs(data ?? [])
          setBriefsLoading(false)
        })
    }
  }, [ticket, open])

  const handleOverride = async () => {
    if (!ticket || !overrideVote) return
    setSubmitting(true)
    await onVerdictOverride(ticket.id, overrideVote, overrideNote)
    setSubmitting(false)
    setOverrideVote('')
    setOverrideNote('')
  }

  const latestBrief = briefs[briefs.length - 1]

  if (!ticket) return null

  const tabClass = (tab: string) =>
    `px-3 py-2 text-xs font-medium transition-colors border-b-2 ${activeTab === tab
      ? 'text-[#38bdf8] border-[#38bdf8]'
      : 'text-[#64748b] border-transparent hover:text-[#94a3b8]'}`

  return (
    <Panel
      open={open}
      onClose={onClose}
      title={ticket.ticket_number}
      subtitle={ticket.title}
      width="580px"
    >
      {/* Ticket header */}
      <div className="px-5 pt-4 pb-3 border-b border-[rgba(56,189,248,0.08)]">
        <div className="flex flex-wrap gap-2 mb-3">
          <PriorityBadge priority={ticket.priority} />
          <StatusBadge status={ticket.status} />
          <VerdictBadge verdict={ticket.verdict} />
        </div>
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex items-center gap-1.5 text-[#64748b]">
            <Building2 size={12} strokeWidth={1.5} />
            <span>{ticket.org?.name ?? 'Unknown Org'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-[#64748b]">
            <User size={12} strokeWidth={1.5} />
            <span>{ticket.assignee_id ?? 'Unassigned'}</span>
          </div>
          <div className="flex items-center gap-1.5 text-[#64748b]">
            <Clock size={12} strokeWidth={1.5} />
            <span>{new Date(ticket.created_at).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-1.5 text-[#64748b]">
            <ExternalLink size={12} strokeWidth={1.5} />
            <span className="text-[#38bdf8]">Jira</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[rgba(56,189,248,0.08)] px-5">
        <button className={tabClass('ai')} onClick={() => setActiveTab('ai')}>
          <span className="flex items-center gap-1.5"><Brain size={12} strokeWidth={1.5} />AI Triage</span>
        </button>
        <button className={tabClass('details')} onClick={() => setActiveTab('details')}>Details</button>
        <button className={tabClass('timeline')} onClick={() => setActiveTab('timeline')}>Timeline</button>
      </div>

      {/* Tab content */}
      <div className="p-5 space-y-4">
        {activeTab === 'ai' && (
          <>
            {briefsLoading ? (
              <Loader variant="card" />
            ) : briefs.length === 0 ? (
              <EmptyState
                title="No AI analysis yet"
                description="AI investigation briefs will appear here once the ticket has been processed."
                icon="search"
              />
            ) : (
              <div className="space-y-4">
                {/* Latest brief summary */}
                {latestBrief && (
                  <div className="bg-[rgba(56,189,248,0.04)] border border-[rgba(56,189,248,0.12)] rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Brain size={14} strokeWidth={1.5} className="text-[#38bdf8]" />
                        <span className="text-xs font-semibold text-[#e2e8f0]">Round {latestBrief.round} Analysis</span>
                        {latestBrief.analyst_override && (
                          <span className="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded">
                            Analyst Override
                          </span>
                        )}
                      </div>
                      <VerdictBadge verdict={latestBrief.verdict} />
                    </div>

                    <ConfidenceMeter value={latestBrief.confidence} />

                    <div>
                      <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-1">Findings</p>
                      <p className="text-xs text-[#94a3b8] leading-relaxed">{latestBrief.findings}</p>
                    </div>

                    {latestBrief.recommended_actions && latestBrief.recommended_actions.length > 0 && (
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Recommended Actions</p>
                        <ul className="space-y-1.5">
                          {latestBrief.recommended_actions.map((action, i) => (
                            <li key={i} className="flex items-start gap-2 text-xs text-[#94a3b8]">
                              <CheckCircle2 size={12} strokeWidth={1.5} className="text-[#38bdf8] mt-0.5 flex-shrink-0" />
                              {action}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {latestBrief.mitre_techniques && latestBrief.mitre_techniques.length > 0 && (
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">MITRE Techniques</p>
                        <div className="flex flex-wrap gap-1.5">
                          {latestBrief.mitre_techniques.map(t => (
                            <span key={t} className="text-[11px] bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded font-mono">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* All rounds */}
                {briefs.length > 1 && (
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Investigation Rounds</p>
                    <div className="space-y-2">
                      {briefs.map(brief => (
                        <div key={brief.id} className="flex items-center gap-3 bg-[rgba(255,255,255,0.02)] rounded-lg px-3 py-2">
                          <div className="w-5 h-5 rounded-full bg-[rgba(56,189,248,0.1)] flex items-center justify-center text-[10px] font-bold text-[#38bdf8]">
                            {brief.round}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <VerdictBadge verdict={brief.verdict} />
                              <span className="text-[11px] text-[#64748b]">{Math.round(brief.confidence * 100)}% confidence</span>
                            </div>
                            <p className="text-[11px] text-[#94a3b8] mt-0.5 truncate">{brief.findings.slice(0, 80)}…</p>
                          </div>
                          <span className="text-[10px] text-[#64748b] font-mono">{brief.model_used}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Analyst Override */}
            <div className="border border-[rgba(255,255,255,0.08)] rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Edit3 size={13} strokeWidth={1.5} className="text-[#64748b]" />
                <span className="text-xs font-semibold text-[#94a3b8]">Analyst Override</span>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-[11px] text-[#64748b] mb-1.5">Override Verdict</label>
                  <select
                    value={overrideVote}
                    onChange={e => setOverrideVote(e.target.value as VerdictType | '')}
                    className="mcc-input text-xs"
                  >
                    <option value="">— Select verdict —</option>
                    <option value="true_positive">True Positive</option>
                    <option value="false_positive">False Positive</option>
                    <option value="benign">Benign</option>
                    <option value="under_review">Under Review</option>
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] text-[#64748b] mb-1.5">Analyst Note</label>
                  <textarea
                    value={overrideNote}
                    onChange={e => setOverrideNote(e.target.value)}
                    placeholder="Add context for this verdict override…"
                    rows={3}
                    className="mcc-input text-xs resize-none"
                  />
                </div>
                <button
                  onClick={handleOverride}
                  disabled={!overrideVote || submitting}
                  className="btn-primary text-xs py-2 w-full disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {submitting ? (
                    <span className="w-3.5 h-3.5 border-2 border-[#080d1a]/30 border-t-[#080d1a] rounded-full animate-spin" />
                  ) : (
                    <ShieldCheck size={13} strokeWidth={1.5} />
                  )}
                  Apply Override
                </button>
              </div>
            </div>
          </>
        )}

        {activeTab === 'details' && (
          <div className="space-y-4">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Summary</p>
              <p className="text-xs text-[#94a3b8] leading-relaxed">{ticket.summary ?? ticket.description ?? 'No description provided.'}</p>
            </div>
            {ticket.tags && ticket.tags.length > 0 && (
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Tags</p>
                <div className="flex flex-wrap gap-1.5">
                  {ticket.tags.map(tag => (
                    <span key={tag} className="inline-flex items-center gap-1 text-[11px] bg-[rgba(255,255,255,0.05)] text-[#94a3b8] border border-[rgba(255,255,255,0.08)] px-2 py-0.5 rounded">
                      <Tag size={9} strokeWidth={1.5} />{tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Severity Score', value: ticket.severity_score ?? '—' },
                { label: 'Source', value: ticket.source ?? 'Jira' },
                { label: 'Source Ref', value: ticket.source_ref ?? '—' },
                { label: 'SLA Breached', value: ticket.sla_breached ? 'Yes' : 'No' },
              ].map(item => (
                <div key={item.label} className="bg-[rgba(255,255,255,0.02)] rounded-lg p-3">
                  <p className="text-[10px] text-[#64748b] uppercase tracking-wider mb-1">{item.label}</p>
                  <p className={`text-xs font-medium ${item.label === 'SLA Breached' && item.value === 'Yes' ? 'text-red-400' : 'text-[#e2e8f0]'}`}>
                    {String(item.value)}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="space-y-3">
            {[
              { time: ticket.created_at, label: 'Ticket Created', icon: AlertCircle, color: 'text-blue-400' },
              ...(ticket.resolved_at ? [{ time: ticket.resolved_at, label: 'Resolved', icon: CheckCircle2, color: 'text-green-400' }] : []),
            ].sort((a, b) => new Date(b.time).getTime() - new Date(a.time).getTime()).map((event, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className={`mt-0.5 ${event.color}`}>
                  <event.icon size={14} strokeWidth={1.5} />
                </div>
                <div>
                  <p className="text-xs font-medium text-[#e2e8f0]">{event.label}</p>
                  <p className="text-[11px] text-[#64748b]">{new Date(event.time).toLocaleString()}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Panel>
  )
}

export function AlertTriagePage() {
  const { organizations } = useOrganizations()
  const [tickets, setTickets] = useState<TicketWithOrg[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState<Filters>(defaultFilters)
  const [selectedTicket, setSelectedTicket] = useState<TicketWithOrg | null>(null)
  const [panelOpen, setPanelOpen] = useState(false)

  const loadTickets = useCallback(async () => {
    setLoading(true)
    try {
      const { data, error } = await supabase
        .from('tickets')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(200)

      if (error) throw error

      const orgsMap = new Map(organizations.map(o => [o.id, o]))
      const withOrg: TicketWithOrg[] = (data ?? []).map(t => ({
        ...t,
        org: orgsMap.get(t.org_id),
      }))
      setTickets(withOrg)
    } catch (err) {
      console.error('Triage load error:', err)
    } finally {
      setLoading(false)
    }
  }, [organizations])

  useEffect(() => {
    loadTickets()
  }, [loadTickets])

  useRealtime<Record<string, unknown>>({
    table: 'tickets',
    event: '*',
    onChange: loadTickets,
  })

  const handleVerdictOverride = async (ticketId: string, verdict: string, note: string) => {
    // Update the ticket verdict
    await supabase
      .from('tickets')
      .update({ verdict: verdict as VerdictType, updated_at: new Date().toISOString() })
      .eq('id', ticketId)

    // Also create/update the latest AI brief with the override
    const { data: briefs } = await supabase
      .from('ai_investigation_briefs')
      .select('id')
      .eq('ticket_id', ticketId)
      .order('round', { ascending: false })
      .limit(1)

    if (briefs && briefs.length > 0) {
      await supabase
        .from('ai_investigation_briefs')
        .update({ analyst_override: true, analyst_verdict: verdict, analyst_note: note })
        .eq('id', briefs[0].id)
    }

    await loadTickets()
  }

  // Filtered tickets
  const filtered = tickets.filter(t => {
    if (filters.search) {
      const q = filters.search.toLowerCase()
      if (
        !t.title.toLowerCase().includes(q) &&
        !t.ticket_number.toLowerCase().includes(q) &&
        !(t.org?.name ?? '').toLowerCase().includes(q)
      ) return false
    }
    if (filters.priority && t.priority !== filters.priority) return false
    if (filters.status && t.status !== filters.status) return false
    if (filters.orgId && t.org_id !== filters.orgId) return false
    if (filters.verdict) {
      if (!t.verdict || t.verdict !== filters.verdict) return false
    }
    return true
  })

  const openPanel = (ticket: TicketWithOrg) => {
    setSelectedTicket(ticket)
    setPanelOpen(true)
  }

  const priorityRowClass = (priority: string) => {
    switch (priority) {
      case 'P1': return 'border-l-2 border-l-red-500/60'
      case 'P2': return 'border-l-2 border-l-orange-500/60'
      case 'P3': return 'border-l-2 border-l-amber-500/60'
      default: return 'border-l-2 border-l-blue-500/60'
    }
  }

  const formatTime = (dateStr: string) => {
    const d = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
    return `${Math.floor(diffMins / 1440)}d ago`
  }

  const activeFilterCount = Object.entries(filters).filter(([k, v]) => k !== 'search' && v !== '').length

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="px-6 pt-6 pb-4 flex-shrink-0">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-lg font-bold text-[#e2e8f0] font-[Sora]">Alert Triage</h1>
            <p className="text-xs text-[#64748b]">
              {loading ? 'Loading…' : `${filtered.length} of ${tickets.length} alerts`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={loadTickets} disabled={loading} className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
              <RefreshCw size={12} strokeWidth={1.5} className={loading ? 'animate-spin' : ''} />
              Refresh
            </button>
          </div>
        </div>

        {/* Search + Filters */}
        <div className="space-y-3">
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" strokeWidth={1.5} />
            <input
              type="text"
              placeholder="Search by title, ticket number, or organization…"
              value={filters.search}
              onChange={e => setFilters(f => ({ ...f, search: e.target.value }))}
              className="mcc-input pl-8 text-xs w-full"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] text-[#64748b] whitespace-nowrap">Filter:</span>
            <FilterChipGroup>
              {(['P1', 'P2', 'P3', 'P4'] as Priority[]).map(p => (
                <FilterChip
                  key={p}
                  label={p}
                  active={filters.priority === p}
                  onClick={() => setFilters(f => ({ ...f, priority: f.priority === p ? '' : p }))}
                />
              ))}
              <div className="w-px h-4 bg-[rgba(255,255,255,0.1)]" />
              {(['open', 'in_progress', 'resolved'] as TicketStatus[]).map(s => (
                <FilterChip
                  key={s}
                  label={s.replace('_', ' ')}
                  active={filters.status === s}
                  onClick={() => setFilters(f => ({ ...f, status: f.status === s ? '' : s }))}
                />
              ))}
              <div className="w-px h-4 bg-[rgba(255,255,255,0.1)]" />
              {(['true_positive', 'false_positive', 'benign'] as VerdictType[]).map(v => (
                <FilterChip
                  key={v}
                  label={v.replace('_', ' ')}
                  active={filters.verdict === v}
                  onClick={() => setFilters(f => ({ ...f, verdict: f.verdict === v ? '' : v }))}
                />
              ))}
              {organizations.length > 0 && (
                <>
                  <div className="w-px h-4 bg-[rgba(255,255,255,0.1)]" />
                  <select
                    value={filters.orgId}
                    onChange={e => setFilters(f => ({ ...f, orgId: e.target.value }))}
                    className="bg-[rgba(255,255,255,0.03)] text-[#94a3b8] border border-[rgba(255,255,255,0.08)] rounded-md px-2 py-1 text-xs outline-none hover:border-[rgba(56,189,248,0.2)] transition-colors"
                  >
                    <option value="">All Orgs</option>
                    {organizations.map(o => (
                      <option key={o.id} value={o.id}>{o.name}</option>
                    ))}
                  </select>
                </>
              )}
              {activeFilterCount > 0 && (
                <button
                  onClick={() => setFilters(defaultFilters)}
                  className="text-[11px] text-red-400 hover:text-red-300 transition-colors"
                >
                  Clear filters ({activeFilterCount})
                </button>
              )}
            </FilterChipGroup>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto px-6 pb-6">
        <Card padding="none">
          {loading ? (
            <div className="p-6"><Loader variant="table" rows={8} /></div>
          ) : filtered.length === 0 ? (
            <EmptyState
              title="No alerts found"
              description="No alerts match your current filters. Try adjusting the search or filter criteria."
              icon="shield"
            />
          ) : (
            <table className="mcc-table">
              <thead className="sticky top-0 z-10">
                <tr>
                  <th className="w-16">Priority</th>
                  <th>Summary</th>
                  <th className="w-36">Organization</th>
                  <th className="w-28">Status</th>
                  <th className="w-32">Verdict</th>
                  <th className="w-24">Source</th>
                  <th className="w-24">Created</th>
                  <th className="w-10"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(ticket => (
                  <tr
                    key={ticket.id}
                    className={`cursor-pointer ${priorityRowClass(ticket.priority)}`}
                    onClick={() => openPanel(ticket)}
                  >
                    <td>
                      <PriorityBadge priority={ticket.priority} />
                    </td>
                    <td>
                      <div>
                        <p className="text-xs font-medium text-[#e2e8f0] truncate max-w-[280px]">{ticket.title}</p>
                        <p className="text-[11px] text-[#64748b] font-mono">{ticket.ticket_number}</p>
                      </div>
                    </td>
                    <td>
                      <span className="text-xs text-[#94a3b8] truncate block max-w-[140px]">
                        {ticket.org?.name ?? <span className="text-[#64748b] italic">Unknown</span>}
                      </span>
                    </td>
                    <td><StatusBadge status={ticket.status} /></td>
                    <td><VerdictBadge verdict={ticket.verdict} /></td>
                    <td>
                      <span className="text-xs text-[#38bdf8]">Jira</span>
                    </td>
                    <td>
                      <span className="text-xs text-[#64748b] whitespace-nowrap">{formatTime(ticket.created_at)}</span>
                    </td>
                    <td>
                      <ChevronRight size={14} strokeWidth={1.5} className="text-[#64748b]" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {/* Investigation Panel */}
      <InvestigationPanel
        ticket={selectedTicket}
        open={panelOpen}
        onClose={() => { setPanelOpen(false); setSelectedTicket(null) }}
        onVerdictOverride={handleVerdictOverride}
      />
    </div>
  )
}
