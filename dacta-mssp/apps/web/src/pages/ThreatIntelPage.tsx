import React, { useState, useEffect, useCallback } from 'react'
import {
  Search,
  RefreshCw,
  Upload,
  Download,
  Globe,
  Hash,
  Link,
  Mail,
  Cpu,
  Shield,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Plus,
  X,
  Activity,
} from 'lucide-react'
import { supabase } from '../lib/supabase'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { FilterChip, FilterChipGroup } from '../components/ui/FilterChip'
import { Loader } from '../components/ui/Loader'
import { EmptyState } from '../components/ui/EmptyState'
import { Panel } from '../components/ui/Modal'
import type { ThreatIntelIOC, ThreatIntelFeed } from '../types/database'

type IocType = 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cve' | 'other'
type VerdictFilter = 'malicious' | 'suspicious' | 'benign' | 'unknown' | ''

const IOC_TYPE_ICONS: Record<IocType, React.ElementType> = {
  ip: Globe,
  domain: Globe,
  url: Link,
  hash_md5: Hash,
  hash_sha1: Hash,
  hash_sha256: Hash,
  email: Mail,
  cve: Shield,
  other: Cpu,
}

const VERDICT_COLORS = {
  malicious: 'bg-red-500/12 text-red-400 border-red-500/25',
  suspicious: 'bg-amber-500/12 text-amber-400 border-amber-500/25',
  benign: 'bg-green-500/12 text-green-400 border-green-500/25',
  unknown: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
}

const VERDICT_ICONS = {
  malicious: AlertTriangle,
  suspicious: AlertTriangle,
  benign: CheckCircle2,
  unknown: HelpCircle,
}

function VerdictChip({ verdict }: { verdict: keyof typeof VERDICT_COLORS }) {
  const Icon = VERDICT_ICONS[verdict]
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${VERDICT_COLORS[verdict]}`}>
      <Icon size={10} strokeWidth={1.5} />
      {verdict.charAt(0).toUpperCase() + verdict.slice(1)}
    </span>
  )
}

interface IOCDetailPanelProps {
  ioc: ThreatIntelIOC | null
  open: boolean
  onClose: () => void
}

function IOCDetailPanel({ ioc, open, onClose }: IOCDetailPanelProps) {
  if (!ioc) return null
  const Icon = IOC_TYPE_ICONS[ioc.ioc_type] ?? Globe
  const enrichment = ioc.enrichment as Record<string, unknown> | null

  return (
    <Panel open={open} onClose={onClose} title="IOC Detail" subtitle={ioc.value} width="520px">
      <div className="p-5 space-y-5">
        {/* Header */}
        <div className="bg-[rgba(255,255,255,0.02)] border border-[rgba(56,189,248,0.08)] rounded-lg p-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-lg bg-[rgba(56,189,248,0.08)] flex items-center justify-center flex-shrink-0">
              <Icon size={18} strokeWidth={1.5} className="text-[#38bdf8]" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-mono font-medium text-[#e2e8f0] break-all">{ioc.value}</p>
              <div className="flex items-center gap-2 mt-1.5">
                <VerdictChip verdict={ioc.verdict} />
                <span className="text-[11px] text-[#64748b] uppercase tracking-wider">{ioc.ioc_type.replace('_', ' ')}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: 'Confidence', value: `${ioc.confidence}%` },
            { label: 'Severity', value: ioc.severity },
            { label: 'Hit Count', value: ioc.hit_count.toString() },
          ].map(item => (
            <div key={item.label} className="bg-[rgba(255,255,255,0.02)] rounded-lg p-3 text-center">
              <p className="text-[10px] text-[#64748b] uppercase tracking-wider mb-1">{item.label}</p>
              <p className="text-sm font-bold text-[#e2e8f0] capitalize">{item.value}</p>
            </div>
          ))}
        </div>

        {/* Dates */}
        <div className="space-y-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b]">Timestamps</p>
          {[
            { label: 'First Seen', value: ioc.first_seen },
            { label: 'Last Seen', value: ioc.last_seen },
            { label: 'Expires', value: ioc.expiry },
          ].map(item => (
            <div key={item.label} className="flex items-center justify-between">
              <span className="text-xs text-[#64748b]">{item.label}</span>
              <span className="text-xs text-[#94a3b8]">
                {item.value ? new Date(item.value).toLocaleString() : '—'}
              </span>
            </div>
          ))}
        </div>

        {/* Tags */}
        {ioc.tags && ioc.tags.length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {ioc.tags.map(tag => (
                <span key={tag} className="text-[11px] bg-[rgba(255,255,255,0.04)] text-[#94a3b8] border border-[rgba(255,255,255,0.08)] px-2 py-0.5 rounded">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Enrichment */}
        {enrichment && Object.keys(enrichment).length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Enrichment Data</p>
            <div className="bg-[rgba(0,0,0,0.2)] rounded-lg p-3 font-mono text-[11px] text-[#94a3b8] space-y-1 max-h-48 overflow-y-auto">
              {Object.entries(enrichment).map(([k, v]) => (
                <div key={k} className="flex gap-2">
                  <span className="text-[#38bdf8] flex-shrink-0">{k}:</span>
                  <span className="break-all">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Source */}
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Source</p>
          <p className="text-xs text-[#94a3b8]">{ioc.source ?? 'Unknown'}</p>
        </div>
      </div>
    </Panel>
  )
}

export function ThreatIntelPage() {
  const [iocs, setIOCs] = useState<ThreatIntelIOC[]>([])
  const [feeds, setFeeds] = useState<ThreatIntelFeed[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [searchType, setSearchType] = useState<IocType | ''>('')
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('')
  const [selectedIOC, setSelectedIOC] = useState<ThreatIntelIOC | null>(null)
  const [panelOpen, setPanelOpen] = useState(false)
  const [activeView, setActiveView] = useState<'iocs' | 'feeds'>('iocs')
  const [bulkInput, setBulkInput] = useState('')
  const [bulkImportOpen, setBulkImportOpen] = useState(false)
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 50

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [iocRes, feedRes] = await Promise.all([
        supabase
          .from('threat_intel_iocs')
          .select('*')
          .order('created_at', { ascending: false })
          .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1),
        supabase
          .from('threat_intel_feeds')
          .select('*')
          .order('name', { ascending: true }),
      ])
      setIOCs(iocRes.data ?? [])
      setFeeds(feedRes.data ?? [])
    } catch (err) {
      console.error('Threat intel load error:', err)
    } finally {
      setLoading(false)
    }
  }, [page])

  useEffect(() => {
    loadData()
  }, [loadData])

  const filteredIOCs = iocs.filter(ioc => {
    if (search) {
      const q = search.toLowerCase()
      if (!ioc.value.toLowerCase().includes(q) && !(ioc.source ?? '').toLowerCase().includes(q)) return false
    }
    if (searchType && ioc.ioc_type !== searchType) return false
    if (verdictFilter && ioc.verdict !== verdictFilter) return false
    return true
  })

  const handleExport = () => {
    const csv = [
      'type,value,verdict,confidence,severity,source,first_seen,last_seen',
      ...filteredIOCs.map(ioc =>
        `${ioc.ioc_type},${ioc.value},${ioc.verdict},${ioc.confidence},${ioc.severity},${ioc.source ?? ''},${ioc.first_seen ?? ''},${ioc.last_seen ?? ''}`
      ),
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `iocs-export-${new Date().toISOString().split('T')[0]}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const stats = {
    malicious: iocs.filter(i => i.verdict === 'malicious').length,
    suspicious: iocs.filter(i => i.verdict === 'suspicious').length,
    benign: iocs.filter(i => i.verdict === 'benign').length,
    total: iocs.length,
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-[#e2e8f0] font-[Sora]">Threat Intelligence</h1>
          <p className="text-xs text-[#64748b]">IOC management, feed ingestion, and reputation lookup</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setBulkImportOpen(true)} className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Upload size={12} strokeWidth={1.5} />
            Bulk Import
          </button>
          <button onClick={handleExport} className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Download size={12} strokeWidth={1.5} />
            Export
          </button>
          <button onClick={loadData} disabled={loading} className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
            <RefreshCw size={12} strokeWidth={1.5} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Total IOCs', value: stats.total, color: 'text-[#38bdf8]', bg: 'rgba(56,189,248,0.1)', icon: Shield },
          { label: 'Malicious', value: stats.malicious, color: 'text-red-400', bg: 'rgba(239,68,68,0.1)', icon: AlertTriangle },
          { label: 'Suspicious', value: stats.suspicious, color: 'text-amber-400', bg: 'rgba(245,158,11,0.1)', icon: AlertTriangle },
          { label: 'Active Feeds', value: feeds.filter(f => f.status === 'active').length, color: 'text-green-400', bg: 'rgba(34,197,94,0.1)', icon: Activity },
        ].map(item => (
          <Card key={item.label} className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: item.bg }}>
              <item.icon size={16} strokeWidth={1.5} className={item.color} />
            </div>
            <div>
              <div className={`text-xl font-bold ${item.color} font-[Sora]`}>{item.value.toLocaleString()}</div>
              <div className="text-[10px] text-[#64748b]">{item.label}</div>
            </div>
          </Card>
        ))}
      </div>

      {/* View tabs */}
      <div className="flex gap-1 border-b border-[rgba(56,189,248,0.08)]">
        {(['iocs', 'feeds'] as const).map(view => (
          <button
            key={view}
            onClick={() => setActiveView(view)}
            className={`px-4 py-2 text-xs font-medium transition-colors border-b-2 ${
              activeView === view
                ? 'text-[#38bdf8] border-[#38bdf8]'
                : 'text-[#64748b] border-transparent hover:text-[#94a3b8]'
            }`}
          >
            {view === 'iocs' ? 'IOC Database' : 'Feed Management'}
            <span className={`ml-1.5 text-[10px] ${activeView === view ? 'text-[#38bdf8]/70' : 'text-[#64748b]'}`}>
              {view === 'iocs' ? `(${stats.total})` : `(${feeds.length})`}
            </span>
          </button>
        ))}
      </div>

      {activeView === 'iocs' && (
        <>
          {/* IOC Search */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-64">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" strokeWidth={1.5} />
              <input
                type="text"
                placeholder="Search IOCs — IP, domain, hash, URL…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="mcc-input pl-8 text-xs"
              />
            </div>
            <select
              value={searchType}
              onChange={e => setSearchType(e.target.value as IocType | '')}
              className="mcc-input text-xs w-40"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash_md5">Hash (MD5)</option>
              <option value="hash_sha1">Hash (SHA1)</option>
              <option value="hash_sha256">Hash (SHA256)</option>
              <option value="email">Email</option>
              <option value="cve">CVE</option>
            </select>
            <FilterChipGroup>
              {(['malicious', 'suspicious', 'benign', 'unknown'] as VerdictFilter[]).filter(Boolean).map(v => (
                <FilterChip
                  key={v}
                  label={v as string}
                  active={verdictFilter === v}
                  onClick={() => setVerdictFilter(f => f === v ? '' : v as VerdictFilter)}
                />
              ))}
            </FilterChipGroup>
          </div>

          {/* IOC Table */}
          <Card padding="none">
            {loading ? (
              <div className="p-6"><Loader variant="table" rows={8} /></div>
            ) : filteredIOCs.length === 0 ? (
              <EmptyState
                title="No IOCs found"
                description="No indicators of compromise match your search criteria."
                icon="search"
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="mcc-table">
                  <thead className="sticky top-0 z-10">
                    <tr>
                      <th className="w-24">Type</th>
                      <th>Value</th>
                      <th className="w-28">Verdict</th>
                      <th className="w-20">Confidence</th>
                      <th className="w-20">Severity</th>
                      <th className="w-24">Source</th>
                      <th className="w-24">Last Seen</th>
                      <th className="w-14">Hits</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIOCs.map(ioc => {
                      const Icon = IOC_TYPE_ICONS[ioc.ioc_type] ?? Globe
                      return (
                        <tr
                          key={ioc.id}
                          className="cursor-pointer"
                          onClick={() => { setSelectedIOC(ioc); setPanelOpen(true) }}
                        >
                          <td>
                            <span className="flex items-center gap-1.5 text-[11px] text-[#64748b]">
                              <Icon size={12} strokeWidth={1.5} />
                              {ioc.ioc_type.replace('_', ' ')}
                            </span>
                          </td>
                          <td>
                            <span className="text-xs font-mono text-[#e2e8f0] truncate block max-w-[280px]">{ioc.value}</span>
                          </td>
                          <td><VerdictChip verdict={ioc.verdict} /></td>
                          <td>
                            <div className="flex items-center gap-1.5">
                              <div className="flex-1 h-1 bg-[rgba(255,255,255,0.08)] rounded-full overflow-hidden w-12">
                                <div
                                  className="h-full rounded-full"
                                  style={{
                                    width: `${ioc.confidence}%`,
                                    background: ioc.confidence >= 80 ? '#ef4444' : ioc.confidence >= 60 ? '#f59e0b' : '#22c55e',
                                  }}
                                />
                              </div>
                              <span className="text-[11px] text-[#64748b]">{ioc.confidence}%</span>
                            </div>
                          </td>
                          <td>
                            <Badge
                              variant="severity"
                              severity={ioc.severity}
                            >
                              {ioc.severity}
                            </Badge>
                          </td>
                          <td>
                            <span className="text-xs text-[#64748b] truncate block max-w-[100px]">{ioc.source ?? '—'}</span>
                          </td>
                          <td>
                            <span className="text-xs text-[#64748b] whitespace-nowrap">
                              {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : '—'}
                            </span>
                          </td>
                          <td>
                            <span className={`text-xs font-mono ${ioc.hit_count > 0 ? 'text-amber-400' : 'text-[#64748b]'}`}>
                              {ioc.hit_count}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {/* Pagination */}
          {!loading && filteredIOCs.length === PAGE_SIZE && (
            <div className="flex justify-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="btn-ghost text-xs py-1.5 px-3 disabled:opacity-40"
              >
                Previous
              </button>
              <span className="flex items-center text-xs text-[#64748b]">Page {page + 1}</span>
              <button
                onClick={() => setPage(p => p + 1)}
                className="btn-ghost text-xs py-1.5 px-3"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {activeView === 'feeds' && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {loading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <Card key={i}><Loader variant="card" /></Card>
            ))
          ) : feeds.length === 0 ? (
            <div className="col-span-full">
              <Card>
                <EmptyState
                  title="No feeds configured"
                  description="No threat intelligence feeds have been configured. Add your first feed to start ingesting IOCs."
                  icon="shield"
                  action={
                    <button className="btn-primary text-xs py-2 px-4 flex items-center gap-2">
                      <Plus size={13} strokeWidth={1.5} />
                      Add Feed
                    </button>
                  }
                />
              </Card>
            </div>
          ) : (
            feeds.map(feed => (
              <Card key={feed.id} hover>
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold text-[#e2e8f0] truncate">{feed.name}</h3>
                    <p className="text-[11px] text-[#64748b] mt-0.5 truncate">{feed.description ?? feed.feed_type}</p>
                  </div>
                  <span className={`ml-2 flex-shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold border
                    ${feed.status === 'active'
                      ? 'bg-green-500/10 text-green-400 border-green-500/20'
                      : feed.status === 'error'
                        ? 'bg-red-500/10 text-red-400 border-red-500/20'
                        : 'bg-slate-500/10 text-slate-400 border-slate-500/20'
                    }`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      feed.status === 'active' ? 'bg-green-400' :
                      feed.status === 'error' ? 'bg-red-400' : 'bg-slate-400'
                    }`} />
                    {feed.status}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                  <div className="bg-[rgba(255,255,255,0.02)] rounded px-2 py-1.5">
                    <span className="text-[10px] text-[#64748b] block">IOC Count</span>
                    <span className="font-bold text-[#e2e8f0]">{feed.ioc_count.toLocaleString()}</span>
                  </div>
                  <div className="bg-[rgba(255,255,255,0.02)] rounded px-2 py-1.5">
                    <span className="text-[10px] text-[#64748b] block">Format</span>
                    <span className="font-bold text-[#e2e8f0] uppercase">{feed.format}</span>
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-[#64748b]">
                  <span>Updated every {feed.update_frequency_hours}h</span>
                  <span>{feed.last_ingested ? new Date(feed.last_ingested).toLocaleDateString() : 'Never'}</span>
                </div>
              </Card>
            ))
          )}

          {/* Add feed card */}
          <Card className="flex flex-col items-center justify-center py-8 cursor-pointer border-dashed hover:border-[rgba(56,189,248,0.3)] transition-colors" onClick={() => {}}>
            <div className="w-10 h-10 rounded-full bg-[rgba(56,189,248,0.08)] flex items-center justify-center mb-3">
              <Plus size={20} strokeWidth={1.5} className="text-[#38bdf8]" />
            </div>
            <p className="text-xs font-medium text-[#64748b]">Add New Feed</p>
          </Card>
        </div>
      )}

      {/* IOC Detail Panel */}
      <IOCDetailPanel
        ioc={selectedIOC}
        open={panelOpen}
        onClose={() => { setPanelOpen(false); setSelectedIOC(null) }}
      />

      {/* Bulk Import Panel */}
      <Panel
        open={bulkImportOpen}
        onClose={() => setBulkImportOpen(false)}
        title="Bulk IOC Import"
        subtitle="Paste IOCs one per line for batch ingestion"
        width="480px"
      >
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">
              IOC List <span className="text-[#64748b] font-normal">(one per line)</span>
            </label>
            <textarea
              value={bulkInput}
              onChange={e => setBulkInput(e.target.value)}
              placeholder={"1.2.3.4\nevil.com\n3e4b5d6c7a8b9f0e..."}
              rows={12}
              className="mcc-input text-xs font-mono resize-none"
            />
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[#64748b]">
            <span>{bulkInput.split('\n').filter(l => l.trim()).length} IOCs detected</span>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setBulkImportOpen(false)}
              className="btn-ghost text-xs py-2 px-4 flex-1"
            >
              Cancel
            </button>
            <button
              disabled={!bulkInput.trim()}
              className="btn-primary text-xs py-2 px-4 flex-1 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <Upload size={13} strokeWidth={1.5} />
              Import IOCs
            </button>
          </div>
        </div>
      </Panel>
    </div>
  )
}
