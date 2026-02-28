import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { Search, RefreshCw, Info, Filter, ExternalLink } from 'lucide-react'
import { supabase } from '../lib/supabase'
import { useOrganizations } from '../hooks/useOrganizations'
import { Card, CardHeader, CardTitle } from '../components/ui/Card'
import { Panel } from '../components/ui/Modal'
import { Loader } from '../components/ui/Loader'
import { EmptyState } from '../components/ui/EmptyState'
import { Badge } from '../components/ui/Badge'
import type { MITRETechnique, MITREOrgHit, DetectionRule } from '../types/database'

// MITRE ATT&CK Enterprise Tactics (in order)
const ENTERPRISE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

// MITRE ATT&CK ICS Tactics
const ICS_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Evasion',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Inhibit Response Function',
  'Impair Process Control',
  'Impact',
]

interface TechniqueCellProps {
  technique: MITRETechnique | undefined
  hitCount: number
  onClick: (t: MITRETechnique) => void
}

function TechniqueCell({ technique, hitCount, onClick }: TechniqueCellProps) {
  if (!technique) {
    return (
      <div className="mitre-cell mitre-cell-0 flex items-center justify-center">
        <span className="text-[9px] text-[#64748b]">—</span>
      </div>
    )
  }

  // 0-5 heat levels
  const heatLevel = hitCount === 0 ? 0 : hitCount <= 1 ? 1 : hitCount <= 3 ? 2 : hitCount <= 7 ? 3 : hitCount <= 15 ? 4 : 5

  return (
    <div
      className={`mitre-cell mitre-cell-${heatLevel}`}
      onClick={() => onClick(technique)}
      title={`${technique.technique_id}: ${technique.name} (${hitCount} hits)`}
    >
      <div className="text-[9px] font-mono text-[#64748b] mb-0.5">{technique.technique_id}</div>
      <div className="text-[10px] font-medium text-[#e2e8f0] leading-tight line-clamp-2">{technique.name}</div>
      {hitCount > 0 && (
        <div className="mt-1 text-[9px] font-bold text-[#38bdf8]">{hitCount}</div>
      )}
    </div>
  )
}

interface TechniqueDetailProps {
  technique: MITRETechnique | null
  open: boolean
  onClose: () => void
  orgId: string
}

function TechniqueDetail({ technique, open, onClose, orgId }: TechniqueDetailProps) {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (technique && open) {
      setLoading(true)
      supabase
        .from('detection_rules')
        .select('*')
        .contains('mitre_techniques', [technique.technique_id])
        .then(({ data }) => {
          setRules(data ?? [])
          setLoading(false)
        })
    }
  }, [technique, open])

  if (!technique) return null

  return (
    <Panel
      open={open}
      onClose={onClose}
      title={technique.technique_id}
      subtitle={technique.name}
      width="520px"
    >
      <div className="p-5 space-y-5">
        {/* Technique info */}
        <div className="bg-[rgba(56,189,248,0.04)] border border-[rgba(56,189,248,0.12)] rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-[#38bdf8]">{technique.technique_id}</span>
            <Badge variant="severity" severity="medium" className="capitalize">{technique.tactic}</Badge>
          </div>
          <p className="text-xs text-[#94a3b8] leading-relaxed">
            {technique.description ?? 'No description available.'}
          </p>
          {technique.url && (
            <a
              href={technique.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[11px] text-[#38bdf8] hover:underline"
            >
              <ExternalLink size={11} strokeWidth={1.5} />
              View on MITRE ATT&CK
            </a>
          )}
        </div>

        {/* Platforms */}
        {technique.platforms && technique.platforms.length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Platforms</p>
            <div className="flex flex-wrap gap-1.5">
              {technique.platforms.map(p => (
                <span key={p} className="text-[11px] bg-[rgba(255,255,255,0.04)] text-[#94a3b8] border border-[rgba(255,255,255,0.08)] px-2 py-0.5 rounded">
                  {p}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Data sources */}
        {technique.data_sources && technique.data_sources.length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">Data Sources</p>
            <div className="flex flex-wrap gap-1.5">
              {technique.data_sources.map(ds => (
                <span key={ds} className="text-[11px] bg-[rgba(56,189,248,0.06)] text-[#38bdf8] border border-[rgba(56,189,248,0.15)] px-2 py-0.5 rounded">
                  {ds}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Detection rules */}
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-[#64748b] mb-2">
            Detection Rules ({rules.length})
          </p>
          {loading ? (
            <Loader variant="card" />
          ) : rules.length === 0 ? (
            <p className="text-xs text-[#64748b] italic">No detection rules mapped to this technique.</p>
          ) : (
            <div className="space-y-2">
              {rules.map(rule => (
                <div key={rule.id} className="bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2.5 flex items-start justify-between gap-2">
                  <div>
                    <p className="text-xs font-medium text-[#e2e8f0]">{rule.name}</p>
                    <p className="text-[11px] text-[#64748b] mt-0.5">{rule.rule_type.toUpperCase()} · {rule.trigger_count} triggers</p>
                  </div>
                  <Badge variant="severity" severity={rule.severity as 'critical' | 'high' | 'medium' | 'low' | 'informational'}>
                    {rule.severity}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

interface MatrixProps {
  tactics: string[]
  techniques: MITRETechnique[]
  orgHits: Map<string, number>
  label: string
  onSelect: (t: MITRETechnique) => void
}

function AttackMatrix({ tactics, techniques, orgHits, label, onSelect }: MatrixProps) {
  // Group techniques by tactic
  const byTactic = useMemo(() => {
    const map = new Map<string, MITRETechnique[]>()
    tactics.forEach(t => map.set(t, []))
    techniques.forEach(tech => {
      const tactic = tech.tactic
      // Match tactic to one of our tactics (case-insensitive partial match)
      const matchedTactic = tactics.find(t =>
        t.toLowerCase() === tactic.toLowerCase() ||
        tactic.toLowerCase().includes(t.toLowerCase().replace(' ', '-')) ||
        t.toLowerCase().replace(' ', '-').includes(tactic.toLowerCase())
      )
      if (matchedTactic) {
        map.get(matchedTactic)?.push(tech)
      }
    })
    return map
  }, [tactics, techniques])

  const maxPerTactic = useMemo(() => {
    return Math.max(...Array.from(byTactic.values()).map(arr => arr.length), 1)
  }, [byTactic])

  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-sm font-semibold text-[#e2e8f0]">{label}</h3>
        <span className="text-[11px] text-[#64748b]">({techniques.length} techniques)</span>
      </div>

      {/* Heat legend */}
      <div className="flex items-center gap-2 mb-4 text-[10px] text-[#64748b]">
        <span>Coverage:</span>
        {[0, 1, 2, 3, 4, 5].map(level => (
          <div key={level} className={`w-4 h-4 rounded mitre-cell-${level} border border-[rgba(255,255,255,0.1)]`} />
        ))}
        <span>→ Critical</span>
      </div>

      <div className="overflow-x-auto">
        <div className="min-w-max">
          {/* Tactic headers */}
          <div className="flex gap-1 mb-2">
            {tactics.map(tactic => {
              const tacticTechs = byTactic.get(tactic) ?? []
              const totalHits = tacticTechs.reduce((acc, t) => acc + (orgHits.get(t.technique_id) ?? 0), 0)
              return (
                <div key={tactic} style={{ minWidth: 90 }} className="text-center">
                  <div className="text-[10px] font-semibold text-[#94a3b8] uppercase leading-tight px-1 mb-1">
                    {tactic}
                  </div>
                  {totalHits > 0 && (
                    <div className="text-[10px] text-amber-400 font-mono mb-1">{totalHits} hits</div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Technique cells */}
          {Array.from({ length: maxPerTactic }).map((_, rowIdx) => (
            <div key={rowIdx} className="flex gap-1 mb-1">
              {tactics.map(tactic => {
                const tacticTechs = byTactic.get(tactic) ?? []
                const tech = tacticTechs[rowIdx]
                const hitCount = tech ? (orgHits.get(tech.technique_id) ?? 0) : 0
                return (
                  <div key={tactic} style={{ minWidth: 90 }}>
                    {tech ? (
                      <TechniqueCell technique={tech} hitCount={hitCount} onClick={onSelect} />
                    ) : (
                      <div style={{ minWidth: 90, minHeight: 52 }} />
                    )}
                  </div>
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export function MitrePage() {
  const { organizations } = useOrganizations()
  const [enterpriseTechniques, setEnterpriseTechniques] = useState<MITRETechnique[]>([])
  const [icsTechniques, setIcsTechniques] = useState<MITRETechnique[]>([])
  const [orgHits, setOrgHits] = useState<MITREOrgHit[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedOrg, setSelectedOrg] = useState<string>('')
  const [search, setSearch] = useState('')
  const [selectedTechnique, setSelectedTechnique] = useState<MITRETechnique | null>(null)
  const [detailOpen, setDetailOpen] = useState(false)

  const loadData = useCallback(async () => {
    setLoading(true)
    try {
      const [entRes, icsRes, hitsRes] = await Promise.all([
        supabase
          .from('mitre_techniques')
          .select('*')
          .eq('matrix', 'enterprise')
          .eq('is_subtechnique', false)
          .order('tactic'),
        supabase
          .from('mitre_techniques')
          .select('*')
          .eq('matrix', 'ics')
          .eq('is_subtechnique', false)
          .order('tactic'),
        selectedOrg
          ? supabase.from('mitre_org_hits').select('*').eq('org_id', selectedOrg)
          : supabase.from('mitre_org_hits').select('*'),
      ])
      setEnterpriseTechniques(entRes.data ?? [])
      setIcsTechniques(icsRes.data ?? [])
      setOrgHits(hitsRes.data ?? [])
    } catch (err) {
      console.error('MITRE load error:', err)
    } finally {
      setLoading(false)
    }
  }, [selectedOrg])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Build hit map: technique_id → total hits
  const hitMap = useMemo(() => {
    const map = new Map<string, number>()
    orgHits.forEach(hit => {
      map.set(hit.technique_id, (map.get(hit.technique_id) ?? 0) + hit.hit_count)
    })
    return map
  }, [orgHits])

  // Filter techniques by search
  const filteredEnterprise = useMemo(() => {
    if (!search) return enterpriseTechniques
    const q = search.toLowerCase()
    return enterpriseTechniques.filter(t =>
      t.technique_id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.tactic.toLowerCase().includes(q)
    )
  }, [enterpriseTechniques, search])

  const filteredICS = useMemo(() => {
    if (!search) return icsTechniques
    const q = search.toLowerCase()
    return icsTechniques.filter(t =>
      t.technique_id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.tactic.toLowerCase().includes(q)
    )
  }, [icsTechniques, search])

  const totalHits = useMemo(() => Array.from(hitMap.values()).reduce((a, b) => a + b, 0), [hitMap])
  const coveredTechniques = useMemo(() => hitMap.size, [hitMap])

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-bold text-[#e2e8f0] font-[Sora]">MITRE ATT&CK</h1>
          <p className="text-xs text-[#64748b]">
            {totalHits} observed hits across {coveredTechniques} technique{coveredTechniques !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {organizations.length > 0 && (
            <select
              value={selectedOrg}
              onChange={e => setSelectedOrg(e.target.value)}
              className="mcc-input text-xs w-40"
            >
              <option value="">All Organizations</option>
              {organizations.map(o => (
                <option key={o.id} value={o.id}>{o.name}</option>
              ))}
            </select>
          )}
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" strokeWidth={1.5} />
            <input
              type="text"
              placeholder="Search techniques…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="mcc-input pl-8 text-xs w-48"
            />
          </div>
          <button onClick={loadData} disabled={loading} className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5">
            <RefreshCw size={12} strokeWidth={1.5} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: 'Enterprise Techniques', value: enterpriseTechniques.length },
          { label: 'ICS Techniques', value: icsTechniques.length },
          { label: 'With Hits', value: coveredTechniques },
          { label: 'Total Observations', value: totalHits },
        ].map(item => (
          <Card key={item.label}>
            <div className="text-xl font-bold text-[#e2e8f0] font-[Sora]">{item.value.toLocaleString()}</div>
            <div className="text-[11px] text-[#64748b] mt-0.5">{item.label}</div>
          </Card>
        ))}
      </div>

      {/* Matrices */}
      {loading ? (
        <Card><Loader variant="table" rows={6} /></Card>
      ) : enterpriseTechniques.length === 0 && icsTechniques.length === 0 ? (
        <Card>
          <EmptyState
            title="No MITRE data"
            description="The MITRE ATT&CK technique database has not been populated yet. Import techniques to see the heatmap."
            icon="file"
            action={
              <div className="flex items-center gap-2 text-xs text-[#64748b]">
                <Info size={13} strokeWidth={1.5} />
                Run the MITRE sync job to populate this view
              </div>
            }
          />
        </Card>
      ) : (
        <div className="space-y-10">
          {/* Enterprise Matrix */}
          <Card padding="lg">
            <AttackMatrix
              tactics={ENTERPRISE_TACTICS}
              techniques={filteredEnterprise}
              orgHits={hitMap}
              label="Enterprise Matrix"
              onSelect={t => { setSelectedTechnique(t); setDetailOpen(true) }}
            />
          </Card>

          {/* ICS Matrix */}
          {(filteredICS.length > 0 || !search) && (
            <Card padding="lg">
              <AttackMatrix
                tactics={ICS_TACTICS}
                techniques={filteredICS}
                orgHits={hitMap}
                label="ICS Matrix"
                onSelect={t => { setSelectedTechnique(t); setDetailOpen(true) }}
              />
            </Card>
          )}
        </div>
      )}

      {/* Technique Detail Panel */}
      <TechniqueDetail
        technique={selectedTechnique}
        open={detailOpen}
        onClose={() => { setDetailOpen(false); setSelectedTechnique(null) }}
        orgId={selectedOrg}
      />
    </div>
  )
}
