import React from 'react'

type PriorityLevel = 'P1' | 'P2' | 'P3' | 'P4'
type VerdictType = 'true_positive' | 'false_positive' | 'benign' | 'under_review'
type StatusType = 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed' | 'false_positive'
type SeverityType = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'info'

interface BadgeProps {
  children: React.ReactNode
  variant?: 'priority' | 'verdict' | 'status' | 'severity' | 'default'
  priority?: PriorityLevel
  verdict?: VerdictType
  status?: StatusType
  severity?: SeverityType
  className?: string
}

const priorityStyles: Record<PriorityLevel, string> = {
  P1: 'bg-red-500/12 text-red-400 border border-red-500/25',
  P2: 'bg-orange-500/12 text-orange-400 border border-orange-500/25',
  P3: 'bg-amber-500/12 text-amber-400 border border-amber-500/25',
  P4: 'bg-blue-500/12 text-blue-400 border border-blue-500/25',
}

const verdictStyles: Record<VerdictType, string> = {
  true_positive: 'bg-red-500/12 text-red-400 border border-red-500/25',
  false_positive: 'bg-green-500/12 text-green-400 border border-green-500/25',
  benign: 'bg-blue-500/12 text-blue-400 border border-blue-500/25',
  under_review: 'bg-amber-500/12 text-amber-400 border border-amber-500/25',
}

const statusStyles: Record<StatusType, string> = {
  open: 'bg-red-500/10 text-red-400 border border-red-500/20',
  in_progress: 'bg-blue-500/10 text-blue-400 border border-blue-500/20',
  pending: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
  resolved: 'bg-green-500/10 text-green-400 border border-green-500/20',
  closed: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  false_positive: 'bg-green-500/10 text-green-400 border border-green-500/20',
}

const severityStyles: Record<SeverityType, string> = {
  critical: 'bg-red-500/12 text-red-400 border border-red-500/25',
  high: 'bg-orange-500/12 text-orange-400 border border-orange-500/25',
  medium: 'bg-amber-500/12 text-amber-400 border border-amber-500/25',
  low: 'bg-blue-500/12 text-blue-400 border border-blue-500/25',
  informational: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  info: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
}

export function Badge({ children, variant = 'default', priority, verdict, status, severity, className = '' }: BadgeProps) {
  let variantClass = 'bg-slate-500/10 text-slate-400 border border-slate-500/20'

  if (variant === 'priority' && priority) variantClass = priorityStyles[priority]
  else if (variant === 'verdict' && verdict) variantClass = verdictStyles[verdict]
  else if (variant === 'status' && status) variantClass = statusStyles[status]
  else if (variant === 'severity' && severity) variantClass = severityStyles[severity]

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold tracking-wide whitespace-nowrap ${variantClass} ${className}`}
    >
      {children}
    </span>
  )
}

export function PriorityBadge({ priority }: { priority: PriorityLevel }) {
  return (
    <Badge variant="priority" priority={priority}>
      {priority}
    </Badge>
  )
}

export function VerdictBadge({ verdict }: { verdict: VerdictType | null }) {
  if (!verdict) return <span className="text-slate-600 text-xs">—</span>
  const labels: Record<VerdictType, string> = {
    true_positive: 'True Positive',
    false_positive: 'False Positive',
    benign: 'Benign',
    under_review: 'Under Review',
  }
  return (
    <Badge variant="verdict" verdict={verdict}>
      {labels[verdict]}
    </Badge>
  )
}

export function StatusBadge({ status }: { status: StatusType }) {
  const labels: Record<StatusType, string> = {
    open: 'Open',
    in_progress: 'In Progress',
    pending: 'Pending',
    resolved: 'Resolved',
    closed: 'Closed',
    false_positive: 'False Positive',
  }
  return (
    <Badge variant="status" status={status}>
      {labels[status]}
    </Badge>
  )
}
