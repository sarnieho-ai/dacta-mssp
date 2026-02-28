import React from 'react'
import { SearchX, ShieldOff, FileSearch } from 'lucide-react'

interface EmptyStateProps {
  title?: string
  description?: string
  icon?: 'search' | 'shield' | 'file' | React.ReactNode
  action?: React.ReactNode
}

const icons = {
  search: <SearchX size={36} strokeWidth={1} className="text-[#64748b]" />,
  shield: <ShieldOff size={36} strokeWidth={1} className="text-[#64748b]" />,
  file: <FileSearch size={36} strokeWidth={1} className="text-[#64748b]" />,
}

export function EmptyState({
  title = 'No data found',
  description = 'No records match your current filters.',
  icon = 'search',
  action,
}: EmptyStateProps) {
  const iconEl = typeof icon === 'string' ? (icons[icon as keyof typeof icons] ?? icons.search) : icon

  return (
    <div className="flex flex-col items-center justify-center py-16 px-8 text-center">
      <div className="p-4 rounded-full bg-[rgba(255,255,255,0.03)] mb-4">
        {iconEl}
      </div>
      <h3 className="text-sm font-semibold text-[#94a3b8] mb-1">{title}</h3>
      <p className="text-xs text-[#64748b] max-w-xs">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}
