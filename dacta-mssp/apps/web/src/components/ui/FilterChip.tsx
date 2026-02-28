import React from 'react'
import { X } from 'lucide-react'

interface FilterChipProps {
  label: string
  value?: string
  onRemove?: () => void
  active?: boolean
  onClick?: () => void
}

export function FilterChip({ label, value, onRemove, active = false, onClick }: FilterChipProps) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium border transition-all duration-150
        ${active
          ? 'bg-[rgba(56,189,248,0.12)] text-[#38bdf8] border-[rgba(56,189,248,0.3)]'
          : 'bg-[rgba(255,255,255,0.03)] text-[#94a3b8] border-[rgba(255,255,255,0.08)] hover:bg-[rgba(255,255,255,0.06)] hover:text-[#e2e8f0]'
        }`}
    >
      {value ? (
        <>
          <span className="text-[#64748b]">{label}:</span>
          <span>{value}</span>
        </>
      ) : (
        <span>{label}</span>
      )}
      {onRemove && (
        <span
          onClick={e => { e.stopPropagation(); onRemove() }}
          className="ml-0.5 rounded-sm hover:bg-[rgba(255,255,255,0.1)] p-0.5 transition-colors"
        >
          <X size={10} />
        </span>
      )}
    </button>
  )
}

interface FilterChipGroupProps {
  children: React.ReactNode
  className?: string
}

export function FilterChipGroup({ children, className = '' }: FilterChipGroupProps) {
  return (
    <div className={`flex flex-wrap items-center gap-2 ${className}`}>
      {children}
    </div>
  )
}
