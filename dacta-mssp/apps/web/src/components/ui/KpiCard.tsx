import React from 'react'
import type { LucideIcon } from 'lucide-react'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'
import { Card } from './Card'

interface KpiCardProps {
  title: string
  value: string | number
  subtitle?: string
  icon: LucideIcon
  iconColor?: string
  iconBg?: string
  trend?: {
    value: number
    label?: string
    direction?: 'up' | 'down' | 'flat'
  }
  glow?: boolean
  className?: string
}

export function KpiCard({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = '#38bdf8',
  iconBg = 'rgba(56,189,248,0.1)',
  trend,
  glow = false,
  className = '',
}: KpiCardProps) {
  const TrendIcon = trend
    ? trend.direction === 'up'
      ? TrendingUp
      : trend.direction === 'down'
        ? TrendingDown
        : Minus
    : null

  const trendColorClass = trend
    ? trend.direction === 'up'
      ? 'text-green-400'
      : trend.direction === 'down'
        ? 'text-red-400'
        : 'text-slate-400'
    : ''

  return (
    <Card
      hover
      glow={glow}
      className={`flex items-start gap-4 ${className}`}
    >
      {/* Icon */}
      <div
        className="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center mt-0.5"
        style={{ background: iconBg }}
      >
        <Icon size={18} style={{ color: iconColor }} strokeWidth={1.5} />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <p className="text-[11px] font-medium uppercase tracking-wider text-[#64748b] mb-1">{title}</p>
        <p className="text-2xl font-bold text-[#e2e8f0] font-[Sora] leading-none">{value}</p>
        {(subtitle || trend) && (
          <div className="flex items-center gap-2 mt-1.5">
            {trend && TrendIcon && (
              <span className={`flex items-center gap-0.5 text-[11px] font-medium ${trendColorClass}`}>
                <TrendIcon size={12} />
                {trend.value > 0 ? '+' : ''}{trend.value}%
              </span>
            )}
            {subtitle && <span className="text-[11px] text-[#64748b]">{subtitle}</span>}
            {trend?.label && <span className="text-[11px] text-[#64748b]">{trend.label}</span>}
          </div>
        )}
      </div>
    </Card>
  )
}
