import React from 'react'

interface CardProps {
  children: React.ReactNode
  className?: string
  hover?: boolean
  glow?: boolean
  onClick?: () => void
  padding?: 'none' | 'sm' | 'md' | 'lg'
}

const paddingClasses = {
  none: '',
  sm: 'p-3',
  md: 'p-4',
  lg: 'p-6',
}

export function Card({ children, className = '', hover = false, glow = false, onClick, padding = 'md' }: CardProps) {
  const base = 'rounded-[10px] border transition-all duration-200'
  const bg = 'bg-[rgba(13,19,36,0.85)] backdrop-blur-[16px]'
  const border = 'border-[rgba(56,189,248,0.08)]'
  const hoverClass = hover
    ? 'hover:border-[rgba(56,189,248,0.25)] hover:shadow-[0_0_24px_rgba(56,189,248,0.06)]'
    : ''
  const glowClass = glow ? 'shadow-[0_0_32px_rgba(56,189,248,0.08)]' : ''
  const clickClass = onClick ? 'cursor-pointer' : ''

  return (
    <div
      className={`${base} ${bg} ${border} ${hoverClass} ${glowClass} ${clickClass} ${paddingClasses[padding]} ${className}`}
      onClick={onClick}
    >
      {children}
    </div>
  )
}

interface CardHeaderProps {
  children: React.ReactNode
  className?: string
}

export function CardHeader({ children, className = '' }: CardHeaderProps) {
  return (
    <div className={`flex items-center justify-between mb-4 ${className}`}>
      {children}
    </div>
  )
}

interface CardTitleProps {
  children: React.ReactNode
  className?: string
}

export function CardTitle({ children, className = '' }: CardTitleProps) {
  return (
    <h3 className={`text-sm font-semibold text-[#e2e8f0] tracking-wide ${className}`}>
      {children}
    </h3>
  )
}
