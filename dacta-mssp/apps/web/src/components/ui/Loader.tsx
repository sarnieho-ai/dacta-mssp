import React from 'react'

interface SpinnerProps {
  size?: number
  className?: string
}

export function Spinner({ size = 20, className = '' }: SpinnerProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={`animate-spin ${className}`}
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke="rgba(56,189,248,0.2)"
        strokeWidth="2"
      />
      <path
        d="M12 2a10 10 0 0 1 10 10"
        stroke="#38bdf8"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  )
}

interface SkeletonProps {
  className?: string
  width?: string | number
  height?: string | number
}

export function Skeleton({ className = '', width, height }: SkeletonProps) {
  return (
    <div
      className={`skeleton rounded ${className}`}
      style={{ width, height }}
    />
  )
}

interface LoaderProps {
  variant?: 'spinner' | 'table' | 'card' | 'page'
  rows?: number
}

export function Loader({ variant = 'spinner', rows = 5 }: LoaderProps) {
  if (variant === 'spinner') {
    return (
      <div className="flex items-center justify-center p-8">
        <Spinner size={32} />
      </div>
    )
  }

  if (variant === 'table') {
    return (
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex gap-4 items-center py-2">
            <Skeleton className="w-16 h-5" />
            <Skeleton className="flex-1 h-5" />
            <Skeleton className="w-24 h-5" />
            <Skeleton className="w-20 h-5" />
            <Skeleton className="w-24 h-5" />
          </div>
        ))}
      </div>
    )
  }

  if (variant === 'card') {
    return (
      <div className="space-y-3">
        <Skeleton className="w-32 h-4" />
        <Skeleton className="w-full h-8" />
        <Skeleton className="w-3/4 h-4" />
      </div>
    )
  }

  if (variant === 'page') {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <Spinner size={40} />
        <p className="text-sm text-[#64748b]">Loading...</p>
      </div>
    )
  }

  return null
}
