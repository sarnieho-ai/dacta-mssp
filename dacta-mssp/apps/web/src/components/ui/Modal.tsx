import React, { useEffect, useCallback } from 'react'
import { X } from 'lucide-react'

// Panel (slide-in from right)
interface PanelProps {
  open: boolean
  onClose: () => void
  title: string
  subtitle?: string
  width?: string
  children: React.ReactNode
}

export function Panel({ open, onClose, title, subtitle, width = '540px', children }: PanelProps) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, handleKeyDown])

  if (!open) return null

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />
      {/* Panel */}
      <div
        className="fixed right-0 top-0 bottom-0 z-50 flex flex-col bg-[#0d1220] border-l border-[rgba(56,189,248,0.1)] shadow-2xl animate-slide-right"
        style={{ width }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[rgba(56,189,248,0.08)] flex-shrink-0">
          <div>
            <h2 className="text-sm font-semibold text-[#e2e8f0]">{title}</h2>
            {subtitle && <p className="text-xs text-[#64748b] mt-0.5">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-[#64748b] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
          >
            <X size={16} strokeWidth={1.5} />
          </button>
        </div>
        {/* Content */}
        <div className="flex-1 overflow-y-auto">
          {children}
        </div>
      </div>
    </>
  )
}

// Modal (centered)
interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  maxWidth?: string
  footer?: React.ReactNode
}

export function Modal({ open, onClose, title, children, maxWidth = '480px', footer }: ModalProps) {
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    if (open) {
      document.addEventListener('keydown', handleKeyDown)
      return () => document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, handleKeyDown])

  if (!open) return null

  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4"
        onClick={onClose}
      >
        <div
          className="relative w-full bg-[#0d1220] border border-[rgba(56,189,248,0.12)] rounded-xl shadow-2xl animate-fade-in"
          style={{ maxWidth }}
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[rgba(56,189,248,0.08)]">
            <h2 className="text-sm font-semibold text-[#e2e8f0]">{title}</h2>
            <button
              onClick={onClose}
              className="p-1.5 rounded-md text-[#64748b] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.06)] transition-colors"
            >
              <X size={16} strokeWidth={1.5} />
            </button>
          </div>
          {/* Body */}
          <div className="p-5">{children}</div>
          {/* Footer */}
          {footer && (
            <div className="px-5 py-4 border-t border-[rgba(56,189,248,0.08)] flex items-center justify-end gap-3">
              {footer}
            </div>
          )}
        </div>
      </div>
    </>
  )
}
