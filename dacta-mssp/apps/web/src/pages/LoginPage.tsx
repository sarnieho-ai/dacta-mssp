import React, { useState } from 'react'
import { Navigate } from 'react-router-dom'
import { Shield, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { useAuthContext } from '../contexts/AuthContext'

export function LoginPage() {
  const { session, signIn, loading } = useAuthContext()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!loading && session) {
    return <Navigate to="/dashboard" replace />
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password.trim()) return
    setSubmitting(true)
    setError(null)
    const { error: err } = await signIn(email.trim(), password)
    if (err) {
      setError(err)
    }
    setSubmitting(false)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#080d1a] p-4 relative overflow-hidden">
      {/* Background glow effects */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-[rgba(56,189,248,0.04)] blur-[120px]" />
        <div className="absolute bottom-1/4 left-1/4 w-[400px] h-[400px] rounded-full bg-[rgba(0,102,204,0.05)] blur-[100px]" />
      </div>

      {/* Grid pattern overlay */}
      <div
        className="absolute inset-0 pointer-events-none opacity-[0.025]"
        style={{
          backgroundImage: 'linear-gradient(rgba(56,189,248,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.5) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#38bdf8] to-[#0066cc] flex items-center justify-center shadow-[0_0_32px_rgba(56,189,248,0.4)] mb-4">
            <Shield size={22} strokeWidth={1.5} className="text-white" />
          </div>
          <h1 className="text-xl font-bold text-[#e2e8f0] font-[Sora]">DACTA</h1>
          <p className="text-xs text-[#64748b] uppercase tracking-[0.15em] mt-0.5">Mission Control Center</p>
        </div>

        {/* Card */}
        <div className="bg-[rgba(13,19,36,0.9)] backdrop-blur-[20px] border border-[rgba(56,189,248,0.1)] rounded-xl p-7 shadow-[0_0_60px_rgba(0,0,0,0.5)]">
          <h2 className="text-sm font-semibold text-[#e2e8f0] mb-1">Sign in to your account</h2>
          <p className="text-xs text-[#64748b] mb-6">For Blue Team, By Blue Team</p>

          {error && (
            <div className="flex items-start gap-2 bg-[rgba(239,68,68,0.08)] border border-[rgba(239,68,68,0.2)] rounded-lg px-3 py-2.5 mb-4">
              <AlertCircle size={14} className="text-red-400 mt-0.5 flex-shrink-0" strokeWidth={1.5} />
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Email address</label>
              <input
                type="email"
                autoComplete="email"
                placeholder="analyst@company.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                className="mcc-input"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#94a3b8] mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  className="mcc-input pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-[#64748b] hover:text-[#94a3b8] transition-colors"
                >
                  {showPassword ? <EyeOff size={14} strokeWidth={1.5} /> : <Eye size={14} strokeWidth={1.5} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={submitting || !email || !password}
              className="w-full btn-primary py-2.5 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {submitting ? (
                <>
                  <span className="w-4 h-4 border-2 border-[#080d1a]/30 border-t-[#080d1a] rounded-full animate-spin" />
                  Authenticating…
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          <div className="mt-5 pt-5 border-t border-[rgba(255,255,255,0.06)]">
            <p className="text-[11px] text-[#64748b] text-center">
              Protected by DACTA MCC · SOC Platform v2.0
            </p>
          </div>
        </div>

        {/* Footer */}
        <p className="text-[11px] text-[#64748b] text-center mt-5">
          © {new Date().getFullYear()} DACTA · Authorized Personnel Only
        </p>
      </div>
    </div>
  )
}
