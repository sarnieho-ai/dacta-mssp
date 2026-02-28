import React, { useState, useRef, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Search, Bell, ChevronDown, LogOut, User, Settings, Radio } from 'lucide-react'
import { useAuthContext } from '../../contexts/AuthContext'

export function TopBar() {
  const { profile, signOut } = useAuthContext()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const location = useLocation()

  // Page title from path
  const pageLabels: Record<string, string> = {
    '/dashboard': 'Mission Control Center',
    '/triage': 'Alert Triage',
    '/threat-intel': 'Threat Intelligence',
    '/mitre': 'MITRE ATT\u0026CK',
    '/detection-rules': 'Detection Rules',
    '/log-parser': 'Log Parser',
    '/assets': 'Asset Inventory',
    '/geo-map': 'Geo Map',
    '/reports': 'Reports',
    '/integration-hub': 'Integration Hub',
    '/settings': 'Settings',
  }

  const currentPath = '/' + location.pathname.split('/')[1]
  const pageTitle = pageLabels[currentPath] ?? 'Mission Control Center'

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const handleSignOut = async () => {
    await signOut()
    navigate('/login')
  }

  return (
    <header className="h-[56px] flex items-center px-5 gap-4 flex-shrink-0 border-b border-[rgba(56,189,248,0.06)] bg-[rgba(13,18,32,0.85)] backdrop-blur-[20px] z-50">
      {/* Page title */}
      <div className="flex items-center gap-2.5 flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Radio size={14} strokeWidth={1.5} className="text-[#38bdf8] flex-shrink-0" />
          <span className="text-sm font-semibold text-[#e2e8f0] whitespace-nowrap">{pageTitle}</span>
        </div>
        <div className="h-4 w-px bg-[rgba(255,255,255,0.1)] mx-1 hidden sm:block" />
        <span className="text-xs text-[#64748b] hidden sm:block">DACTA SOC Platform</span>
      </div>

      {/* Global search */}
      <div className="relative hidden md:flex items-center">
        <Search size={13} className="absolute left-3 text-[#64748b]" strokeWidth={1.5} />
        <input
          type="text"
          placeholder="Search alerts, IOCs, assets… (⌘K)"
          className="mcc-input pl-8 pr-4 py-1.5 text-xs w-64 lg:w-80"
          onKeyDown={e => e.key === 'k' && e.metaKey && e.preventDefault()}
        />
      </div>

      {/* Right actions */}
      <div className="flex items-center gap-2">
        {/* Notifications */}
        <button className="relative p-2 rounded-lg text-[#64748b] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.06)] transition-colors">
          <Bell size={16} strokeWidth={1.5} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-[#ef4444] shadow-[0_0_6px_rgba(239,68,68,0.6)]" />
        </button>

        {/* User menu */}
        <div ref={menuRef} className="relative">
          <button
            onClick={() => setMenuOpen(v => !v)}
            className="flex items-center gap-2 pl-1.5 pr-2.5 py-1.5 rounded-lg hover:bg-[rgba(255,255,255,0.06)] transition-colors"
          >
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-[#38bdf8] to-[#0066cc] flex items-center justify-center text-[10px] font-bold text-white">
              {profile?.full_name?.charAt(0)?.toUpperCase() ?? 'U'}
            </div>
            <span className="text-xs text-[#94a3b8] hidden sm:block max-w-[100px] truncate">
              {profile?.full_name ?? profile?.email ?? 'Analyst'}
            </span>
            <ChevronDown size={12} strokeWidth={1.5} className={`text-[#64748b] transition-transform ${menuOpen ? 'rotate-180' : ''}`} />
          </button>

          {menuOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-48 bg-[#111827] border border-[rgba(56,189,248,0.1)] rounded-lg shadow-2xl overflow-hidden z-50 animate-fade-in">
              <div className="px-3 py-2.5 border-b border-[rgba(255,255,255,0.06)]">
                <div className="text-xs font-medium text-[#e2e8f0] truncate">{profile?.full_name}</div>
                <div className="text-[11px] text-[#64748b] truncate">{profile?.email}</div>
              </div>
              <div className="py-1">
                <button
                  onClick={() => { setMenuOpen(false); navigate('/settings') }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-[#94a3b8] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
                >
                  <User size={14} strokeWidth={1.5} />
                  Profile
                </button>
                <button
                  onClick={() => { setMenuOpen(false); navigate('/settings') }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-[#94a3b8] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.05)] transition-colors"
                >
                  <Settings size={14} strokeWidth={1.5} />
                  Settings
                </button>
                <div className="my-1 h-px bg-[rgba(255,255,255,0.06)]" />
                <button
                  onClick={handleSignOut}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-red-400 hover:text-red-300 hover:bg-[rgba(239,68,68,0.06)] transition-colors"
                >
                  <LogOut size={14} strokeWidth={1.5} />
                  Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
