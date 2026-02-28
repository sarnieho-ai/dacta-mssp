import { useState, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { Search, Bell, ChevronDown, LogOut, User, Shield } from 'lucide-react'
import { useAuthContext } from '../../contexts/AuthContext'

const pageTitles: Record<string, string> = {
  '/dashboard': 'Dashboard',
  '/triage': 'Alert Triage',
  '/threat-intel': 'Threat Intelligence',
  '/mitre': 'MITRE ATT&CK',
  '/detection-rules': 'Detection Rules',
  '/log-parser': 'Log Parser',
  '/assets': 'Asset Inventory',
  '/geo-map': 'Geo Map',
  '/reports': 'Reports',
  '/integration-hub': 'Integration Hub',
  '/settings': 'Settings',
}

export function TopBar() {
  const { profile, signOut } = useAuthContext()
  const location = useLocation()
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  const pageTitle = pageTitles[location.pathname] ?? 'Dashboard'

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  return (
    <header className="mcc-topbar">
      <div className="mcc-topbar-brand">
        <Shield size={16} strokeWidth={1.5} style={{ color: 'var(--accent-cyan)' }} />
        <span>Mission Control Center</span>
        <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: 12, marginLeft: 8 }}>
          DACTA SOC Platform
        </span>
      </div>

      <div className="mcc-topbar-search" style={{ position: 'relative' }}>
        <Search size={14} strokeWidth={1.5} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
        <input type="text" placeholder="Search alerts, IOCs, assets..." />
      </div>

      <div className="mcc-topbar-actions">
        <button style={{ background: 'none', border: 'none', color: 'var(--text-muted)', position: 'relative', padding: 4 }} title="Notifications">
          <Bell size={18} strokeWidth={1.5} />
        </button>

        <div ref={menuRef} style={{ position: 'relative' }}>
          <button
            onClick={() => setMenuOpen(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              background: 'none', border: 'none', color: 'var(--text-secondary)',
              padding: '4px 8px', borderRadius: 6, cursor: 'pointer',
            }}
          >
            <div className="mcc-sidebar-avatar" style={{ width: 26, height: 26, fontSize: 10 }}>
              {(profile?.full_name ?? profile?.email ?? 'U').charAt(0).toUpperCase()}
            </div>
            <span style={{ fontSize: 12, fontWeight: 500, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {profile?.email ?? 'Analyst'}
            </span>
            <ChevronDown size={14} strokeWidth={1.5} />
          </button>

          {menuOpen && (
            <div style={{
              position: 'absolute', top: '100%', right: 0, marginTop: 8,
              background: 'var(--bg-surface)', border: '1px solid var(--border-card)',
              borderRadius: 'var(--radius-md)', padding: 4, minWidth: 180,
              boxShadow: '0 8px 32px rgba(0,0,0,0.4)', zIndex: 200,
            }}>
              <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--border-subtle)' }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)' }}>{profile?.full_name}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{profile?.email}</div>
              </div>
              <button
                onClick={signOut}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                  padding: '8px 12px', background: 'none', border: 'none',
                  color: 'var(--danger)', fontSize: 12, borderRadius: 4, cursor: 'pointer',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(239,68,68,0.08)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'none')}
              >
                <LogOut size={14} strokeWidth={1.5} />
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
