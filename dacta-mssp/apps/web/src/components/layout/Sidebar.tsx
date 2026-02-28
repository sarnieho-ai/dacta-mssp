import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  ShieldAlert,
  Globe,
  Network,
  FileCode,
  Terminal,
  Monitor,
  Map,
  FileText,
  Puzzle,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
} from 'lucide-react'
import { useAuthContext } from '../../contexts/AuthContext'

interface NavItem {
  to: string
  label: string
  icon: React.ElementType
}

interface NavSection {
  title: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    title: 'Operations',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/triage', label: 'Alert Triage', icon: ShieldAlert },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { to: '/threat-intel', label: 'Threat Intel', icon: Globe },
      { to: '/mitre', label: 'MITRE ATT&CK', icon: Network },
    ],
  },
  {
    title: 'Detection',
    items: [
      { to: '/detection-rules', label: 'Detection Rules', icon: FileCode },
      { to: '/log-parser', label: 'Log Parser', icon: Terminal },
    ],
  },
  {
    title: 'Assets & Visibility',
    items: [
      { to: '/assets', label: 'Assets', icon: Monitor },
      { to: '/geo-map', label: 'Geo Map', icon: Map },
    ],
  },
  {
    title: 'Reporting',
    items: [
      { to: '/reports', label: 'Reports', icon: FileText },
    ],
  },
  {
    title: 'Platform',
    items: [
      { to: '/integration-hub', label: 'Integration Hub', icon: Puzzle },
      { to: '/settings', label: 'Settings', icon: Settings },
    ],
  },
]

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { profile } = useAuthContext()
  const location = useLocation()

  const getRoleClass = (role: string | undefined) => {
    if (role?.includes('admin')) return 'admin'
    if (role?.includes('manager')) return 'manager'
    if (role?.includes('analyst') || role?.includes('engineer')) return 'analyst'
    return 'default'
  }

  return (
    <aside className={`mcc-sidebar ${collapsed ? 'collapsed' : 'expanded'}`}>
      {/* Logo */}
      <div className="mcc-sidebar-logo">
        <div className="mcc-sidebar-logo-icon">
          <Shield size={14} strokeWidth={2} color="white" />
        </div>
        <div className="mcc-sidebar-logo-text">
          <div className="mcc-sidebar-brand">DACTA</div>
          <div className="mcc-sidebar-sub">SIEMLess</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="mcc-sidebar-nav">
        {navSections.map(section => (
          <div key={section.title} style={{ marginBottom: 4 }}>
            <div className="mcc-sidebar-section-label">{section.title}</div>
            <div className="mcc-sidebar-section-divider" />
            {section.items.map(item => {
              const isActive = location.pathname === item.to || location.pathname.startsWith(item.to + '/')
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  title={collapsed ? item.label : undefined}
                  className={`mcc-nav-item ${isActive ? 'active' : ''}`}
                >
                  <item.icon size={16} strokeWidth={1.5} style={{ flexShrink: 0 }} />
                  <span className="mcc-nav-label">{item.label}</span>
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      {/* User section */}
      {profile && (
        <div className="mcc-sidebar-user">
          <div className="mcc-sidebar-user-row">
            <div className="mcc-sidebar-avatar">
              {(profile.full_name ?? profile.email ?? 'U').charAt(0).toUpperCase()}
            </div>
            {!collapsed && (
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {profile.full_name ?? profile.email}
                </div>
                <span className={`role-badge ${getRoleClass(profile.role)}`}>
                  {profile.role?.replace(/_/g, ' ')}
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Toggle */}
      <button onClick={onToggle} className="mcc-sidebar-toggle" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
        {collapsed
          ? <ChevronRight size={16} strokeWidth={1.5} />
          : <ChevronLeft size={16} strokeWidth={1.5} />
        }
      </button>
    </aside>
  )
}
