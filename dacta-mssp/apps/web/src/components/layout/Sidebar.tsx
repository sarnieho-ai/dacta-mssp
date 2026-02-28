import React, { useState } from 'react'
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

  const getRoleColor = (role: string | undefined) => {
    switch (role) {
      case 'admin': return 'text-red-400 bg-red-500/10 border-red-500/25'
      case 'manager': return 'text-orange-400 bg-orange-500/10 border-orange-500/25'
      case 'analyst': return 'text-blue-400 bg-blue-500/10 border-blue-500/25'
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20'
    }
  }

  return (
    <aside
      style={{
        width: collapsed ? 'var(--sidebar-collapsed)' : 'var(--sidebar-width)',
        minWidth: collapsed ? 'var(--sidebar-collapsed)' : 'var(--sidebar-width)',
      }}
      className="h-screen flex flex-col bg-[#0d1220] border-r border-[rgba(255,255,255,0.06)] transition-all duration-[350ms] ease-[cubic-bezier(0.4,0,0.2,1)] z-[100] relative overflow-hidden flex-shrink-0"
    >
      {/* Logo */}
      <div className="h-[56px] flex items-center gap-2.5 px-3 border-b border-[rgba(255,255,255,0.06)] flex-shrink-0 overflow-hidden">
        <div className="w-8 h-8 flex-shrink-0 rounded-[7px] bg-gradient-to-br from-[#38bdf8] to-[#0066cc] flex items-center justify-center shadow-[0_0_16px_rgba(56,189,248,0.35)]">
          <Shield size={14} strokeWidth={2} className="text-white" />
        </div>
        <div
          className="overflow-hidden transition-all duration-[350ms] ease-[cubic-bezier(0.4,0,0.2,1)]"
          style={{
            opacity: collapsed ? 0 : 1,
            width: collapsed ? 0 : 'auto',
            maxWidth: collapsed ? 0 : 200,
          }}
        >
          <div className="font-bold text-[15px] text-[#e2e8f0] whitespace-nowrap font-[Sora]">DACTA</div>
          <div className="text-[9px] font-medium text-[#64748b] uppercase tracking-[0.1em] whitespace-nowrap">SIEMLess</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-2 scrollbar-thin">
        {navSections.map(section => (
          <div key={section.title} className="mb-1">
            {!collapsed && (
              <div className="px-4 py-2 text-[9px] font-semibold uppercase tracking-[0.1em] text-[#64748b] whitespace-nowrap">
                {section.title}
              </div>
            )}
            {collapsed && <div className="my-1 mx-3 h-px bg-[rgba(255,255,255,0.04)]" />}
            {section.items.map(item => {
              const isActive = location.pathname === item.to || location.pathname.startsWith(item.to + '/')
              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  title={collapsed ? item.label : undefined}
                  className={`flex items-center gap-2.5 mx-1.5 my-0.5 px-3 py-2 rounded-md transition-all duration-150 cursor-pointer overflow-hidden relative group
                    ${isActive
                      ? 'bg-[rgba(56,189,248,0.1)] text-[#38bdf8] border-l-2 border-[#38bdf8] pl-[10px]'
                      : 'text-[#64748b] border-l-2 border-transparent hover:bg-[rgba(255,255,255,0.04)] hover:text-[#94a3b8]'
                    }`}
                >
                  <item.icon
                    size={16}
                    strokeWidth={1.5}
                    className={`flex-shrink-0 transition-colors ${isActive ? 'text-[#38bdf8]' : 'text-[#64748b] group-hover:text-[#94a3b8]'}`}
                  />
                  <span
                    className="text-[12.5px] font-medium whitespace-nowrap transition-all duration-[350ms]"
                    style={{
                      opacity: collapsed ? 0 : 1,
                      width: collapsed ? 0 : 'auto',
                      overflow: 'hidden',
                    }}
                  >
                    {item.label}
                  </span>
                </NavLink>
              )
            })}
          </div>
        ))}
      </nav>

      {/* User section */}
      {!collapsed && profile && (
        <div className="flex-shrink-0 border-t border-[rgba(255,255,255,0.06)] p-3">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#38bdf8] to-[#0066cc] flex items-center justify-center flex-shrink-0 text-xs font-bold text-white">
              {profile.full_name?.charAt(0)?.toUpperCase() ?? 'U'}
            </div>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-[#e2e8f0] truncate">{profile.full_name}</div>
              <div className={`inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider border mt-0.5 ${getRoleColor(profile.role)}`}>
                {profile.role}
              </div>
            </div>
          </div>
        </div>
      )}

      {collapsed && profile && (
        <div className="flex-shrink-0 border-t border-[rgba(255,255,255,0.06)] p-3 flex justify-center">
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#38bdf8] to-[#0066cc] flex items-center justify-center text-xs font-bold text-white">
            {profile.full_name?.charAt(0)?.toUpperCase() ?? 'U'}
          </div>
        </div>
      )}

      {/* Toggle */}
      <button
        onClick={onToggle}
        className="flex-shrink-0 h-10 flex items-center justify-center border-t border-[rgba(255,255,255,0.06)] text-[#64748b] hover:text-[#e2e8f0] hover:bg-[rgba(255,255,255,0.04)] transition-all duration-150"
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed
          ? <ChevronRight size={16} strokeWidth={1.5} />
          : <ChevronLeft size={16} strokeWidth={1.5} />
        }
      </button>
    </aside>
  )
}
