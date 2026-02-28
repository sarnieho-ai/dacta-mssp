import React from 'react'
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
  ArrowRight,
} from 'lucide-react'

const ICON_MAP: Record<string, React.ElementType> = {
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
}

interface PlaceholderPageProps {
  title: string
  icon?: string
  description?: string
}

export function PlaceholderPage({ title, icon = 'LayoutDashboard', description }: PlaceholderPageProps) {
  const Icon = ICON_MAP[icon] ?? LayoutDashboard

  return (
    <div className="flex flex-col items-center justify-center h-full p-8 animate-fade-in">
      {/* Background glow */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full bg-[rgba(56,189,248,0.03)] blur-[80px]" />
      </div>

      <div className="relative flex flex-col items-center text-center max-w-md">
        {/* Icon */}
        <div className="w-16 h-16 rounded-2xl bg-[rgba(56,189,248,0.08)] border border-[rgba(56,189,248,0.12)] flex items-center justify-center mb-5">
          <Icon size={28} strokeWidth={1} className="text-[#38bdf8]" />
        </div>

        {/* Title */}
        <h1 className="text-xl font-bold text-[#e2e8f0] font-[Sora] mb-2">{title}</h1>

        {/* Coming soon badge */}
        <div className="inline-flex items-center gap-1.5 bg-[rgba(56,189,248,0.08)] border border-[rgba(56,189,248,0.2)] text-[#38bdf8] text-[11px] font-semibold uppercase tracking-wider px-3 py-1 rounded-full mb-4">
          <span className="w-1.5 h-1.5 rounded-full bg-[#38bdf8] animate-pulse" />
          Coming Soon
        </div>

        {/* Description */}
        {description && (
          <p className="text-sm text-[#64748b] leading-relaxed mb-6">{description}</p>
        )}

        {/* Divider */}
        <div className="flex items-center gap-3 w-full mb-6">
          <div className="flex-1 h-px bg-[rgba(255,255,255,0.06)]" />
          <span className="text-[11px] text-[#64748b]">Module under construction</span>
          <div className="flex-1 h-px bg-[rgba(255,255,255,0.06)]" />
        </div>

        {/* Feature hints */}
        <div className="w-full space-y-2 text-left">
          {getFeatureHints(title).map((hint, i) => (
            <div key={i} className="flex items-center gap-2.5 bg-[rgba(255,255,255,0.02)] border border-[rgba(255,255,255,0.06)] rounded-lg px-3 py-2.5">
              <ArrowRight size={12} strokeWidth={1.5} className="text-[#38bdf8] flex-shrink-0" />
              <span className="text-xs text-[#94a3b8]">{hint}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function getFeatureHints(title: string): string[] {
  const hints: Record<string, string[]> = {
    'Detection Rules': [
      'Create and manage Sigma, YARA, and custom detection rules',
      'Test rules against sample log data in real-time',
      'Version control and change history for all rules',
      'Auto-mapping to MITRE ATT&CK techniques',
    ],
    'Log Parser': [
      'Visual log parser builder with regex and Grok support',
      'Real-time log novelty detection and alerting',
      'Multi-source ingestion with normalization',
      'CEF, LEEF, JSON, XML, and syslog format support',
    ],
    'Asset Inventory': [
      'Auto-discovery and classification of assets',
      'Criticality scoring and ownership tracking',
      'Vulnerability status integration',
      'Asset relationship mapping',
    ],
    'Geo Map': [
      'Real-time geolocation of attack sources',
      'VPN, Tor, and proxy detection overlay',
      'Threat cluster visualization by region',
      'Time-lapse attack pattern replay',
    ],
    'Reports': [
      'Automated weekly and monthly executive reports',
      'Incident-level forensic timelines',
      'SLA compliance and trend charts',
      'Custom report builder with branding',
    ],
    'Integration Hub': [
      'Native Jira, ServiceNow, and PagerDuty connectors',
      'SIEM, SOAR, and EDR integrations',
      'Webhook and REST API support',
      'Real-time health monitoring for all connectors',
    ],
    'Settings': [
      'User management and role-based access control',
      'SLA policy configuration per organization',
      'Notification rules and escalation paths',
      'Audit log and compliance reporting',
    ],
  }
  return hints[title] ?? [
    'This module is being built by the DACTA engineering team',
    'Check back soon for updates',
  ]
}
