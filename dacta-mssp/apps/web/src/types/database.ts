export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export interface Database {
  public: {
    Tables: {
      organizations: {
        Row: {
          id: string
          name: string
          slug: string
          domain: string | null
          status: 'active' | 'inactive' | 'suspended'
          tier: 'starter' | 'professional' | 'enterprise'
          timezone: string
          logo_url: string | null
          contact_email: string | null
          contact_phone: string | null
          sla_tier: 'standard' | 'premium' | 'critical'
          created_at: string
          updated_at: string
          metadata: Json | null
        }
        Insert: {
          id?: string
          name: string
          slug: string
          domain?: string | null
          status?: 'active' | 'inactive' | 'suspended'
          tier?: 'starter' | 'professional' | 'enterprise'
          timezone?: string
          logo_url?: string | null
          contact_email?: string | null
          contact_phone?: string | null
          sla_tier?: 'standard' | 'premium' | 'critical'
          created_at?: string
          updated_at?: string
          metadata?: Json | null
        }
        Update: Partial<Database['public']['Tables']['organizations']['Insert']>
      }
      users: {
        Row: {
          id: string
          auth_id: string
          email: string
          full_name: string
          role: 'admin' | 'analyst' | 'viewer' | 'manager'
          org_id: string | null
          avatar_url: string | null
          is_active: boolean
          last_login: string | null
          mfa_enabled: boolean
          created_at: string
          updated_at: string
          preferences: Json | null
        }
        Insert: {
          id?: string
          auth_id: string
          email: string
          full_name: string
          role?: 'admin' | 'analyst' | 'viewer' | 'manager'
          org_id?: string | null
          avatar_url?: string | null
          is_active?: boolean
          last_login?: string | null
          mfa_enabled?: boolean
          created_at?: string
          updated_at?: string
          preferences?: Json | null
        }
        Update: Partial<Database['public']['Tables']['users']['Insert']>
      }
      tickets: {
        Row: {
          id: string
          ticket_number: string
          title: string
          summary: string | null
          description: string | null
          priority: 'P1' | 'P2' | 'P3' | 'P4'
          status: 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed' | 'false_positive'
          verdict: 'true_positive' | 'false_positive' | 'benign' | 'under_review' | null
          verdict_confidence: number | null
          org_id: string
          assignee_id: string | null
          reporter_id: string | null
          source: string
          source_ref: string | null
          severity_score: number | null
          tags: string[] | null
          sla_breach_at: string | null
          sla_breached: boolean
          resolved_at: string | null
          closed_at: string | null
          created_at: string
          updated_at: string
          metadata: Json | null
        }
        Insert: {
          id?: string
          ticket_number?: string
          title: string
          summary?: string | null
          description?: string | null
          priority?: 'P1' | 'P2' | 'P3' | 'P4'
          status?: 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed' | 'false_positive'
          verdict?: 'true_positive' | 'false_positive' | 'benign' | 'under_review' | null
          verdict_confidence?: number | null
          org_id: string
          assignee_id?: string | null
          reporter_id?: string | null
          source?: string
          source_ref?: string | null
          severity_score?: number | null
          tags?: string[] | null
          sla_breach_at?: string | null
          sla_breached?: boolean
          resolved_at?: string | null
          closed_at?: string | null
          created_at?: string
          updated_at?: string
          metadata?: Json | null
        }
        Update: Partial<Database['public']['Tables']['tickets']['Insert']>
      }
      ai_investigation_briefs: {
        Row: {
          id: string
          ticket_id: string
          round: number
          model_used: string
          prompt_summary: string | null
          findings: string
          verdict: 'true_positive' | 'false_positive' | 'benign' | 'under_review'
          confidence: number
          recommended_actions: string[] | null
          iocs_found: Json | null
          mitre_techniques: string[] | null
          raw_response: string | null
          tokens_used: number | null
          duration_ms: number | null
          analyst_override: boolean
          analyst_verdict: string | null
          analyst_note: string | null
          created_at: string
        }
        Insert: {
          id?: string
          ticket_id: string
          round?: number
          model_used?: string
          prompt_summary?: string | null
          findings: string
          verdict?: 'true_positive' | 'false_positive' | 'benign' | 'under_review'
          confidence?: number
          recommended_actions?: string[] | null
          iocs_found?: Json | null
          mitre_techniques?: string[] | null
          raw_response?: string | null
          tokens_used?: number | null
          duration_ms?: number | null
          analyst_override?: boolean
          analyst_verdict?: string | null
          analyst_note?: string | null
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['ai_investigation_briefs']['Insert']>
      }
      assets: {
        Row: {
          id: string
          org_id: string
          hostname: string
          ip_address: string | null
          mac_address: string | null
          asset_type: 'server' | 'workstation' | 'network' | 'iot' | 'cloud' | 'other'
          os: string | null
          os_version: string | null
          criticality: 'critical' | 'high' | 'medium' | 'low'
          owner: string | null
          location: string | null
          tags: string[] | null
          last_seen: string | null
          is_active: boolean
          created_at: string
          updated_at: string
          metadata: Json | null
        }
        Insert: {
          id?: string
          org_id: string
          hostname: string
          ip_address?: string | null
          mac_address?: string | null
          asset_type?: 'server' | 'workstation' | 'network' | 'iot' | 'cloud' | 'other'
          os?: string | null
          os_version?: string | null
          criticality?: 'critical' | 'high' | 'medium' | 'low'
          owner?: string | null
          location?: string | null
          tags?: string[] | null
          last_seen?: string | null
          is_active?: boolean
          created_at?: string
          updated_at?: string
          metadata?: Json | null
        }
        Update: Partial<Database['public']['Tables']['assets']['Insert']>
      }
      audit_log: {
        Row: {
          id: string
          user_id: string | null
          org_id: string | null
          action: string
          entity_type: string
          entity_id: string | null
          old_values: Json | null
          new_values: Json | null
          ip_address: string | null
          user_agent: string | null
          created_at: string
        }
        Insert: {
          id?: string
          user_id?: string | null
          org_id?: string | null
          action: string
          entity_type: string
          entity_id?: string | null
          old_values?: Json | null
          new_values?: Json | null
          ip_address?: string | null
          user_agent?: string | null
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['audit_log']['Insert']>
      }
      integrations: {
        Row: {
          id: string
          org_id: string
          name: string
          type: string
          status: 'active' | 'inactive' | 'error' | 'configuring'
          config: Json
          last_sync: string | null
          error_message: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          name: string
          type: string
          status?: 'active' | 'inactive' | 'error' | 'configuring'
          config?: Json
          last_sync?: string | null
          error_message?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['integrations']['Insert']>
      }
      llm_usage_log: {
        Row: {
          id: string
          ticket_id: string | null
          user_id: string | null
          model: string
          prompt_tokens: number
          completion_tokens: number
          total_tokens: number
          cost_usd: number | null
          purpose: string
          duration_ms: number | null
          created_at: string
        }
        Insert: {
          id?: string
          ticket_id?: string | null
          user_id?: string | null
          model: string
          prompt_tokens?: number
          completion_tokens?: number
          total_tokens?: number
          cost_usd?: number | null
          purpose?: string
          duration_ms?: number | null
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['llm_usage_log']['Insert']>
      }
      sla_configs: {
        Row: {
          id: string
          org_id: string
          priority: 'P1' | 'P2' | 'P3' | 'P4'
          response_minutes: number
          resolution_minutes: number
          escalation_minutes: number
          is_active: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          priority: 'P1' | 'P2' | 'P3' | 'P4'
          response_minutes?: number
          resolution_minutes?: number
          escalation_minutes?: number
          is_active?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['sla_configs']['Insert']>
      }
      ticket_comments: {
        Row: {
          id: string
          ticket_id: string
          user_id: string
          body: string
          is_internal: boolean
          attachments: Json | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          ticket_id: string
          user_id: string
          body: string
          is_internal?: boolean
          attachments?: Json | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['ticket_comments']['Insert']>
      }
      ticket_timeline: {
        Row: {
          id: string
          ticket_id: string
          user_id: string | null
          event_type: string
          event_data: Json | null
          message: string | null
          created_at: string
        }
        Insert: {
          id?: string
          ticket_id: string
          user_id?: string | null
          event_type: string
          event_data?: Json | null
          message?: string | null
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['ticket_timeline']['Insert']>
      }
      detection_rules: {
        Row: {
          id: string
          org_id: string | null
          name: string
          description: string | null
          rule_type: 'sigma' | 'yara' | 'custom' | 'correlation'
          content: string
          status: 'active' | 'inactive' | 'testing' | 'deprecated'
          severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'
          mitre_tactics: string[] | null
          mitre_techniques: string[] | null
          false_positive_rate: number | null
          trigger_count: number
          last_triggered: string | null
          tags: string[] | null
          author: string | null
          version: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id?: string | null
          name: string
          description?: string | null
          rule_type?: 'sigma' | 'yara' | 'custom' | 'correlation'
          content: string
          status?: 'active' | 'inactive' | 'testing' | 'deprecated'
          severity?: 'critical' | 'high' | 'medium' | 'low' | 'informational'
          mitre_tactics?: string[] | null
          mitre_techniques?: string[] | null
          false_positive_rate?: number | null
          trigger_count?: number
          last_triggered?: string | null
          tags?: string[] | null
          author?: string | null
          version?: string
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['detection_rules']['Insert']>
      }
      rule_validation_queue: {
        Row: {
          id: string
          rule_id: string
          status: 'pending' | 'validating' | 'passed' | 'failed'
          validator: string | null
          results: Json | null
          errors: string[] | null
          created_at: string
          validated_at: string | null
        }
        Insert: {
          id?: string
          rule_id: string
          status?: 'pending' | 'validating' | 'passed' | 'failed'
          validator?: string | null
          results?: Json | null
          errors?: string[] | null
          created_at?: string
          validated_at?: string | null
        }
        Update: Partial<Database['public']['Tables']['rule_validation_queue']['Insert']>
      }
      threat_intel_feeds: {
        Row: {
          id: string
          name: string
          description: string | null
          url: string | null
          feed_type: 'osint' | 'commercial' | 'internal' | 'isac'
          format: 'stix' | 'taxii' | 'csv' | 'json' | 'txt'
          status: 'active' | 'inactive' | 'error'
          last_ingested: string | null
          ioc_count: number
          update_frequency_hours: number
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          description?: string | null
          url?: string | null
          feed_type?: 'osint' | 'commercial' | 'internal' | 'isac'
          format?: 'stix' | 'taxii' | 'csv' | 'json' | 'txt'
          status?: 'active' | 'inactive' | 'error'
          last_ingested?: string | null
          ioc_count?: number
          update_frequency_hours?: number
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['threat_intel_feeds']['Insert']>
      }
      threat_intel_iocs: {
        Row: {
          id: string
          feed_id: string | null
          ioc_type: 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cve' | 'other'
          value: string
          verdict: 'malicious' | 'suspicious' | 'benign' | 'unknown'
          confidence: number
          severity: 'critical' | 'high' | 'medium' | 'low'
          tags: string[] | null
          source: string | null
          first_seen: string | null
          last_seen: string | null
          expiry: string | null
          enrichment: Json | null
          hit_count: number
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          feed_id?: string | null
          ioc_type: 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'cve' | 'other'
          value: string
          verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown'
          confidence?: number
          severity?: 'critical' | 'high' | 'medium' | 'low'
          tags?: string[] | null
          source?: string | null
          first_seen?: string | null
          last_seen?: string | null
          expiry?: string | null
          enrichment?: Json | null
          hit_count?: number
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['threat_intel_iocs']['Insert']>
      }
      emerging_threats: {
        Row: {
          id: string
          title: string
          description: string
          threat_actor: string | null
          campaign_name: string | null
          severity: 'critical' | 'high' | 'medium' | 'low'
          status: 'active' | 'monitoring' | 'resolved'
          affected_sectors: string[] | null
          affected_regions: string[] | null
          mitre_techniques: string[] | null
          ioc_count: number
          source_url: string | null
          published_at: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          title: string
          description: string
          threat_actor?: string | null
          campaign_name?: string | null
          severity?: 'critical' | 'high' | 'medium' | 'low'
          status?: 'active' | 'monitoring' | 'resolved'
          affected_sectors?: string[] | null
          affected_regions?: string[] | null
          mitre_techniques?: string[] | null
          ioc_count?: number
          source_url?: string | null
          published_at?: string
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['emerging_threats']['Insert']>
      }
      mitre_techniques: {
        Row: {
          id: string
          technique_id: string
          name: string
          description: string | null
          tactic: string
          matrix: 'enterprise' | 'ics' | 'mobile'
          is_subtechnique: boolean
          parent_id: string | null
          url: string | null
          data_sources: string[] | null
          platforms: string[] | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          technique_id: string
          name: string
          description?: string | null
          tactic: string
          matrix?: 'enterprise' | 'ics' | 'mobile'
          is_subtechnique?: boolean
          parent_id?: string | null
          url?: string | null
          data_sources?: string[] | null
          platforms?: string[] | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['mitre_techniques']['Insert']>
      }
      mitre_org_hits: {
        Row: {
          id: string
          org_id: string
          technique_id: string
          hit_count: number
          ticket_ids: string[] | null
          last_seen: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          technique_id: string
          hit_count?: number
          ticket_ids?: string[] | null
          last_seen?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['mitre_org_hits']['Insert']>
      }
      log_parser_configs: {
        Row: {
          id: string
          org_id: string
          name: string
          description: string | null
          log_source: string
          parser_type: 'regex' | 'grok' | 'json' | 'xml' | 'csv' | 'custom'
          config: Json
          status: 'active' | 'inactive' | 'testing'
          sample_log: string | null
          field_mappings: Json | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          name: string
          description?: string | null
          log_source: string
          parser_type?: 'regex' | 'grok' | 'json' | 'xml' | 'csv' | 'custom'
          config: Json
          status?: 'active' | 'inactive' | 'testing'
          sample_log?: string | null
          field_mappings?: Json | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['log_parser_configs']['Insert']>
      }
      log_novelties: {
        Row: {
          id: string
          org_id: string
          parser_id: string | null
          log_source: string
          pattern: string
          first_seen: string
          last_seen: string
          occurrence_count: number
          severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
          status: 'new' | 'reviewed' | 'dismissed' | 'escalated'
          sample_log: string | null
          analyst_note: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          parser_id?: string | null
          log_source: string
          pattern: string
          first_seen?: string
          last_seen?: string
          occurrence_count?: number
          severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
          status?: 'new' | 'reviewed' | 'dismissed' | 'escalated'
          sample_log?: string | null
          analyst_note?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['log_novelties']['Insert']>
      }
      log_parser_patterns: {
        Row: {
          id: string
          parser_id: string
          name: string
          pattern: string
          description: string | null
          is_active: boolean
          priority: number
          created_at: string
        }
        Insert: {
          id?: string
          parser_id: string
          name: string
          pattern: string
          description?: string | null
          is_active?: boolean
          priority?: number
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['log_parser_patterns']['Insert']>
      }
      geo_alerts: {
        Row: {
          id: string
          org_id: string
          ticket_id: string | null
          source_ip: string
          source_country: string | null
          source_city: string | null
          source_lat: number | null
          source_lon: number | null
          dest_ip: string | null
          dest_country: string | null
          event_type: string
          severity: 'critical' | 'high' | 'medium' | 'low'
          is_vpn: boolean
          is_tor: boolean
          is_proxy: boolean
          asn: string | null
          created_at: string
        }
        Insert: {
          id?: string
          org_id: string
          ticket_id?: string | null
          source_ip: string
          source_country?: string | null
          source_city?: string | null
          source_lat?: number | null
          source_lon?: number | null
          dest_ip?: string | null
          dest_country?: string | null
          event_type: string
          severity?: 'critical' | 'high' | 'medium' | 'low'
          is_vpn?: boolean
          is_tor?: boolean
          is_proxy?: boolean
          asn?: string | null
          created_at?: string
        }
        Update: Partial<Database['public']['Tables']['geo_alerts']['Insert']>
      }
      reports: {
        Row: {
          id: string
          org_id: string
          title: string
          report_type: 'weekly' | 'monthly' | 'incident' | 'executive' | 'custom'
          status: 'draft' | 'generating' | 'ready' | 'sent' | 'failed'
          period_start: string | null
          period_end: string | null
          generated_by: string | null
          file_url: string | null
          file_size: number | null
          recipient_emails: string[] | null
          sent_at: string | null
          created_at: string
          updated_at: string
          metadata: Json | null
        }
        Insert: {
          id?: string
          org_id: string
          title: string
          report_type?: 'weekly' | 'monthly' | 'incident' | 'executive' | 'custom'
          status?: 'draft' | 'generating' | 'ready' | 'sent' | 'failed'
          period_start?: string | null
          period_end?: string | null
          generated_by?: string | null
          file_url?: string | null
          file_size?: number | null
          recipient_emails?: string[] | null
          sent_at?: string | null
          created_at?: string
          updated_at?: string
          metadata?: Json | null
        }
        Update: Partial<Database['public']['Tables']['reports']['Insert']>
      }
      org_connectors: {
        Row: {
          id: string
          org_id: string
          connector_type: string
          display_name: string
          status: 'connected' | 'disconnected' | 'error' | 'pending'
          config: Json
          credentials: Json | null
          last_heartbeat: string | null
          error_message: string | null
          version: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          connector_type: string
          display_name: string
          status?: 'connected' | 'disconnected' | 'error' | 'pending'
          config?: Json
          credentials?: Json | null
          last_heartbeat?: string | null
          error_message?: string | null
          version?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['org_connectors']['Insert']>
      }
      notification_rules: {
        Row: {
          id: string
          org_id: string
          name: string
          description: string | null
          trigger_event: string
          conditions: Json
          channels: Json
          is_active: boolean
          last_triggered: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          org_id: string
          name: string
          description?: string | null
          trigger_event: string
          conditions?: Json
          channels?: Json
          is_active?: boolean
          last_triggered?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: Partial<Database['public']['Tables']['notification_rules']['Insert']>
      }
      cases: {
        Row: {
          id: string
          case_number: string
          title: string
          description: string | null
          org_id: string
          status: 'open' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed'
          severity: 'critical' | 'high' | 'medium' | 'low'
          lead_analyst_id: string | null
          ticket_ids: string[] | null
          asset_ids: string[] | null
          tags: string[] | null
          timeline: Json | null
          ioc_ids: string[] | null
          mitre_techniques: string[] | null
          created_at: string
          updated_at: string
          closed_at: string | null
          metadata: Json | null
        }
        Insert: {
          id?: string
          case_number?: string
          title: string
          description?: string | null
          org_id: string
          status?: 'open' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed'
          severity?: 'critical' | 'high' | 'medium' | 'low'
          lead_analyst_id?: string | null
          ticket_ids?: string[] | null
          asset_ids?: string[] | null
          tags?: string[] | null
          timeline?: Json | null
          ioc_ids?: string[] | null
          mitre_techniques?: string[] | null
          created_at?: string
          updated_at?: string
          closed_at?: string | null
          metadata?: Json | null
        }
        Update: Partial<Database['public']['Tables']['cases']['Insert']>
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      [_ in never]: never
    }
    Enums: {
      [_ in never]: never
    }
  }
}

// Convenience type aliases
export type Tables<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Row']
export type InsertTables<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Insert']
export type UpdateTables<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Update']

// Row types
export type Organization = Tables<'organizations'>
export type User = Tables<'users'>
export type Ticket = Tables<'tickets'>
export type AIInvestigationBrief = Tables<'ai_investigation_briefs'>
export type Asset = Tables<'assets'>
export type AuditLog = Tables<'audit_log'>
export type Integration = Tables<'integrations'>
export type LLMUsageLog = Tables<'llm_usage_log'>
export type SLAConfig = Tables<'sla_configs'>
export type TicketComment = Tables<'ticket_comments'>
export type TicketTimeline = Tables<'ticket_timeline'>
export type DetectionRule = Tables<'detection_rules'>
export type RuleValidationQueue = Tables<'rule_validation_queue'>
export type ThreatIntelFeed = Tables<'threat_intel_feeds'>
export type ThreatIntelIOC = Tables<'threat_intel_iocs'>
export type EmergingThreat = Tables<'emerging_threats'>
export type MITRETechnique = Tables<'mitre_techniques'>
export type MITREOrgHit = Tables<'mitre_org_hits'>
export type LogParserConfig = Tables<'log_parser_configs'>
export type LogNovelty = Tables<'log_novelties'>
export type LogParserPattern = Tables<'log_parser_patterns'>
export type GeoAlert = Tables<'geo_alerts'>
export type Report = Tables<'reports'>
export type OrgConnector = Tables<'org_connectors'>
export type NotificationRule = Tables<'notification_rules'>
export type Case = Tables<'cases'>
