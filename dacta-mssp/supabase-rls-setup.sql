-- ============================================================
-- DACTA SIEMLess — RLS Security Lockdown (IDEMPOTENT)
-- Safe to run multiple times. Drops existing policies first.
-- Run in Supabase Dashboard → SQL Editor
-- ============================================================

-- ============================================================
-- STEP 1: Drop ALL existing policies (safe if they don't exist)
-- ============================================================
DO $$ 
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN 
        SELECT policyname, tablename 
        FROM pg_policies 
        WHERE schemaname = 'public'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I', pol.policyname, pol.tablename);
    END LOOP;
END $$;

-- ============================================================
-- STEP 2: Enable RLS on ALL 28 tables
-- ============================================================
ALTER TABLE ai_investigation_briefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE emerging_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE geo_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_usage_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_novelties ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_parser_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_parser_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_org_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_techniques ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_validation_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE sla_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- ============================================================
-- STEP 3: Create policies — AUTHENTICATED gets full access
--         ANON gets NOTHING (no policies = no access with RLS on)
-- ============================================================

-- ai_investigation_briefs
CREATE POLICY "auth_select_ai_investigation_briefs" ON ai_investigation_briefs FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_ai_investigation_briefs" ON ai_investigation_briefs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_ai_investigation_briefs" ON ai_investigation_briefs FOR UPDATE TO authenticated USING (true);

-- assets
CREATE POLICY "auth_select_assets" ON assets FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_assets" ON assets FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_assets" ON assets FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_assets" ON assets FOR DELETE TO authenticated USING (true);

-- audit_log
CREATE POLICY "auth_select_audit_log" ON audit_log FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_audit_log" ON audit_log FOR INSERT TO authenticated WITH CHECK (true);

-- cases
CREATE POLICY "auth_select_cases" ON cases FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_cases" ON cases FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_cases" ON cases FOR UPDATE TO authenticated USING (true);

-- detection_rules
CREATE POLICY "auth_select_detection_rules" ON detection_rules FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_detection_rules" ON detection_rules FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_detection_rules" ON detection_rules FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_detection_rules" ON detection_rules FOR DELETE TO authenticated USING (true);

-- emerging_threats
CREATE POLICY "auth_select_emerging_threats" ON emerging_threats FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_emerging_threats" ON emerging_threats FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_emerging_threats" ON emerging_threats FOR UPDATE TO authenticated USING (true);

-- geo_alerts
CREATE POLICY "auth_select_geo_alerts" ON geo_alerts FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_geo_alerts" ON geo_alerts FOR INSERT TO authenticated WITH CHECK (true);

-- integrations
CREATE POLICY "auth_select_integrations" ON integrations FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_integrations" ON integrations FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_integrations" ON integrations FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_integrations" ON integrations FOR DELETE TO authenticated USING (true);

-- investigation_cache
CREATE POLICY "auth_select_investigation_cache" ON investigation_cache FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_investigation_cache" ON investigation_cache FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_investigation_cache" ON investigation_cache FOR UPDATE TO authenticated USING (true);

-- llm_usage_log
CREATE POLICY "auth_select_llm_usage_log" ON llm_usage_log FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_llm_usage_log" ON llm_usage_log FOR INSERT TO authenticated WITH CHECK (true);

-- log_novelties
CREATE POLICY "auth_select_log_novelties" ON log_novelties FOR SELECT TO authenticated USING (true);

-- log_parser_configs
CREATE POLICY "auth_select_log_parser_configs" ON log_parser_configs FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_log_parser_configs" ON log_parser_configs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_log_parser_configs" ON log_parser_configs FOR UPDATE TO authenticated USING (true);

-- log_parser_patterns
CREATE POLICY "auth_select_log_parser_patterns" ON log_parser_patterns FOR SELECT TO authenticated USING (true);

-- mitre_org_hits
CREATE POLICY "auth_select_mitre_org_hits" ON mitre_org_hits FOR SELECT TO authenticated USING (true);

-- mitre_techniques
CREATE POLICY "auth_select_mitre_techniques" ON mitre_techniques FOR SELECT TO authenticated USING (true);

-- notification_rules
CREATE POLICY "auth_select_notification_rules" ON notification_rules FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_notification_rules" ON notification_rules FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_notification_rules" ON notification_rules FOR UPDATE TO authenticated USING (true);

-- org_connectors
CREATE POLICY "auth_select_org_connectors" ON org_connectors FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_org_connectors" ON org_connectors FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_org_connectors" ON org_connectors FOR UPDATE TO authenticated USING (true);

-- organizations
CREATE POLICY "auth_select_organizations" ON organizations FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_organizations" ON organizations FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_organizations" ON organizations FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_organizations" ON organizations FOR DELETE TO authenticated USING (true);

-- reports
CREATE POLICY "auth_select_reports" ON reports FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_reports" ON reports FOR INSERT TO authenticated WITH CHECK (true);

-- response_playbooks
CREATE POLICY "auth_select_response_playbooks" ON response_playbooks FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_response_playbooks" ON response_playbooks FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_response_playbooks" ON response_playbooks FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_response_playbooks" ON response_playbooks FOR DELETE TO authenticated USING (true);

-- rule_validation_queue
CREATE POLICY "auth_select_rule_validation_queue" ON rule_validation_queue FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_rule_validation_queue" ON rule_validation_queue FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_rule_validation_queue" ON rule_validation_queue FOR UPDATE TO authenticated USING (true);

-- sla_configs
CREATE POLICY "auth_select_sla_configs" ON sla_configs FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_sla_configs" ON sla_configs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_sla_configs" ON sla_configs FOR UPDATE TO authenticated USING (true);
CREATE POLICY "auth_delete_sla_configs" ON sla_configs FOR DELETE TO authenticated USING (true);

-- threat_intel_feeds
CREATE POLICY "auth_select_threat_intel_feeds" ON threat_intel_feeds FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_threat_intel_feeds" ON threat_intel_feeds FOR INSERT TO authenticated WITH CHECK (true);

-- threat_intel_iocs
CREATE POLICY "auth_select_threat_intel_iocs" ON threat_intel_iocs FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_threat_intel_iocs" ON threat_intel_iocs FOR INSERT TO authenticated WITH CHECK (true);

-- ticket_comments
CREATE POLICY "auth_select_ticket_comments" ON ticket_comments FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_ticket_comments" ON ticket_comments FOR INSERT TO authenticated WITH CHECK (true);

-- ticket_timeline
CREATE POLICY "auth_select_ticket_timeline" ON ticket_timeline FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_ticket_timeline" ON ticket_timeline FOR INSERT TO authenticated WITH CHECK (true);

-- tickets
CREATE POLICY "auth_select_tickets" ON tickets FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_tickets" ON tickets FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_tickets" ON tickets FOR UPDATE TO authenticated USING (true);

-- users (read all, but only update own profile)
CREATE POLICY "auth_select_users" ON users FOR SELECT TO authenticated USING (true);
CREATE POLICY "auth_insert_users" ON users FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "auth_update_own_users" ON users FOR UPDATE TO authenticated USING (auth.uid() = id);

-- ============================================================
-- STEP 4: Performance indexes (IF NOT EXISTS = safe to re-run)
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_tickets_org_id ON tickets(org_id);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON tickets(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_investigation_briefs_ticket_id ON ai_investigation_briefs(ticket_id);
CREATE INDEX IF NOT EXISTS idx_investigation_cache_ticket_key ON investigation_cache(ticket_key);
CREATE INDEX IF NOT EXISTS idx_llm_usage_log_created_at ON llm_usage_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_geo_alerts_org_id ON geo_alerts(org_id);
CREATE INDEX IF NOT EXISTS idx_geo_alerts_created_at ON geo_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_org_id ON assets(org_id);
CREATE INDEX IF NOT EXISTS idx_integrations_org_id ON integrations(org_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_org_id ON detection_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_emerging_threats_published_at ON emerging_threats(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_organizations_short_name ON organizations(short_name);
