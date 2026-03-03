-- ============================================================
-- DACTA SIEMLess — Supabase RLS & Security Policies
-- Run this in Supabase Dashboard → SQL Editor
-- ============================================================

-- 1. Enable RLS on all tables
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE sla_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_usage_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_investigation_briefs ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE ticket_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE geo_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE emerging_threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_parser_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_parser_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_novelties ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_techniques ENABLE ROW LEVEL SECURITY;
ALTER TABLE mitre_org_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_validation_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- 2. Authenticated users can read all data (SOC platform — all analysts need full visibility)
-- Organizations
CREATE POLICY "Authenticated read organizations" ON organizations FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert organizations" ON organizations FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update organizations" ON organizations FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated delete organizations" ON organizations FOR DELETE TO authenticated USING (true);

-- Integrations
CREATE POLICY "Authenticated read integrations" ON integrations FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert integrations" ON integrations FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update integrations" ON integrations FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated delete integrations" ON integrations FOR DELETE TO authenticated USING (true);

-- SLA Configs
CREATE POLICY "Authenticated read sla_configs" ON sla_configs FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert sla_configs" ON sla_configs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update sla_configs" ON sla_configs FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated delete sla_configs" ON sla_configs FOR DELETE TO authenticated USING (true);

-- Audit Log (read for all, write for authenticated)
CREATE POLICY "Authenticated read audit_log" ON audit_log FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert audit_log" ON audit_log FOR INSERT TO authenticated WITH CHECK (true);

-- LLM Usage Log
CREATE POLICY "Authenticated read llm_usage_log" ON llm_usage_log FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert llm_usage_log" ON llm_usage_log FOR INSERT TO authenticated WITH CHECK (true);

-- AI Investigation Briefs
CREATE POLICY "Authenticated read ai_investigation_briefs" ON ai_investigation_briefs FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert ai_investigation_briefs" ON ai_investigation_briefs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update ai_investigation_briefs" ON ai_investigation_briefs FOR UPDATE TO authenticated USING (true);

-- Assets
CREATE POLICY "Authenticated read assets" ON assets FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert assets" ON assets FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update assets" ON assets FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated delete assets" ON assets FOR DELETE TO authenticated USING (true);

-- Tickets
CREATE POLICY "Authenticated read tickets" ON tickets FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert tickets" ON tickets FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update tickets" ON tickets FOR UPDATE TO authenticated USING (true);

-- Ticket Comments
CREATE POLICY "Authenticated read ticket_comments" ON ticket_comments FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert ticket_comments" ON ticket_comments FOR INSERT TO authenticated WITH CHECK (true);

-- Ticket Timeline
CREATE POLICY "Authenticated read ticket_timeline" ON ticket_timeline FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert ticket_timeline" ON ticket_timeline FOR INSERT TO authenticated WITH CHECK (true);

-- Cases
CREATE POLICY "Authenticated read cases" ON cases FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert cases" ON cases FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update cases" ON cases FOR UPDATE TO authenticated USING (true);

-- Detection Rules
CREATE POLICY "Authenticated read detection_rules" ON detection_rules FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert detection_rules" ON detection_rules FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update detection_rules" ON detection_rules FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated delete detection_rules" ON detection_rules FOR DELETE TO authenticated USING (true);

-- Geo Alerts
CREATE POLICY "Authenticated read geo_alerts" ON geo_alerts FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert geo_alerts" ON geo_alerts FOR INSERT TO authenticated WITH CHECK (true);

-- Emerging Threats
CREATE POLICY "Authenticated read emerging_threats" ON emerging_threats FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert emerging_threats" ON emerging_threats FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update emerging_threats" ON emerging_threats FOR UPDATE TO authenticated USING (true);

-- Threat Intel
CREATE POLICY "Authenticated read threat_intel_feeds" ON threat_intel_feeds FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert threat_intel_feeds" ON threat_intel_feeds FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated read threat_intel_iocs" ON threat_intel_iocs FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert threat_intel_iocs" ON threat_intel_iocs FOR INSERT TO authenticated WITH CHECK (true);

-- Investigation Cache
CREATE POLICY "Authenticated read investigation_cache" ON investigation_cache FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert investigation_cache" ON investigation_cache FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update investigation_cache" ON investigation_cache FOR UPDATE TO authenticated USING (true);

-- Log Parser
CREATE POLICY "Authenticated read log_parser_configs" ON log_parser_configs FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert log_parser_configs" ON log_parser_configs FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update log_parser_configs" ON log_parser_configs FOR UPDATE TO authenticated USING (true);
CREATE POLICY "Authenticated read log_parser_patterns" ON log_parser_patterns FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated read log_novelties" ON log_novelties FOR SELECT TO authenticated USING (true);

-- MITRE
CREATE POLICY "Authenticated read mitre_techniques" ON mitre_techniques FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated read mitre_org_hits" ON mitre_org_hits FOR SELECT TO authenticated USING (true);

-- Notification Rules
CREATE POLICY "Authenticated read notification_rules" ON notification_rules FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert notification_rules" ON notification_rules FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update notification_rules" ON notification_rules FOR UPDATE TO authenticated USING (true);

-- Org Connectors
CREATE POLICY "Authenticated read org_connectors" ON org_connectors FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert org_connectors" ON org_connectors FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update org_connectors" ON org_connectors FOR UPDATE TO authenticated USING (true);

-- Reports
CREATE POLICY "Authenticated read reports" ON reports FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert reports" ON reports FOR INSERT TO authenticated WITH CHECK (true);

-- Rule Validation Queue
CREATE POLICY "Authenticated read rule_validation_queue" ON rule_validation_queue FOR SELECT TO authenticated USING (true);
CREATE POLICY "Authenticated insert rule_validation_queue" ON rule_validation_queue FOR INSERT TO authenticated WITH CHECK (true);
CREATE POLICY "Authenticated update rule_validation_queue" ON rule_validation_queue FOR UPDATE TO authenticated USING (true);

-- Users table — users can read all, but only update their own profile
CREATE POLICY "Authenticated read users" ON users FOR SELECT TO authenticated USING (true);
CREATE POLICY "Users update own profile" ON users FOR UPDATE TO authenticated USING (auth.uid() = id);
CREATE POLICY "Authenticated insert users" ON users FOR INSERT TO authenticated WITH CHECK (true);

-- 3. BLOCK anonymous access entirely (anon role gets nothing after RLS is on)
-- This is automatic: with RLS enabled and policies only for 'authenticated',
-- the 'anon' role has no SELECT/INSERT/UPDATE/DELETE access.

-- 4. Create indexes for performance (addresses Supabase performance advisories)
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
CREATE INDEX IF NOT EXISTS idx_organizations_code ON organizations(code);
