-- ============================================================
-- SSO & JIRA ACCOUNT LINKING — Schema Migration
-- Run this in the Supabase SQL Editor
-- ============================================================

-- SSO identity fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject_id TEXT;

-- Jira account linking fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS jira_account_id TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS jira_display_name TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS jira_email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS jira_linked_at TIMESTAMPTZ;

-- Index on jira_account_id for fast lookups during escalation
CREATE INDEX IF NOT EXISTS idx_users_jira_account_id ON users(jira_account_id) WHERE jira_account_id IS NOT NULL;

-- Index on sso_subject_id for post-login matching
CREATE INDEX IF NOT EXISTS idx_users_sso_subject_id ON users(sso_subject_id) WHERE sso_subject_id IS NOT NULL;
