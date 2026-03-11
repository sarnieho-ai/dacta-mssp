-- ============================================================
-- DACTA SIEMLess — Analyst Investigation Corpus Table
-- Run in Supabase Dashboard → SQL Editor
-- Creates table for storing analyst investigation patterns
-- extracted from closed Jira tickets
-- ============================================================

CREATE TABLE IF NOT EXISTS analyst_investigation_corpus (
  id BIGSERIAL PRIMARY KEY,
  ticket_key TEXT UNIQUE NOT NULL,
  summary TEXT,
  detection_rule TEXT,
  status TEXT,
  resolution TEXT,
  priority TEXT,
  org TEXT,
  assignee TEXT,
  created_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  comment_count INTEGER DEFAULT 0,
  meaningful_comment_count INTEGER DEFAULT 0,
  closure_reasoning TEXT,
  comment_timeline JSONB DEFAULT '[]'::jsonb,
  entities JSONB DEFAULT '{}'::jsonb,
  extracted_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast lookup by detection rule and org
CREATE INDEX IF NOT EXISTS idx_corpus_detection_rule ON analyst_investigation_corpus(detection_rule);
CREATE INDEX IF NOT EXISTS idx_corpus_org ON analyst_investigation_corpus(org);
CREATE INDEX IF NOT EXISTS idx_corpus_resolved ON analyst_investigation_corpus(resolved_at DESC);

-- RLS: allow service_role full access
ALTER TABLE analyst_investigation_corpus ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS corpus_service_role_all ON analyst_investigation_corpus;
CREATE POLICY corpus_service_role_all ON analyst_investigation_corpus 
  FOR ALL USING (true) WITH CHECK (true);

-- Verify
SELECT 'analyst_investigation_corpus created successfully' AS result;
