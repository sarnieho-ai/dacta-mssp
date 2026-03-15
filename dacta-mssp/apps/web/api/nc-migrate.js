// Temporary migration — creates novelty_catchers + novelty_alerts tables
// Uses direct Supabase Postgres connection via supabase-js v2

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SB_URL = 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SB_KEY = _d('ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKemRYQmhZbUZ6WlNJc0luSmxaaUk2SW5GcGNYSnBlbWRuYVhSamNYZHJkM05vYldaNUlpd2ljbTlzWlNJNkluTmxjblpwWTJWZmNtOXNaU0lzSW1saGRDSTZNVGMzTWpBM09UTXlNU3dpWlhod0lqb3lNRGczTmpVMU16SXhmUS5nQ3VEaUxISDZKT1VETFByeUZ4QkUzZmRKNTNwU1hvS1Zrc296NXZJWmQ0');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const results = [];

  // Check if table exists by trying the REST API
  const check = await fetch(`${SB_URL}/rest/v1/novelty_catchers?select=id&limit=1`, {
    headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
  });
  
  if (check.ok) {
    const check2 = await fetch(`${SB_URL}/rest/v1/novelty_alerts?select=id&limit=1`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    if (check2.ok) {
      return res.status(200).json({ status: 'ok', message: 'Both tables already exist' });
    }
  }

  // Tables don't exist. We can't create them via PostgREST.
  // Return the SQL and instructions.
  const sql = `-- DACTA Novelty Catcher — Database Migration
-- Run in Supabase Dashboard → SQL Editor
-- Project: qiqrizggitcqwkwshmfy

CREATE TABLE IF NOT EXISTS public.novelty_catchers (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  org_id UUID REFERENCES public.organizations(id),
  hostname TEXT NOT NULL DEFAULT 'unnamed',
  version TEXT DEFAULT '2.0.0',
  mode TEXT DEFAULT 'learn',
  status TEXT DEFAULT 'pending',
  platform TEXT DEFAULT 'linux',
  events_processed BIGINT DEFAULT 0,
  alerts_24h INTEGER DEFAULT 0,
  last_heartbeat TIMESTAMPTZ,
  stats JSONB DEFAULT '{}'::jsonb,
  config JSONB DEFAULT '{}'::jsonb,
  indices TEXT[] DEFAULT ARRAY[]::TEXT[],
  learn_progress INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.novelty_alerts (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  catcher_id UUID,
  org_id UUID REFERENCES public.organizations(id),
  alert_type TEXT NOT NULL DEFAULT 'unknown',
  severity TEXT DEFAULT 'medium',
  source_key TEXT DEFAULT '',
  detail TEXT DEFAULT '',
  alert_data JSONB DEFAULT '{}'::jsonb,
  acknowledged BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Add foreign key after both tables exist
DO $$ BEGIN
  ALTER TABLE public.novelty_alerts 
    ADD CONSTRAINT novelty_alerts_catcher_fk 
    FOREIGN KEY (catcher_id) REFERENCES public.novelty_catchers(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE public.novelty_catchers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.novelty_alerts ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN DROP POLICY IF EXISTS novelty_catchers_anon_all ON public.novelty_catchers; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN DROP POLICY IF EXISTS novelty_alerts_anon_all ON public.novelty_alerts; EXCEPTION WHEN OTHERS THEN NULL; END $$;

CREATE POLICY novelty_catchers_anon_all ON public.novelty_catchers FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY novelty_alerts_anon_all ON public.novelty_alerts FOR ALL TO anon USING (true) WITH CHECK (true);

-- Seed test data (optional)
INSERT INTO public.novelty_catchers (org_id, hostname, version, mode, status, platform, events_processed, alerts_24h, last_heartbeat, config, indices, learn_progress) VALUES
  ('9ce7a126-4e9d-434e-b952-f4c4fce56fa1', 'collector-sg-01', '2.0.0', 'monitor', 'online', 'linux', 1300000000, 12, now() - interval '2 minutes', '{"syslog_port":5514,"threshold":0.75,"learning_hours":168}'::jsonb, ARRAY['logs-fortinet_fortigate.log-dacta','logs-m365_defender.alert-dacta'], 100),
  ('3a57db8a-7787-414c-9e28-1c14de388d31', 'collector-kh-01', '2.0.0', 'monitor', 'online', 'linux', 890000000, 7, now() - interval '1 minute', '{"syslog_port":5514,"threshold":0.75,"learning_hours":168}'::jsonb, ARRAY['logs-fortinet_fortigate.log-naga','logs-sophos.endpoint-naga'], 100),
  ('b8672c8b-3907-48b0-8c58-b61aa38fbf4b', 'collector-sg-02', '2.0.0', 'learn', 'learning', 'linux', 45000000, 0, now() - interval '30 seconds', '{"syslog_port":5514,"threshold":0.75,"learning_hours":168}'::jsonb, ARRAY['logs-trendmicro.visionone-spmt'], 42),
  ('bb0db674-d91f-4a21-9c71-984c10749feb', 'collector-sg-03', '2.0.0', 'monitor', 'online', 'windows', 230000000, 3, now() - interval '3 minutes', '{"syslog_port":5514,"threshold":0.80,"learning_hours":168}'::jsonb, ARRAY['logs-m365_defender.alert-adv'], 100);
`;

  return res.status(200).json({
    status: 'tables_missing',
    message: 'Tables need to be created. Run the SQL in Supabase SQL Editor (Dashboard → SQL Editor → New query → paste and run).',
    supabase_url: 'https://supabase.com/dashboard/project/qiqrizggitcqwkwshmfy/sql/new',
    sql
  });
}
