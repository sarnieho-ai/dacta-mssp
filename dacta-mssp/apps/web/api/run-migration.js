// Temporary migration endpoint — creates the generated_parsers table
// DELETE THIS FILE after migration is complete

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-migration-key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const migKey = req.headers['x-migration-key'];
  if (migKey !== 'dacta-migrate-2026') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY
    || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFpcXJpemdnaXRjcXdrd3NobWZ5Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MjA3OTMyMSwiZXhwIjoyMDg3NjU1MzIxfQ.gCuDiLHH6JOUDLPryFxBE3fdJ53pSXoKVksoz5vIZd4';

  const createSQL = `CREATE TABLE IF NOT EXISTS generated_parsers (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  parser_name text NOT NULL,
  vendor text DEFAULT 'Custom',
  format_type text DEFAULT 'Custom',
  delimiter text DEFAULT 'N/A',
  fields_count integer DEFAULT 0,
  fields_data jsonb DEFAULT '[]'::jsonb,
  regex_pattern text DEFAULT '',
  parsed_sample jsonb DEFAULT '{}'::jsonb,
  notes text DEFAULT '',
  confidence integer DEFAULT 0,
  status text DEFAULT 'Generated',
  org_name text DEFAULT '',
  source_name text DEFAULT '',
  created_at timestamptz DEFAULT now(),
  created_by text DEFAULT 'system'
);
ALTER TABLE generated_parsers ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='generated_parsers' AND policyname='Allow read access') THEN
    CREATE POLICY "Allow read access" ON generated_parsers FOR SELECT USING (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='generated_parsers' AND policyname='Allow insert') THEN
    CREATE POLICY "Allow insert" ON generated_parsers FOR INSERT WITH CHECK (true);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename='generated_parsers' AND policyname='Allow delete') THEN
    CREATE POLICY "Allow delete" ON generated_parsers FOR DELETE USING (true);
  END IF;
END $$;
GRANT ALL ON generated_parsers TO anon, authenticated;`;

  try {
    // Check if table already exists
    const checkResp = await fetch(`${SUPABASE_URL}/rest/v1/generated_parsers?select=id&limit=0`, {
      headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}` }
    });
    if (checkResp.ok) {
      return res.status(200).json({ status: 'exists', message: 'generated_parsers table already exists' });
    }

    const results = {};

    // Attempt 1: Supabase pg/query endpoint
    try {
      const r1 = await fetch(`${SUPABASE_URL}/pg/query`, {
        method: 'POST',
        headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: createSQL })
      });
      results.pg_query = { status: r1.status, body: (await r1.text()).substring(0, 300) };
      if (r1.ok) return res.status(200).json({ status: 'created', method: 'pg/query', detail: results.pg_query });
    } catch (e) { results.pg_query = { error: e.message }; }

    // Attempt 2: Supabase Management API
    try {
      const r2 = await fetch(`https://api.supabase.com/v1/projects/qiqrizggitcqwkwshmfy/database/query`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${SERVICE_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: createSQL })
      });
      results.mgmt_api = { status: r2.status, body: (await r2.text()).substring(0, 300) };
      if (r2.ok) return res.status(200).json({ status: 'created', method: 'mgmt_api', detail: results.mgmt_api });
    } catch (e) { results.mgmt_api = { error: e.message }; }

    // Attempt 3: Try using postgres module if available (Vercel Node.js runtime)
    try {
      const { Client } = require('pg');
      const connStr = process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.SUPABASE_DB_URL || '';
      if (connStr) {
        const client = new Client({ connectionString: connStr, ssl: { rejectUnauthorized: false } });
        await client.connect();
        await client.query(createSQL);
        await client.end();
        return res.status(200).json({ status: 'created', method: 'pg_direct' });
      }
      results.pg_direct = { error: 'No DATABASE_URL env var' };
    } catch (e) { results.pg_direct = { error: e.message }; }

    return res.status(200).json({
      status: 'needs_manual_creation',
      attempts: results,
      message: 'Could not auto-create table. Run the SQL in Supabase Dashboard > SQL Editor.',
      sql: createSQL
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
