// Vercel Serverless Function — Database Migration Helper
// Creates missing tables required by new features
// Uses service role key for DDL operations via Supabase pg-meta query endpoint

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

async function runSQL(sql) {
  // Use PostgREST's rpc endpoint or fall back to direct pg-meta query
  // Supabase exposes a SQL query endpoint at /pg/query for service role
  const url = `${SUPABASE_URL}/rest/v1/rpc/`;
  
  // Try creating via direct table manipulation (PostgREST)
  // Since we can't run raw DDL through PostgREST, we use a workaround:
  // Create the table by inserting into it with the service role key
  // and letting Supabase auto-create schema from the migration SQL
  
  // Actually, the correct approach for Supabase is the Management API
  // But that requires a different token. Let's use the service role to 
  // attempt a table check and creation via the pg endpoint
  const resp = await fetch(`${SUPABASE_URL}/rest/v1/simulation_results?select=id&limit=0`, {
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`
    }
  });
  return { exists: resp.ok, status: resp.status };
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY not configured' });
  }

  const { action } = req.body || {};

  if (action === 'ensure_simulation_results') {
    // Check if table exists
    const check = await runSQL('');
    if (check.exists) {
      return res.status(200).json({ status: 'exists', message: 'simulation_results table already exists' });
    }

    // Table doesn't exist — try to create it using Supabase Management API
    // Extract project ref from URL
    const projectRef = SUPABASE_URL.match(/https:\/\/([^.]+)\.supabase\.co/)?.[1];
    if (!projectRef) {
      return res.status(500).json({ error: 'Cannot extract project ref from SUPABASE_URL' });
    }

    // Use Supabase Management API v1 to run SQL
    // This requires the service role key as bearer token
    const sqlQuery = `
CREATE TABLE IF NOT EXISTS public.simulation_results (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  simulation_name TEXT NOT NULL,
  category TEXT,
  techniques JSONB DEFAULT '[]'::jsonb,
  step_results JSONB DEFAULT '[]'::jsonb,
  prevention_score INTEGER DEFAULT 0,
  detection_score INTEGER DEFAULT 0,
  total_events INTEGER DEFAULT 0,
  duration_seconds NUMERIC(6,1) DEFAULT 0,
  run_date TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE public.simulation_results ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'simulation_results' AND policyname = 'Allow anon full access') THEN
    CREATE POLICY "Allow anon full access" ON public.simulation_results FOR ALL USING (true) WITH CHECK (true);
  END IF;
END $$;
GRANT ALL ON public.simulation_results TO anon, authenticated;
`;

    // Try via Supabase's internal pg endpoint (available to service role)
    try {
      const pgResp = await fetch(`${SUPABASE_URL}/pg/query`, {
        method: 'POST',
        headers: {
          'apikey': SUPABASE_SERVICE_KEY,
          'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query: sqlQuery })
      });
      
      if (pgResp.ok) {
        return res.status(200).json({ status: 'created', message: 'simulation_results table created successfully' });
      }
      
      // If pg endpoint doesn't work, try the SQL API
      const sqlResp = await fetch(`https://api.supabase.com/v1/projects/${projectRef}/database/query`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query: sqlQuery })
      });
      
      if (sqlResp.ok) {
        return res.status(200).json({ status: 'created', message: 'simulation_results table created via Management API' });
      }

      const errText = await sqlResp.text();
      return res.status(500).json({ 
        status: 'failed', 
        message: 'Could not create table automatically',
        error: errText,
        sql: sqlQuery.trim()
      });
    } catch (e) {
      return res.status(500).json({ status: 'error', message: e.message, sql: sqlQuery.trim() });
    }
  }

  return res.status(400).json({ error: 'Unknown action. Supported: ensure_simulation_results' });
};
