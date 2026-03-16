// Temporary migration endpoint — creates the generated_parsers table
// Uses the Supabase database URL (direct connection) to run DDL
// DELETE THIS FILE after migration is complete

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-migration-key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  // Simple protection — require a header
  const migKey = req.headers['x-migration-key'];
  if (migKey !== 'dacta-migrate-2026') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Use Supabase connection string
  // Supabase exposes a direct DB URL that's accessible from Vercel
  const DATABASE_URL = process.env.DATABASE_URL 
    || process.env.SUPABASE_DB_URL
    || process.env.POSTGRES_URL
    || '';

  if (!DATABASE_URL) {
    // Fallback: try to construct from SUPABASE_URL
    const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
    const projectRef = SUPABASE_URL.match(/https:\/\/([^.]+)\.supabase\.co/)?.[1];
    const dbPassword = process.env.SUPABASE_DB_PASSWORD || '';
    
    if (!dbPassword) {
      return res.status(500).json({ 
        error: 'No DATABASE_URL or SUPABASE_DB_PASSWORD configured in Vercel env vars',
        hint: 'Set DATABASE_URL in Vercel to your Supabase direct connection string, or set SUPABASE_DB_PASSWORD',
        alternative: 'Run the SQL manually in the Supabase dashboard SQL Editor'
      });
    }
  }

  // Since we may not have direct DB access, let's try an alternative:
  // Use the Supabase service role to create via PostgREST insert
  // (won't work for DDL, but let's check if table exists first)
  const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
  const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

  if (!SERVICE_KEY) {
    return res.status(500).json({ error: 'SUPABASE_SERVICE_ROLE_KEY not set' });
  }

  // Check if table already exists
  try {
    const checkResp = await fetch(`${SUPABASE_URL}/rest/v1/generated_parsers?select=id&limit=0`, {
      headers: {
        'apikey': SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`
      }
    });

    if (checkResp.ok) {
      return res.status(200).json({ status: 'exists', message: 'generated_parsers table already exists' });
    }

    // Table doesn't exist — provide SQL for manual execution
    const sql = `CREATE TABLE IF NOT EXISTS generated_parsers (
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
CREATE POLICY "Allow read access" ON generated_parsers FOR SELECT USING (true);
CREATE POLICY "Allow insert" ON generated_parsers FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow delete" ON generated_parsers FOR DELETE USING (true);
GRANT ALL ON generated_parsers TO anon, authenticated;`;

    return res.status(200).json({ 
      status: 'needs_creation',
      message: 'Table does not exist. Please run the SQL below in Supabase Dashboard > SQL Editor.',
      sql: sql
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
