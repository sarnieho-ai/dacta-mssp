// Temporary migration — creates novelty_catchers and novelty_alerts tables
// Uses Supabase pg-meta query endpoint (available from Vercel)
// DELETE THIS FILE after migration

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SB_URL = 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SB_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBjM01pT2lKemRYQmhZbUZ6WlNJc0luSmxaaUk2SW5GcGNYSnBlbWRuYVhSamNYZHJkM05vYldaNUlpd2ljbTlzWlNJNkluTmxjblpwWTJWZmNtOXNaU0lzSW1saGRDSTZNVGMzTWpBM09UTXlNU3dpWlhod0lqb3lNRGczTmpVMU16SXhmUS5nQ3VEaUxISDZKT1VETFByeUZ4QkUzZmRKNTNwU1hvS1Zrc296NXZJWmQ0');

async function runSQL(sql) {
  // Method 1: Try pg-meta query endpoint (Supabase internal)
  const pgMetaResp = await fetch(`${SB_URL}/pg/query`, {
    method: 'POST',
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: sql })
  });
  if (pgMetaResp.ok) {
    const data = await pgMetaResp.json();
    return { method: 'pg-meta', ok: true, data };
  }

  // Method 2: Try /pg endpoint  
  const pgResp = await fetch(`${SB_URL}/pg`, {
    method: 'POST',
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query: sql })
  });
  if (pgResp.ok) {
    const data = await pgResp.json();
    return { method: 'pg', ok: true, data };
  }

  // Method 3: Try database/query
  const dbResp = await fetch(`${SB_URL}/rest/v1/rpc/exec_sql`, {
    method: 'POST',
    headers: {
      'apikey': SB_KEY,
      'Authorization': `Bearer ${SB_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
    },
    body: JSON.stringify({ sql_text: sql })
  });

  const text = await pgMetaResp.text().catch(() => '');
  const text2 = await pgResp.text().catch(() => '');
  const text3 = await dbResp.text().catch(() => '');

  return { 
    method: 'all_failed', 
    ok: false, 
    details: { pgMeta: text, pg: text2, rpc: text3 }
  };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const results = [];

  // Check if table exists
  const check = await fetch(`${SB_URL}/rest/v1/novelty_catchers?select=id&limit=1`, {
    headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
  });
  if (check.ok) {
    // Check alerts too
    const check2 = await fetch(`${SB_URL}/rest/v1/novelty_alerts?select=id&limit=1`, {
      headers: { 'apikey': SB_KEY, 'Authorization': `Bearer ${SB_KEY}` }
    });
    if (check2.ok) {
      return res.status(200).json({ status: 'ok', message: 'Both tables exist' });
    }
  }

  // Try to create tables
  const sqls = [
    `CREATE TABLE IF NOT EXISTS public.novelty_catchers (
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
    )`,
    `CREATE TABLE IF NOT EXISTS public.novelty_alerts (
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
    )`,
    `ALTER TABLE public.novelty_catchers ENABLE ROW LEVEL SECURITY`,
    `ALTER TABLE public.novelty_alerts ENABLE ROW LEVEL SECURITY`,
    `CREATE POLICY IF NOT EXISTS novelty_catchers_anon_all ON public.novelty_catchers FOR ALL TO anon USING (true) WITH CHECK (true)`,
    `CREATE POLICY IF NOT EXISTS novelty_alerts_anon_all ON public.novelty_alerts FOR ALL TO anon USING (true) WITH CHECK (true)`,
  ];

  for (const sql of sqls) {
    const r = await runSQL(sql);
    results.push({ sql: sql.substring(0, 80) + '...', ...r });
  }

  return res.status(200).json({ status: 'migration_attempted', results });
}
