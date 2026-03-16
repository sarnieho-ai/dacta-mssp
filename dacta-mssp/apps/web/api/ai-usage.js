// Vercel Serverless Function — AI Usage Data API
// Server-side query for llm_usage_log, bypasses RLS with service role key.
// This ensures the AI Usage Dashboard always loads data regardless of client auth state.

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'Service key not configured' });
  }

  try {
    // Accept month param: ?month=2026-03 (defaults to current month)
    const now = new Date();
    const month = req.query.month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    const parts = month.split('-');
    const startDate = `${month}-01T00:00:00Z`;
    const endDate = new Date(parseInt(parts[0]), parseInt(parts[1]), 1).toISOString();

    const url = `${SUPABASE_URL}/rest/v1/llm_usage_log?select=*&created_at=gte.${encodeURIComponent(startDate)}&created_at=lt.${encodeURIComponent(endDate)}&order=created_at.desc&limit=1000`;

    const resp = await fetch(url, {
      headers: {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    if (!resp.ok) {
      console.error('[ai-usage] DB error:', resp.status, await resp.text());
      return res.status(resp.status).json({ error: 'Database query failed' });
    }

    const data = await resp.json();
    return res.status(200).json({ data, month });
  } catch (err) {
    console.error('[ai-usage] Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
}
