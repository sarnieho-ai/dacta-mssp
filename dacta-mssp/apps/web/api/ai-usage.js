// Vercel Serverless Function — AI Usage Data API
// Server-side query for llm_usage_log, bypasses RLS with service role key.
// This ensures the AI Usage Dashboard always loads data regardless of client auth state.

const { SUPABASE_URL, sbHeaders, sbFetch, SUPABASE_SECRET_KEY } = require('./lib/supabase');
const { setCors, requireAuth } = require('./lib/auth');

export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // SECURITY: Require authenticated session
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent


  if (!SUPABASE_SECRET_KEY) {
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
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
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
