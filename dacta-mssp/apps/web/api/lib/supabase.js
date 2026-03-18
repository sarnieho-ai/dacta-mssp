// Centralized Supabase configuration for all API endpoints
// SECURITY: All credentials must come from environment variables (Vercel dashboard).
// No fallback secrets in code — missing env vars will cause a clear startup error.

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;

if (!SUPABASE_URL) {
  console.error('[SECURITY] SUPABASE_URL env var is not set. All API calls will fail.');
}
if (!SUPABASE_SECRET_KEY) {
  console.error('[SECURITY] SUPABASE_SERVICE_ROLE_KEY env var is not set. All API calls will fail.');
}

// Standard headers for PostgREST calls
function sbHeaders() {
  return {
    'apikey': SUPABASE_SECRET_KEY,
    'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };
}

// Convenience: fetch from Supabase REST API
async function sbFetch(path, opts = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  const res = await fetch(url, {
    ...opts,
    headers: { ...sbHeaders(), ...(opts.headers || {}) }
  });
  return res;
}

module.exports = { SUPABASE_URL, sbHeaders, sbFetch, SUPABASE_SECRET_KEY };
