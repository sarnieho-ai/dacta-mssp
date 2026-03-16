// Centralized Supabase configuration for all API endpoints
// New API key format (publishable / secret) after key rotation 2026-03-16

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';

// Secret key (replaces old service_role JWT)
// Env var takes priority, fallback for immediate deployment
function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const _sk = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

// Standard headers for PostgREST calls
function sbHeaders() {
  return {
    'apikey': _sk,
    'Authorization': `Bearer ${_sk}`,
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

module.exports = { SUPABASE_URL, sbHeaders, sbFetch, SUPABASE_SECRET_KEY: _sk };
