// Shared auth middleware for Vercel serverless functions
// Validates that the caller has a valid Supabase JWT session token.
// SECURITY: This must be called at the top of every handler that uses
// service-role access or touches privileged data.

const { SUPABASE_URL, SUPABASE_SECRET_KEY } = require('./supabase');

// Allowed origins for CORS — restrict to production + local dev
const ALLOWED_ORIGINS = [
  'https://dacta-siemless.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
];

// Set CORS headers — restrict to known origins instead of wildcard
function setCors(req, res) {
  const origin = req.headers.origin || '';
  // In production, only allow listed origins. If no origin header (e.g. server-to-server), allow.
  if (!origin || ALLOWED_ORIGINS.includes(origin) || process.env.NODE_ENV === 'development') {
    res.setHeader('Access-Control-Allow-Origin', origin || ALLOWED_ORIGINS[0]);
  } else {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0]);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Vary', 'Origin');
}

// Verify the caller's Supabase JWT by calling Supabase auth.getUser()
// Returns the authenticated user object or null if invalid/missing.
async function verifyAuth(req) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) return null;

  // Skip verification for service-role key (server-to-server calls)
  if (token === SUPABASE_SECRET_KEY) return { id: 'service-role', role: 'service_role' };

  try {
    const resp = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${token}`,
      },
    });
    if (!resp.ok) return null;
    const user = await resp.json();
    return user && user.id ? user : null;
  } catch (e) {
    console.error('[Auth] Token verification failed:', e.message);
    return null;
  }
}

// Convenience: verify + reject if unauthenticated (use in handlers)
// Returns user if valid, or sends 401 and returns null.
async function requireAuth(req, res) {
  const user = await verifyAuth(req);
  if (!user) {
    res.status(401).json({ error: 'Unauthorized — valid session token required' });
    return null;
  }
  return user;
}

// For agent/webhook endpoints that use a shared API key instead of JWT
function verifyApiKey(req) {
  const key = req.headers['x-api-key'] || req.query.api_key || '';
  const expected = process.env.SIEMLESS_API_KEY;
  if (!expected) {
    console.error('[Auth] SIEMLESS_API_KEY env var not set — API key auth disabled');
    return false;
  }
  return key === expected;
}

module.exports = { setCors, verifyAuth, requireAuth, verifyApiKey, ALLOWED_ORIGINS };
