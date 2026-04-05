// Vercel Serverless Function — DACTA TIP GraphQL Proxy
// Proxies DACTA TIP GraphQL queries from the frontend, hiding credentials server-side
// Supports: observable lookups (IP, hash, domain), indicator queries, report searches


const { setCors, requireAuth } = require('./lib/auth');
const { OPENCTI_URL, OPENCTI_TOKEN } = require('./lib/config');

export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Health check: GET without params returns service status
  if (req.method === 'GET' && (!req.body || !req.body.query)) {
    return res.status(200).json({ status: 'ok', service: 'dacta-tip-proxy', configured: !!OPENCTI_URL, timestamp: new Date().toISOString() });
  }

  // SECURITY: Require authenticated session for TIP queries
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent

  if (!OPENCTI_URL) {
    return res.status(503).json({ error: 'DACTA TIP service not configured' });
  }

  try {
    const { query, variables } = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    if (!query) return res.status(400).json({ error: 'Missing GraphQL query' });

    const response = await fetch(`${OPENCTI_URL}/graphql`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENCTI_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query, variables: variables || {} })
    });

    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (err) {
    console.error('DACTA TIP proxy error:', err);
    return res.status(500).json({ error: err.message });
  }
}
