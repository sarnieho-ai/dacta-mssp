// Vercel Serverless Function — Elastic SIEM Proxy
// Proxies Elasticsearch queries from the frontend, hiding credentials server-side
// All credentials read from Vercel Environment Variables — never hardcode secrets
// Required env vars: ELASTIC_URL, ELASTIC_API_KEY
// Optional env vars: ELASTIC_SKIP_SSL_VERIFY=true (for self-signed certs)

import https from 'https';

// Custom fetch options for SSL certificate handling
const { setCors, requireAuth } = require('./lib/auth');
function getFetchOptions(baseOpts) {
  // If ELASTIC_SKIP_SSL_VERIFY is set, use a custom agent that skips SSL verification
  if (process.env.ELASTIC_SKIP_SSL_VERIFY === 'true') {
    const agent = new https.Agent({ rejectUnauthorized: false });
    return { ...baseOpts, agent };
  }
  return baseOpts;
}

export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // SECURITY: Require authenticated session
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent


  // Health check: GET without params returns service status
  if (req.method === 'GET' && (!req.query || !req.query.action)) {
    return res.status(200).json({ status: 'ok', service: 'elastic-proxy', timestamp: new Date().toISOString() });
  }

  const ELASTIC_URL = process.env.ELASTIC_URL || '';
  const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || '';

  if (!ELASTIC_URL || !ELASTIC_API_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: ELASTIC_URL and ELASTIC_API_KEY environment variables are required' });
  }

  try {
    const { action, index, body } = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

    if (!action) return res.status(400).json({ error: 'Missing action parameter' });

    let url, method = 'POST', fetchBody;

    switch (action) {
      case 'search': {
        // Standard search — index required
        const idx = index || 'logs-*';
        url = `${ELASTIC_URL}/${idx}/_search`;
        fetchBody = JSON.stringify(body || { size: 10 });
        break;
      }
      case 'msearch': {
        // Multi-search — body is array of header+body pairs
        const idx = index || 'logs-*';
        url = `${ELASTIC_URL}/${idx}/_msearch`;
        // msearch uses ndjson format
        if (Array.isArray(body)) {
          fetchBody = body.map(line => JSON.stringify(line)).join('\n') + '\n';
        } else {
          fetchBody = body;
        }
        break;
      }
      case 'field_caps': {
        const idx = index || 'logs-*';
        url = `${ELASTIC_URL}/${idx}/_field_caps?fields=*`;
        method = 'GET';
        fetchBody = undefined;
        break;
      }
      case 'count': {
        const idx = index || 'logs-*';
        url = `${ELASTIC_URL}/${idx}/_count`;
        fetchBody = JSON.stringify(body || { query: { match_all: {} } });
        break;
      }
      case 'cluster_health': {
        url = `${ELASTIC_URL}/_cluster/health`;
        method = 'GET';
        fetchBody = undefined;
        break;
      }
      default:
        return res.status(400).json({ error: 'Unknown action: ' + action });
    }

    const headers = {
      'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
      'Content-Type': action === 'msearch' ? 'application/x-ndjson' : 'application/json'
    };

    const fetchOpts = getFetchOptions({ method, headers });
    if (fetchBody) fetchOpts.body = fetchBody;

    const response = await fetch(url, fetchOpts);
    const data = await response.json();

    return res.status(response.status).json(data);
  } catch (err) {
    console.error('Elastic proxy error:', err);
    // Provide actionable error for SSL cert issues
    if (err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'SELF_SIGNED_CERT_IN_CHAIN' || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || (err.message && err.message.includes('certificate'))) {
      return res.status(502).json({ error: 'SSL certificate error connecting to Elastic SIEM. If using a self-signed certificate, set ELASTIC_SKIP_SSL_VERIFY=true in environment variables.', code: err.code });
    }
    return res.status(500).json({ error: err.message });
  }
}
