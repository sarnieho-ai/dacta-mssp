// Vercel Serverless Function — Elastic SIEM Proxy
// Proxies Elasticsearch queries from the frontend, hiding credentials server-side
// All credentials read from Vercel Environment Variables — never hardcode secrets
// Required env vars: ELASTIC_URL, ELASTIC_API_KEY

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

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

    const fetchOpts = { method, headers };
    if (fetchBody) fetchOpts.body = fetchBody;

    const response = await fetch(url, fetchOpts);
    const data = await response.json();

    return res.status(response.status).json(data);
  } catch (err) {
    console.error('Elastic proxy error:', err);
    return res.status(500).json({ error: err.message });
  }
}
