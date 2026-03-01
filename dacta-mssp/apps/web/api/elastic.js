// Vercel Serverless Function — Elastic SIEM Proxy
// Proxies Elasticsearch queries from the frontend, hiding credentials server-side
// Supports: search, field_caps, and alert correlation queries

const _EU = 'aHR0cHM6Ly9kYWN0YS1nbG9iYWwuZXMuYXAtc291dGhlYXN0LTEuYXdzLmZvdW5kLmlv'; // elastic URL
const _EK = 'dWtab3Fwd0JPWjFDSVlZQ3pFVkE6bjVyTTk3VS05YnpkQ05sWnRsRmRpQQ=='; // API key

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const ELASTIC_URL = process.env.ELASTIC_URL || _d(_EU);
  const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || _EK;

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
