// Vercel Serverless Function — OpenCTI GraphQL Proxy
// Proxies OpenCTI GraphQL queries from the frontend, hiding credentials server-side
// Supports: observable lookups (IP, hash, domain), indicator queries, report searches

const _OU = 'aHR0cDovLzYxLjEzLjIxNC4xOTg6ODA4MA=='; // opencti URL
const _OK = 'NjE4OTZjMTQtNWM0OS00NDQ2LTllMDEtYTI4MWRmNTNmY2Qz'; // api token

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const OPENCTI_URL = process.env.OPENCTI_URL || _d(_OU);
  const OPENCTI_TOKEN = process.env.OPENCTI_TOKEN || _d(_OK);

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
    console.error('OpenCTI proxy error:', err);
    return res.status(500).json({ error: err.message });
  }
}
