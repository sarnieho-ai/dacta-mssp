// Vercel Serverless Function — Heimdal Security API Proxy
// Provides endpoint monitoring, threat detections, XTP, TAC alerts, and DNS security data
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   HEIMDAL_API_KEY       — Personal API key (Bearer token)
//   HEIMDAL_CUSTOMER_ID   — Customer ID for API requests
//   HEIMDAL_BASE_URL      — e.g. https://dashboard.heimdalsecurity.com/api/heimdalapi/2.0
//
// Per-org credentials: read from org_connectors.credentials_ref via Supabase
//
// Supported actions:
//   get_endpoints         — List active client endpoints (activeclients)
//   get_detections        — Vigilance (EDR) detections
//   get_xtp_detections    — XTP (eXtended Threat Protection) detections
//   get_tac_alerts        — TAC (Threat-hunting & Action Center) alerts
//   get_dns_security      — DarkLayer Guard DNS security events
//   get_network_threats   — Threat Prevention Network (TPN) events
//   get_vectorn           — VectorN Detection matches (behavioral AI)
//   get_patching          — Patch & Asset Management status
//   ping                  — Health check
//
// Rate limit: 5 requests/minute/IP/endpoint — handle 429 gracefully


const HM_BASE = process.env.HEIMDAL_BASE_URL || 'https://dashboard.heimdalsecurity.com/api/heimdalapi/2.0';
const HM_API_KEY = process.env.HEIMDAL_API_KEY || '';
const HM_CUSTOMER_ID = process.env.HEIMDAL_CUSTOMER_ID || '';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// ── Per-org credential resolution (fetch-based, no npm deps) ──
async function getOrgCredentials(orgId) {
  if (!orgId || !SUPABASE_SERVICE_KEY) return null;
  try {
    const url = `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&vendor=ilike.*heimdal*&is_enabled=eq.true&select=api_endpoint,auth_type,credentials_ref&limit=1`;
    const resp = await fetch(url, {
      headers: {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Accept': 'application/json'
      }
    });
    if (!resp.ok) return null;
    const rows = await resp.json();
    return rows && rows.length > 0 ? rows[0] : null;
  } catch { return null; }
}

async function resolveAuth(orgId) {
  const orgCreds = await getOrgCredentials(orgId);
  if (orgCreds && orgCreds.credentials_ref) {
    const creds = typeof orgCreds.credentials_ref === 'string'
      ? JSON.parse(orgCreds.credentials_ref) : orgCreds.credentials_ref;
    return {
      baseUrl: orgCreds.api_endpoint || HM_BASE,
      apiKey: creds.api_key || creds.token || HM_API_KEY,
      customerId: creds.customer_id || HM_CUSTOMER_ID
    };
  }
  return { baseUrl: HM_BASE, apiKey: HM_API_KEY, customerId: HM_CUSTOMER_ID };
}

// ── HTTP helper with rate limit handling ──
async function hmGet(baseUrl, apiKey, customerId, endpoint, params = {}) {
  const allParams = { customerId, ...params };
  const qs = new URLSearchParams(allParams).toString();
  const url = `${baseUrl}/${endpoint}${qs ? '?' + qs : ''}`;

  const resp = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Accept': 'application/json'
    }
  });

  // Handle rate limiting (5 req/min/IP/endpoint)
  if (resp.status === 429) {
    const retryAfter = resp.headers.get('Retry-After') || '60';
    throw new Error(`Rate limited — retry after ${retryAfter}s. Heimdal allows 5 requests/minute per endpoint.`);
  }

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Heimdal GET /${endpoint} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Action handlers ──

async function getEndpoints(auth, params = {}) {
  // Active Clients — list all registered endpoints
  const queryParams = {};
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  if (params.hostname) queryParams.hostname = params.hostname;
  if (params.group_name) queryParams.groupName = params.group_name;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'activeclients', queryParams);
}

async function getDetections(auth, params = {}) {
  // Vigilance (EDR) detections
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.severity) queryParams.severity = params.severity;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'vigilancedetections', queryParams);
}

async function getXTPDetections(auth, params = {}) {
  // XTP (eXtended Threat Protection) detections — advanced threat analysis
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'xtp/getDetections', queryParams);
}

async function getTACAlerts(auth, params = {}) {
  // TAC (Threat-hunting & Action Center) alerts
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.status) queryParams.status = params.status;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'tacAlerts', queryParams);
}

async function getDNSSecurity(auth, params = {}) {
  // DarkLayer Guard — DNS-based threat prevention
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'darklayerguard', queryParams);
}

async function getNetworkThreats(auth, params = {}) {
  // Threat Prevention Network (TPN) — network-level threat events
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'threatPreventionNetwork', queryParams);
}

async function getVectorN(auth, params = {}) {
  // VectorN Detection — behavioral AI-based anomaly detection matches
  const queryParams = {};
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'vectorn/getEndpointMatches', queryParams);
}

async function getPatching(auth, params = {}) {
  // Patch & Asset Management — software inventory and patching status
  const queryParams = {};
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.page) queryParams.page = params.page;
  if (params.per_page) queryParams.perPage = params.per_page;
  return hmGet(auth.baseUrl, auth.apiKey, auth.customerId, 'patchmanagement/software', queryParams);
}

// ── Main handler ──

export async function heimdalHandler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = req.method === 'POST'
    ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) || {}
    : {};
  const action = req.query.action || body.action;
  const orgId = body.org_id || req.query.org_id;

  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  try {
    const auth = await resolveAuth(orgId);
    if (!auth.apiKey) {
      return res.status(503).json({ error: 'Heimdal credentials not configured', configured: false });
    }

    let result;

    switch (action) {
      case 'get_endpoints':
        result = await getEndpoints(auth, body);
        break;

      case 'get_detections':
        result = await getDetections(auth, body);
        break;

      case 'get_xtp_detections':
        result = await getXTPDetections(auth, body);
        break;

      case 'get_tac_alerts':
        result = await getTACAlerts(auth, body);
        break;

      case 'get_dns_security':
        result = await getDNSSecurity(auth, body);
        break;

      case 'get_network_threats':
        result = await getNetworkThreats(auth, body);
        break;

      case 'get_vectorn':
        result = await getVectorN(auth, body);
        break;

      case 'get_patching':
        result = await getPatching(auth, body);
        break;

      case 'ping': {
        try {
          const pingResult = await getEndpoints(auth, { per_page: 1 });
          const endpointCount = Array.isArray(pingResult) ? pingResult.length
            : (pingResult.data ? pingResult.data.length : 0);
          result = {
            status: 'ok',
            base_url: auth.baseUrl,
            authenticated: true,
            customer_id: auth.customerId,
            endpoints_found: endpointCount
          };
        } catch (e) {
          result = { status: 'error', base_url: auth.baseUrl, authenticated: false, error: e.message };
        }
        break;
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }

    return res.status(200).json(result);

  } catch (err) {
    console.error('[Heimdal]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
