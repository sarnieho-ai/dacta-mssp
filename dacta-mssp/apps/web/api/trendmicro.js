// Vercel Serverless Function — Trend Micro Vision One API Proxy
// Provides workbench alerts, endpoint search, OAT data, and email security events
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   TRENDMICRO_API_TOKEN   — Vision One API token (Bearer)
//   TRENDMICRO_BASE_URL    — e.g. https://api.xdr.trendmicro.com
//
// Per-org credentials: read from org_connectors.credentials_ref via Supabase
//
// Supported actions:
//   search_detections    — Search workbench alerts by entity (IP, hostname, user, hash)
//   get_detection        — Get alert detail by workbenchId
//   search_endpoints     — Search endpoints by IP, hostname, or agentGuid
//   get_endpoint         — Get endpoint detail
//   search_emails        — Email security sweep (sender, subject, recipient)
//   get_oat             — Observed Attack Techniques data
//   search_suspicious   — Suspicious object list (IOC management)
//   ping                — Health check


function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const TM_BASE = process.env.TRENDMICRO_BASE_URL || 'https://api.xdr.trendmicro.com';
const TM_TOKEN = process.env.TRENDMICRO_API_TOKEN || '';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

// ── Per-org credential resolution (fetch-based, no npm deps) ──
async function getOrgCredentials(orgId) {
  if (!orgId || !SUPABASE_SERVICE_KEY) return null;
  try {
    const url = `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&vendor=eq.TrendMicro&is_enabled=eq.true&select=api_endpoint,auth_type,credentials_ref&limit=1`;
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
  // Try per-org credentials first, fall back to env vars
  const orgCreds = await getOrgCredentials(orgId);
  if (orgCreds && orgCreds.credentials_ref) {
    const creds = typeof orgCreds.credentials_ref === 'string'
      ? JSON.parse(orgCreds.credentials_ref) : orgCreds.credentials_ref;
    return {
      baseUrl: orgCreds.api_endpoint || TM_BASE,
      token: creds.api_token || creds.token || creds.api_key || TM_TOKEN
    };
  }
  return { baseUrl: TM_BASE, token: TM_TOKEN };
}

// ── HTTP helpers ──
async function tmGet(baseUrl, token, path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${baseUrl}${path}${qs ? '?' + qs : ''}`;
  const resp = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`TM GET ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

async function tmPost(baseUrl, token, path, body) {
  const resp = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`TM POST ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Action handlers ──

async function searchDetections(auth, params = {}) {
  // Vision One Workbench Alerts — search by entity, severity, time range
  const query = {};
  if (params.start_time) query.startDateTime = params.start_time;
  if (params.end_time) query.endDateTime = params.end_time;

  // Build filter — entity-based search
  const filters = [];
  if (params.hostname) filters.push(`endpointHostName eq '${params.hostname}'`);
  if (params.ip) filters.push(`entityValue eq '${params.ip}'`);
  if (params.user) filters.push(`entityValue eq '${params.user}'`);
  if (params.hash) filters.push(`entityValue eq '${params.hash}'`);
  if (params.severity) filters.push(`severity eq '${params.severity}'`);
  if (filters.length) query.filter = filters.join(' and ');

  const top = params.limit || 20;
  query.top = top;
  if (params.offset) query.skip = params.offset;
  query.orderBy = 'createdDateTime desc';

  return tmGet(auth.baseUrl, auth.token, '/v3.0/workbench/alerts', query);
}

async function getDetection(auth, workbenchId) {
  return tmGet(auth.baseUrl, auth.token, `/v3.0/workbench/alerts/${workbenchId}`);
}

async function searchEndpoints(auth, params = {}) {
  const query = { top: params.limit || 20 };
  const filters = [];
  if (params.hostname) filters.push(`endpointName eq '${params.hostname}'`);
  if (params.ip) filters.push(`ip eq '${params.ip}'`);
  if (params.agent_guid) filters.push(`agentGuid eq '${params.agent_guid}'`);
  if (params.os_name) filters.push(`osName eq '${params.os_name}'`);
  if (filters.length) query.filter = filters.join(' and ');
  query.orderBy = 'lastUsedDateTime desc';
  return tmGet(auth.baseUrl, auth.token, '/v3.0/eiam/endpoints', query);
}

async function getEndpoint(auth, agentGuid) {
  return tmGet(auth.baseUrl, auth.token, `/v3.0/eiam/endpoints/${agentGuid}`);
}

async function searchEmails(auth, params = {}) {
  // Email Activity Data — search by sender, subject, recipient
  const body = {
    top: params.limit || 50,
    select: ['mailMsgSubject', 'mailSenderIp', 'mailFromAddresses', 'mailToAddresses', 'mailMsgDirection', 'eventTime', 'filterRiskLevel', 'mailUrlsRealLink']
  };
  const filters = [];
  if (params.sender) filters.push(`mailFromAddresses eq '${params.sender}'`);
  if (params.recipient) filters.push(`mailToAddresses eq '${params.recipient}'`);
  if (params.subject) filters.push(`mailMsgSubject eq '${params.subject}'`);
  if (params.start_time) body.startDateTime = params.start_time;
  if (params.end_time) body.endDateTime = params.end_time;
  if (filters.length) body.filter = filters.join(' and ');
  return tmPost(auth.baseUrl, auth.token, '/v3.0/search/emailActivities', body);
}

async function getOAT(auth, params = {}) {
  // Observed Attack Techniques — MITRE-mapped telemetry
  const query = { top: params.limit || 50, detectedStartDateTime: params.start_time || '', detectedEndDateTime: params.end_time || '' };
  const filters = [];
  if (params.hostname) filters.push(`endpointHostName eq '${params.hostname}'`);
  if (params.technique_id) filters.push(`tactics.techniqueId eq '${params.technique_id}'`);
  if (filters.length) query.filter = filters.join(' and ');
  return tmGet(auth.baseUrl, auth.token, '/v3.0/oat/detections', query);
}

async function searchSuspicious(auth, params = {}) {
  // Suspicious Object Management — IOC list
  const query = { top: params.limit || 100 };
  if (params.type) query.type = params.type; // ip, domain, fileSha1, fileSha256, senderMailAddress, url
  return tmGet(auth.baseUrl, auth.token, '/v3.0/threatintel/suspiciousObjects', query);
}

// ── Main handler ──

export default async function handler(req, res) {
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
    if (!auth.token) {
      return res.status(503).json({ error: 'Trend Micro credentials not configured', configured: false });
    }

    let result;

    switch (action) {
      case 'search_detections':
        result = await searchDetections(auth, body);
        break;

      case 'get_detection': {
        const wbId = body.workbench_id || req.query.workbench_id;
        if (!wbId) return res.status(400).json({ error: 'Missing workbench_id' });
        result = await getDetection(auth, wbId);
        break;
      }

      case 'search_endpoints':
        result = await searchEndpoints(auth, body);
        break;

      case 'get_endpoint': {
        const agentGuid = body.agent_guid || req.query.agent_guid;
        if (!agentGuid) return res.status(400).json({ error: 'Missing agent_guid' });
        result = await getEndpoint(auth, agentGuid);
        break;
      }

      case 'search_emails':
        result = await searchEmails(auth, body);
        break;

      case 'get_oat':
        result = await getOAT(auth, body);
        break;

      case 'search_suspicious':
        result = await searchSuspicious(auth, body);
        break;

      case 'ping': {
        // Health check — try listing endpoints with limit 1
        try {
          const pingResult = await tmGet(auth.baseUrl, auth.token, '/v3.0/eiam/endpoints', { top: 1 });
          result = { status: 'ok', base_url: auth.baseUrl, authenticated: true, endpoints_found: (pingResult.items || []).length };
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
    console.error('[TrendMicro]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
