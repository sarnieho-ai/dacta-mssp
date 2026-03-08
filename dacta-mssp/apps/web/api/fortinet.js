// Vercel Serverless Function — Fortinet FortiGate / FortiAnalyzer API Proxy
// Provides firewall log queries, threat events, and system monitoring
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   FORTINET_API_KEY    — FortiGate/FortiAnalyzer API key
//   FORTINET_BASE_URL   — e.g. https://fortianalyzer.example.com
//
// Per-org credentials: read from org_connectors.credentials_ref via Supabase
//
// Supported actions:
//   search_logs          — FortiAnalyzer log search (ADOM-based)
//   get_threat_events    — IPS/AV/WAF threat events
//   get_traffic_logs     — Firewall traffic logs (allow/deny/drop)
//   get_url_filter       — Web filter / URL filtering events
//   get_system_status    — System status and health
//   search_events        — FortiGate event log search
//   get_vpn_events       — VPN connection events
//   ping                 — Health check

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const FN_BASE = process.env.FORTINET_BASE_URL || '';
const FN_API_KEY = process.env.FORTINET_API_KEY || '';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// ── Per-org credential resolution ──
async function getOrgCredentials(orgId) {
  if (!orgId || !SUPABASE_SERVICE_KEY) return null;
  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    const { data } = await sb.from('org_connectors')
      .select('api_endpoint, auth_type, credentials_ref')
      .eq('org_id', orgId)
      .ilike('vendor', '%fortinet%')
      .eq('is_enabled', true)
      .limit(1)
      .single();
    return data || null;
  } catch { return null; }
}

async function resolveAuth(orgId) {
  const orgCreds = await getOrgCredentials(orgId);
  if (orgCreds && orgCreds.credentials_ref) {
    const creds = typeof orgCreds.credentials_ref === 'string'
      ? JSON.parse(orgCreds.credentials_ref) : orgCreds.credentials_ref;
    return {
      baseUrl: orgCreds.api_endpoint || FN_BASE,
      apiKey: creds.api_key || creds.token || FN_API_KEY,
      authType: orgCreds.auth_type || 'api_key',
      username: creds.username || '',
      password: creds.password || '',
      adom: creds.adom || 'root'
    };
  }
  return { baseUrl: FN_BASE, apiKey: FN_API_KEY, authType: 'api_key', adom: 'root' };
}

// ── HTTP helpers ──
// FortiGate uses query-string access_token or session-based auth
// FortiAnalyzer uses JSON-RPC

async function fnRestGet(auth, path, params = {}) {
  const allParams = { access_token: auth.apiKey, ...params };
  const qs = new URLSearchParams(allParams).toString();
  const url = `${auth.baseUrl}${path}?${qs}`;
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json' }
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Fortinet GET ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// FortiAnalyzer JSON-RPC method
let _fazSession = null;
async function fazLogin(auth) {
  if (_fazSession) return _fazSession;
  const resp = await fetch(`${auth.baseUrl}/jsonrpc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'exec',
      params: [{ url: '/sys/login/user', data: { user: auth.username, passwd: auth.password } }],
      id: 1
    })
  });
  const data = await resp.json();
  if (data.result && data.result[0] && data.result[0].status && data.result[0].status.code === 0) {
    _fazSession = data.session;
    return _fazSession;
  }
  throw new Error('FortiAnalyzer login failed: ' + JSON.stringify(data));
}

async function fazQuery(auth, method, params) {
  // For FortiAnalyzer, we need a session
  const session = auth.username ? await fazLogin(auth) : null;
  const body = { method, params, id: Date.now(), session };
  const resp = await fetch(`${auth.baseUrl}/jsonrpc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`FAZ ${method} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Unified query — auto-detect FortiGate REST vs FortiAnalyzer JSON-RPC ──
async function isFortiAnalyzer(auth) {
  // If username is present, assume FortiAnalyzer (JSON-RPC); otherwise FortiGate REST
  return !!(auth.username && auth.password);
}

// ── Action handlers ──

async function searchLogs(auth, params = {}) {
  const isFAZ = await isFortiAnalyzer(auth);
  if (isFAZ) {
    // FortiAnalyzer: SQL-like log query via JSON-RPC
    const logtype = params.logtype || 'traffic'; // traffic, threat, event, webfilter, app-ctrl
    const filter = params.filter || '';
    const limit = params.limit || 50;
    const fazParams = [{
      url: `/logview/adom/${auth.adom}/logfiles/data`,
      apiver: 3,
      limit,
      logtype,
      filter
    }];
    return fazQuery(auth, 'get', fazParams);
  } else {
    // FortiGate REST: /api/v2/log/{type}/{subtype}
    const logType = params.logtype || 'disk';
    const subType = params.subtype || 'traffic';
    const queryParams = {};
    if (params.filter) queryParams.filter = params.filter;
    if (params.rows) queryParams.rows = params.rows;
    else queryParams.rows = params.limit || 50;
    if (params.start) queryParams.start = params.start;
    if (params.serial_no) queryParams.serial_no = params.serial_no;
    return fnRestGet(auth, `/api/v2/log/${logType}/${subType}`, queryParams);
  }
}

async function getThreatEvents(auth, params = {}) {
  // IPS, AV, and WAF threat events
  return searchLogs(auth, { ...params, logtype: 'threat', subtype: 'ips' });
}

async function getTrafficLogs(auth, params = {}) {
  // Standard firewall traffic (allow/deny/drop)
  return searchLogs(auth, { ...params, logtype: 'disk', subtype: 'forward' });
}

async function getURLFilter(auth, params = {}) {
  // Web filter / URL filtering events
  return searchLogs(auth, { ...params, logtype: 'disk', subtype: 'webfilter' });
}

async function getSystemStatus(auth) {
  return fnRestGet(auth, '/api/v2/monitor/system/status');
}

async function searchEvents(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: 'disk', subtype: 'event' });
}

async function getVPNEvents(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: 'disk', subtype: 'vpn' });
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
    if (!auth.baseUrl || (!auth.apiKey && !auth.username)) {
      return res.status(503).json({ error: 'Fortinet credentials not configured', configured: false });
    }

    let result;

    switch (action) {
      case 'search_logs':
        result = await searchLogs(auth, body);
        break;

      case 'get_threat_events':
        result = await getThreatEvents(auth, body);
        break;

      case 'get_traffic_logs':
        result = await getTrafficLogs(auth, body);
        break;

      case 'get_url_filter':
        result = await getURLFilter(auth, body);
        break;

      case 'get_system_status':
        result = await getSystemStatus(auth);
        break;

      case 'search_events':
        result = await searchEvents(auth, body);
        break;

      case 'get_vpn_events':
        result = await getVPNEvents(auth, body);
        break;

      case 'ping': {
        try {
          const isFAZ = await isFortiAnalyzer(auth);
          if (isFAZ) {
            await fazLogin(auth);
            result = { status: 'ok', type: 'FortiAnalyzer', base_url: auth.baseUrl, authenticated: true, adom: auth.adom };
          } else {
            const sysStatus = await getSystemStatus(auth);
            result = {
              status: 'ok',
              type: 'FortiGate',
              base_url: auth.baseUrl,
              authenticated: true,
              hostname: sysStatus.results ? sysStatus.results.hostname : 'unknown',
              serial: sysStatus.results ? sysStatus.results.serial : 'unknown',
              firmware: sysStatus.results ? sysStatus.results.version : 'unknown'
            };
          }
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
    console.error('[Fortinet]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
