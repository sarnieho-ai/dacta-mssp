// Vercel Serverless Function — Palo Alto Networks API Proxy
// Supports Cortex Data Lake (CDL), PAN-OS XML API, and Cortex XDR
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   PALOALTO_API_KEY    — API key (PAN-OS) or Bearer token (Cortex)
//   PALOALTO_BASE_URL   — e.g. https://api.us.cdl.paloaltonetworks.com or https://firewall.example.com
//   PALOALTO_API_TYPE   — 'cdl' (Cortex Data Lake), 'panos' (PAN-OS XML), or 'xdr' (Cortex XDR)
//
// Per-org credentials: read from org_connectors.credentials_ref via Supabase
//
// Supported actions:
//   search_logs          — CDL/PAN-OS log query (traffic, threat, url, wildfire)
//   get_threat_logs      — Threat logs (IPS, AV, spyware)
//   get_traffic_logs     — Firewall traffic logs (allow/deny)
//   get_url_logs         — URL filtering events
//   get_wildfire_logs    — WildFire malware analysis verdicts
//   get_system_info      — PAN-OS system info
//   search_incidents     — Cortex XDR incident search
//   get_alerts           — Cortex XDR alerts
//   ping                 — Health check


function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const PA_BASE = process.env.PALOALTO_BASE_URL || '';
const PA_API_KEY = process.env.PALOALTO_API_KEY || '';
const PA_API_TYPE = process.env.PALOALTO_API_TYPE || 'panos';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

// ── Per-org credential resolution (fetch-based, no npm deps) ──
async function getOrgCredentials(orgId) {
  if (!orgId || !SUPABASE_SERVICE_KEY) return null;
  try {
    const url = `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&vendor=ilike.*palo*&is_enabled=eq.true&select=api_endpoint,auth_type,credentials_ref&limit=1`;
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
    const meta = orgCreds.metadata || {};
    return {
      baseUrl: orgCreds.api_endpoint || PA_BASE,
      apiKey: creds.api_key || creds.token || PA_API_KEY,
      apiType: meta.api_type || creds.api_type || PA_API_TYPE,
      tenantId: creds.tenant_id || '',
      clientId: creds.client_id || '',
      clientSecret: creds.client_secret || ''
    };
  }
  return { baseUrl: PA_BASE, apiKey: PA_API_KEY, apiType: PA_API_TYPE };
}

// ── HTTP helpers ──

// PAN-OS XML API
async function panosGet(auth, params = {}) {
  const allParams = { key: auth.apiKey, ...params };
  const qs = new URLSearchParams(allParams).toString();
  const url = `${auth.baseUrl}/api/?${qs}`;
  const resp = await fetch(url, { headers: { 'Accept': 'application/xml' } });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`PAN-OS API failed (${resp.status}): ${err}`);
  }
  // Return raw XML text — caller parses as needed
  return resp.text();
}

// Cortex Data Lake REST API
async function cdlPost(auth, path, body) {
  const resp = await fetch(`${auth.baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${auth.apiKey}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`CDL POST ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

async function cdlGet(auth, path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${auth.baseUrl}${path}${qs ? '?' + qs : ''}`;
  const resp = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${auth.apiKey}`,
      'Accept': 'application/json'
    }
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`CDL GET ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// Cortex XDR API
async function xdrPost(auth, path, body) {
  const resp = await fetch(`${auth.baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'x-xdr-auth-id': auth.clientId || '1',
      'Authorization': auth.apiKey,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`XDR POST ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Action handlers ──

async function searchLogs(auth, params = {}) {
  if (auth.apiType === 'cdl') {
    // Cortex Data Lake — SQL query
    const query = params.query || buildCDLQuery(params);
    return cdlPost(auth, '/query/v2/jobs', { query, startTime: params.start_time || 0, endTime: params.end_time || 0 });
  } else {
    // PAN-OS XML API — log query
    const logType = params.logtype || 'traffic';
    const filter = params.filter || '';
    const nlogs = params.limit || 50;
    const xmlResp = await panosGet(auth, {
      type: 'log',
      'log-type': logType,
      query: filter,
      nlogs
    });
    // Parse XML to extract log entries (basic extraction)
    return { raw_xml: xmlResp, logtype: logType };
  }
}

function buildCDLQuery(params) {
  const logType = params.logtype || 'firewall.traffic';
  const parts = [`SELECT * FROM \`${logType}\``];
  const conditions = [];
  if (params.src_ip) conditions.push(`source_ip.value = '${params.src_ip}'`);
  if (params.dst_ip) conditions.push(`dest_ip.value = '${params.dst_ip}'`);
  if (params.hostname) conditions.push(`source_host = '${params.hostname}'`);
  if (params.action) conditions.push(`action = '${params.action}'`);
  if (params.rule_name) conditions.push(`rule = '${params.rule_name}'`);
  if (conditions.length) parts.push('WHERE ' + conditions.join(' AND '));
  parts.push(`LIMIT ${params.limit || 50}`);
  return parts.join(' ');
}

async function getThreatLogs(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: auth.apiType === 'cdl' ? 'firewall.threat' : 'threat' });
}

async function getTrafficLogs(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: auth.apiType === 'cdl' ? 'firewall.traffic' : 'traffic' });
}

async function getURLLogs(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: auth.apiType === 'cdl' ? 'firewall.url' : 'url' });
}

async function getWildfireLogs(auth, params = {}) {
  return searchLogs(auth, { ...params, logtype: auth.apiType === 'cdl' ? 'firewall.wildfire' : 'wildfire' });
}

async function getSystemInfo(auth) {
  if (auth.apiType === 'panos') {
    const xmlResp = await panosGet(auth, { type: 'op', cmd: '<show><system><info></info></system></show>' });
    return { raw_xml: xmlResp };
  }
  return { error: 'System info only available for PAN-OS API type' };
}

async function searchIncidents(auth, params = {}) {
  if (auth.apiType !== 'xdr') return { error: 'Incident search requires Cortex XDR API type' };
  const body = {
    request_data: {
      filters: [],
      search_from: params.offset || 0,
      search_to: (params.offset || 0) + (params.limit || 20),
      sort: { field: 'creation_time', keyword: 'desc' }
    }
  };
  if (params.status) body.request_data.filters.push({ field: 'status', operator: 'eq', value: params.status });
  if (params.severity) body.request_data.filters.push({ field: 'severity', operator: 'eq', value: params.severity });
  if (params.hostname) body.request_data.filters.push({ field: 'host_name', operator: 'contains', value: params.hostname });
  return xdrPost(auth, '/public_api/v1/incidents/get_incidents/', body);
}

async function getAlerts(auth, params = {}) {
  if (auth.apiType !== 'xdr') return { error: 'Alert search requires Cortex XDR API type' };
  const body = {
    request_data: {
      filters: [],
      search_from: params.offset || 0,
      search_to: (params.offset || 0) + (params.limit || 50),
      sort: { field: 'event_timestamp', keyword: 'desc' }
    }
  };
  if (params.hostname) body.request_data.filters.push({ field: 'host_name', operator: 'contains', value: params.hostname });
  if (params.ip) body.request_data.filters.push({ field: 'host_ip', operator: 'contains', value: params.ip });
  return xdrPost(auth, '/public_api/v1/alerts/get_alerts_multi_events/', body);
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
    if (!auth.baseUrl || !auth.apiKey) {
      return res.status(503).json({ error: 'Palo Alto credentials not configured', configured: false });
    }

    let result;

    switch (action) {
      case 'search_logs':
        result = await searchLogs(auth, body);
        break;

      case 'get_threat_logs':
        result = await getThreatLogs(auth, body);
        break;

      case 'get_traffic_logs':
        result = await getTrafficLogs(auth, body);
        break;

      case 'get_url_logs':
        result = await getURLLogs(auth, body);
        break;

      case 'get_wildfire_logs':
        result = await getWildfireLogs(auth, body);
        break;

      case 'get_system_info':
        result = await getSystemInfo(auth);
        break;

      case 'search_incidents':
        result = await searchIncidents(auth, body);
        break;

      case 'get_alerts':
        result = await getAlerts(auth, body);
        break;

      case 'ping': {
        try {
          if (auth.apiType === 'panos') {
            const sysInfo = await getSystemInfo(auth);
            result = { status: 'ok', type: 'PAN-OS', base_url: auth.baseUrl, authenticated: true, info: sysInfo };
          } else if (auth.apiType === 'xdr') {
            const incidents = await searchIncidents(auth, { limit: 1 });
            result = { status: 'ok', type: 'Cortex XDR', base_url: auth.baseUrl, authenticated: true, total_incidents: incidents.reply ? incidents.reply.total_count : 0 };
          } else {
            // CDL — run a minimal query
            const testQ = await cdlPost(auth, '/query/v2/jobs', { query: "SELECT * FROM `firewall.traffic` LIMIT 1" });
            result = { status: 'ok', type: 'Cortex Data Lake', base_url: auth.baseUrl, authenticated: true, job_id: testQ.jobId || testQ.queryId };
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
    console.error('[PaloAlto]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
