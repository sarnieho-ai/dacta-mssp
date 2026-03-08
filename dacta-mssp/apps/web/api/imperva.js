// Vercel Serverless Function — Imperva WAF / Cloud Security API Proxy
// Provides WAF security events, DDoS alerts, bot mitigation, and site configuration
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   IMPERVA_API_ID      — API ID
//   IMPERVA_API_KEY     — API Key
//   IMPERVA_BASE_URL    — e.g. https://my.imperva.com/api (Imperva Cloud WAF)
//
// Per-org credentials: read from org_connectors.credentials_ref via Supabase
//
// Supported actions:
//   get_security_events  — WAF security events (SQLi, XSS, RCE, bot, DDoS)
//   get_site_status      — Site protection status
//   get_visits           — Recent visit data (with threat classification)
//   get_attack_analytics — Attack analytics summary
//   get_ip_reputation    — IP reputation lookup
//   get_rules            — WAF rules and policies
//   get_incidents        — Security incidents
//   get_performance      — CDN and performance metrics
//   ping                 — Health check

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const IMP_BASE = process.env.IMPERVA_BASE_URL || 'https://my.imperva.com/api';
const IMP_API_ID = process.env.IMPERVA_API_ID || '';
const IMP_API_KEY = process.env.IMPERVA_API_KEY || '';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// ── Per-org credential resolution ──
async function getOrgCredentials(orgId) {
  if (!orgId || !SUPABASE_SERVICE_KEY) return null;
  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
    const { data } = await sb.from('org_connectors')
      .select('api_endpoint, auth_type, credentials_ref, metadata')
      .eq('org_id', orgId)
      .ilike('vendor', '%imperva%')
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
      baseUrl: orgCreds.api_endpoint || IMP_BASE,
      apiId: creds.api_id || IMP_API_ID,
      apiKey: creds.api_key || IMP_API_KEY,
      accountId: creds.account_id || '',
      siteId: creds.site_id || ''
    };
  }
  return { baseUrl: IMP_BASE, apiId: IMP_API_ID, apiKey: IMP_API_KEY };
}

// ── HTTP helpers ──
// Imperva Cloud WAF uses POST with api_id + api_key in body or headers

async function impPost(auth, path, params = {}) {
  const body = {
    api_id: auth.apiId,
    api_key: auth.apiKey,
    ...params
  };
  const resp = await fetch(`${auth.baseUrl}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
    body: new URLSearchParams(body).toString()
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Imperva POST ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// Imperva SIEM API (newer REST endpoints)
async function impSiemGet(auth, path, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${auth.baseUrl}${path}${qs ? '?' + qs : ''}`;
  const resp = await fetch(url, {
    headers: {
      'x-API-Id': auth.apiId,
      'x-API-Key': auth.apiKey,
      'Accept': 'application/json'
    }
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Imperva SIEM GET ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Action handlers ──

async function getSecurityEvents(auth, params = {}) {
  // WAF Security Events — SIEM integration logs
  const queryParams = {};
  if (params.site_id || auth.siteId) queryParams.site_id = params.site_id || auth.siteId;
  if (params.account_id || auth.accountId) queryParams.account_id = params.account_id || auth.accountId;
  if (params.time_range) queryParams.time_range = params.time_range; // e.g. "last_1_hr", "last_24_hrs"
  if (params.start) queryParams.start = params.start;
  if (params.end) queryParams.end = params.end;
  if (params.page_size) queryParams.page_size = params.page_size;
  else queryParams.page_size = params.limit || 50;
  if (params.page) queryParams.page = params.page;
  return impSiemGet(auth, '/v1/events', queryParams);
}

async function getSiteStatus(auth, params = {}) {
  // Site protection status and configuration
  const siteId = params.site_id || auth.siteId;
  if (!siteId) throw new Error('Missing site_id');
  return impPost(auth, '/prov/v1/sites/status', { site_id: siteId });
}

async function getVisits(auth, params = {}) {
  // Visit analytics with threat classification
  const siteId = params.site_id || auth.siteId;
  if (!siteId) throw new Error('Missing site_id');
  const visitParams = { site_id: siteId };
  if (params.time_range) visitParams.time_range = params.time_range;
  if (params.security) visitParams.security = params.security; // filter by threat type
  if (params.page_size) visitParams.page_size = params.page_size;
  if (params.page) visitParams.page = params.page;
  return impPost(auth, '/prov/v1/sites/visits', visitParams);
}

async function getAttackAnalytics(auth, params = {}) {
  // Attack analytics summary — aggregated threat data
  const accountId = params.account_id || auth.accountId;
  if (!accountId) throw new Error('Missing account_id');
  const aaParams = { account_id: accountId };
  if (params.time_range) aaParams.time_range = params.time_range;
  if (params.site_id || auth.siteId) aaParams.site_id = params.site_id || auth.siteId;
  return impPost(auth, '/v1/attack-analytics/incidents', aaParams);
}

async function getIPReputation(auth, params = {}) {
  // IP reputation lookup
  if (!params.ip) throw new Error('Missing ip parameter');
  return impPost(auth, '/v1/ips/classification', { ips: params.ip });
}

async function getRules(auth, params = {}) {
  // WAF rules and policies for a site
  const siteId = params.site_id || auth.siteId;
  if (!siteId) throw new Error('Missing site_id');
  return impPost(auth, '/prov/v1/sites/incapRules/list', { site_id: siteId });
}

async function getIncidents(auth, params = {}) {
  // Security incidents
  const accountId = params.account_id || auth.accountId;
  if (!accountId) throw new Error('Missing account_id');
  const incParams = { account_id: accountId };
  if (params.time_range) incParams.time_range = params.time_range;
  if (params.page_size) incParams.page_size = params.page_size;
  if (params.page) incParams.page = params.page;
  return impPost(auth, '/v1/incidents', incParams);
}

async function getPerformance(auth, params = {}) {
  // CDN performance and caching metrics
  const siteId = params.site_id || auth.siteId;
  if (!siteId) throw new Error('Missing site_id');
  return impPost(auth, '/prov/v1/sites/performance', { site_id: siteId, time_range: params.time_range || 'last_24_hrs' });
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
    if (!auth.apiId || !auth.apiKey) {
      return res.status(503).json({ error: 'Imperva credentials not configured', configured: false });
    }

    let result;

    switch (action) {
      case 'get_security_events':
        result = await getSecurityEvents(auth, body);
        break;

      case 'get_site_status': {
        result = await getSiteStatus(auth, body);
        break;
      }

      case 'get_visits':
        result = await getVisits(auth, body);
        break;

      case 'get_attack_analytics':
        result = await getAttackAnalytics(auth, body);
        break;

      case 'get_ip_reputation':
        result = await getIPReputation(auth, body);
        break;

      case 'get_rules':
        result = await getRules(auth, body);
        break;

      case 'get_incidents':
        result = await getIncidents(auth, body);
        break;

      case 'get_performance':
        result = await getPerformance(auth, body);
        break;

      case 'ping': {
        try {
          // Try listing account sites as a health check
          const sites = await impPost(auth, '/prov/v1/sites/list', {
            account_id: auth.accountId || '',
            page_size: 1
          });
          result = {
            status: 'ok',
            base_url: auth.baseUrl,
            authenticated: true,
            account_id: auth.accountId || 'default',
            sites_found: sites.sites ? sites.sites.length : 0
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
    console.error('[Imperva]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
