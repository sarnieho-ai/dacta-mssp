// Vercel Serverless Function — CrowdStrike Falcon Intel API Proxy
// Provides IOC enrichment, adversary profiles, malware intelligence, and indicator feeds
// Credentials stored server-side only — never exposed to frontend
//
// Required Vercel env vars:
//   CROWDSTRIKE_CLIENT_ID     — OAuth2 client ID
//   CROWDSTRIKE_CLIENT_SECRET — OAuth2 client secret
//   CROWDSTRIKE_BASE_URL      — e.g. https://api.us-2.crowdstrike.com
//
// Supported actions (passed as ?action=... or in POST body):
//   enrich_iocs      — Bulk IOC enrichment (IPs, domains, hashes, URLs)
//   get_actor        — Threat actor profile by slug or ID
//   search_actors    — Search actors by keyword, target industry, target country
//   get_report       — Intelligence report by ID
//   search_reports   — Search finished intelligence reports
//   get_malware      — Malware family detail
//   search_indicators — Search indicators with filters
//   get_vulnerabilities — CVE intelligence lookup

const CS_BASE = process.env.CROWDSTRIKE_BASE_URL || 'https://api.us-2.crowdstrike.com';
const CS_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID || '';
const CS_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET || '';

// ── Token cache (survives warm Vercel invocations) ──
let _csToken = null;
let _csTokenExpiry = 0;

async function getToken() {
  const now = Date.now();
  if (_csToken && now < _csTokenExpiry - 60000) return _csToken; // 1-min buffer

  const resp = await fetch(`${CS_BASE}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `client_id=${encodeURIComponent(CS_CLIENT_ID)}&client_secret=${encodeURIComponent(CS_CLIENT_SECRET)}`
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`CrowdStrike auth failed (${resp.status}): ${err}`);
  }

  const data = await resp.json();
  _csToken = data.access_token;
  _csTokenExpiry = now + (data.expires_in * 1000);
  return _csToken;
}

async function csGet(path, params = {}) {
  const token = await getToken();
  const qs = new URLSearchParams(params).toString();
  const url = `${CS_BASE}${path}${qs ? '?' + qs : ''}`;
  const resp = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`CS GET ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

async function csPost(path, body) {
  const token = await getToken();
  const resp = await fetch(`${CS_BASE}${path}`, {
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
    throw new Error(`CS POST ${path} failed (${resp.status}): ${err}`);
  }
  return resp.json();
}

// ── Action handlers ──

/**
 * Bulk IOC enrichment — accepts mixed array of IPs, domains, hashes (MD5/SHA1/SHA256), URLs
 * Returns per-indicator: malicious_confidence, type, labels, actors, malware_families, last_updated
 * Max 1000 indicators per call (CrowdStrike limit)
 */
async function enrichIOCs(indicators) {
  if (!indicators || !indicators.length) return { resources: [] };

  // CrowdStrike requires indicators chunked to 1000 max
  const chunks = [];
  for (let i = 0; i < indicators.length; i += 1000) {
    chunks.push(indicators.slice(i, i + 1000));
  }

  const results = [];
  for (const chunk of chunks) {
    // First get IDs matching these indicator values
    const filterStr = chunk.map(v => `indicator:"${v}"`).join(',');
    const queryResp = await csGet('/intel/combined/indicators/v1', {
      filter: `(${filterStr})`,
      limit: chunk.length,
      sort: 'published_date|desc'
    });
    if (queryResp.resources) results.push(...queryResp.resources);
  }

  // Shape into a clean lookup map: { indicator_value: { confidence, type, actors, malware, labels } }
  const lookup = {};
  results.forEach(r => {
    lookup[r.indicator] = {
      indicator: r.indicator,
      type: r.type,
      malicious_confidence: r.malicious_confidence, // high / medium / low / unverified
      labels: (r.labels || []).map(l => l.name),
      actors: r.actors || [],
      malware_families: r.malware_families || [],
      kill_chains: r.kill_chains || [],
      published_date: r.published_date,
      last_updated: r.last_updated,
      reports: r.reports || [],
      threat_types: r.threat_types || [],
      // Composite risk signal for DACTA risk scoring
      dacta_confidence_score: {
        high: 90,
        medium: 60,
        low: 30,
        unverified: 10
      }[r.malicious_confidence] || 0
    };
  });

  return { lookup, total: results.length, queried: indicators.length };
}

/**
 * Get threat actor profile(s) by ID or slug
 * e.g. actor_id = 'fancy-bear' or numeric ID
 */
async function getActor(actorIds) {
  const ids = Array.isArray(actorIds) ? actorIds : [actorIds];
  const resp = await csGet('/intel/entities/actors/v1', {
    ids: ids,
    fields: '__full__'
  });
  return resp;
}

/**
 * Search threat actors — by keyword, target industry, target country, motivations
 * Useful for dashboard "Active Adversaries" widget and TI page actor cards
 */
async function searchActors(params = {}) {
  const {
    q,
    target_countries,
    target_industries,
    motivations,
    limit = 10,
    offset = 0
  } = params;

  const queryParams = { limit, offset, fields: 'name,slug,short_description,target_countries,target_industries,motivations,capabilities,group_status,origins,known_as,first_activity_date,last_activity_date,active,kill_chain,image' };
  if (q) queryParams.q = q;
  if (target_countries) queryParams.target_countries = target_countries;
  if (target_industries) queryParams.target_industries = target_industries;
  if (motivations) queryParams.motivations = motivations;

  // Get matching actor IDs first
  const idResp = await csGet('/intel/queries/actors/v1', queryParams);
  if (!idResp.resources || !idResp.resources.length) return { resources: [], meta: idResp.meta };

  // Then fetch full actor details
  const detailResp = await csGet('/intel/entities/actors/v1', {
    ids: idResp.resources,
    fields: '__full__'
  });
  return { resources: detailResp.resources || [], meta: idResp.meta };
}

/**
 * Get finished intelligence reports
 * Useful for TI page "Latest Reports" section
 */
async function searchReports(params = {}) {
  const { q, type, tags, limit = 10, offset = 0 } = params;
  const queryParams = { limit, offset };
  if (q) queryParams.q = q;
  if (type) queryParams.type = type;
  if (tags) queryParams.tags = tags;

  const idResp = await csGet('/intel/queries/reports/v1', queryParams);
  if (!idResp.resources || !idResp.resources.length) return { resources: [], meta: idResp.meta };

  const detailResp = await csGet('/intel/entities/reports/v1', { ids: idResp.resources });
  return { resources: detailResp.resources || [], meta: idResp.meta };
}

/**
 * Get report by ID
 */
async function getReport(reportId) {
  return csGet('/intel/entities/reports/v1', { ids: [reportId] });
}

/**
 * Get malware family detail
 */
async function getMalware(malwareIds) {
  const ids = Array.isArray(malwareIds) ? malwareIds : [malwareIds];
  return csGet('/intel/entities/malware/v1', { ids });
}

/**
 * Search indicators with filters — for TI feed / IOC management
 */
async function searchIndicators(params = {}) {
  const {
    filter,
    sort = 'published_date|desc',
    limit = 50,
    offset = 0,
    include_deleted = false
  } = params;

  const queryParams = { sort, limit, offset, include_deleted };
  if (filter) queryParams.filter = filter;

  return csGet('/intel/combined/indicators/v1', queryParams);
}

/**
 * CVE vulnerability intelligence
 * Useful for Vulnerability Management page
 */
async function getVulnerabilities(params = {}) {
  const { cve_ids, filter, limit = 20, offset = 0 } = params;
  if (cve_ids) {
    const ids = Array.isArray(cve_ids) ? cve_ids : [cve_ids];
    return csGet('/intel/entities/vulnerabilities/v1', { ids });
  }
  const queryParams = { limit, offset };
  if (filter) queryParams.filter = filter;
  const idResp = await csGet('/intel/queries/vulnerabilities/v1', queryParams);
  if (!idResp.resources || !idResp.resources.length) return { resources: [], meta: idResp.meta };
  return csGet('/intel/entities/vulnerabilities/v1', { ids: idResp.resources });
}

// ── Main handler ──

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (!CS_CLIENT_ID || !CS_CLIENT_SECRET) {
    return res.status(503).json({ error: 'CrowdStrike credentials not configured', configured: false });
  }

  const body = req.method === 'POST'
    ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) || {}
    : {};
  const action = req.query.action || body.action;

  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  try {
    let result;

    switch (action) {

      case 'enrich_iocs': {
        // POST body: { indicators: ['1.2.3.4', 'evil.com', 'abc123hash...'] }
        const indicators = body.indicators || req.query.indicators;
        const iocList = Array.isArray(indicators) ? indicators : (indicators ? [indicators] : []);
        result = await enrichIOCs(iocList);
        break;
      }

      case 'get_actor': {
        const actorId = body.actor_id || req.query.actor_id;
        if (!actorId) return res.status(400).json({ error: 'Missing actor_id' });
        result = await getActor(actorId);
        break;
      }

      case 'search_actors': {
        result = await searchActors({
          q: body.q || req.query.q,
          target_countries: body.target_countries || req.query.target_countries,
          target_industries: body.target_industries || req.query.target_industries,
          motivations: body.motivations || req.query.motivations,
          limit: parseInt(body.limit || req.query.limit || 10),
          offset: parseInt(body.offset || req.query.offset || 0)
        });
        break;
      }

      case 'search_reports': {
        result = await searchReports({
          q: body.q || req.query.q,
          type: body.type || req.query.type,
          tags: body.tags || req.query.tags,
          limit: parseInt(body.limit || req.query.limit || 10),
          offset: parseInt(body.offset || req.query.offset || 0)
        });
        break;
      }

      case 'get_report': {
        const reportId = body.report_id || req.query.report_id;
        if (!reportId) return res.status(400).json({ error: 'Missing report_id' });
        result = await getReport(reportId);
        break;
      }

      case 'get_malware': {
        const malwareId = body.malware_id || req.query.malware_id;
        if (!malwareId) return res.status(400).json({ error: 'Missing malware_id' });
        result = await getMalware(malwareId);
        break;
      }

      case 'search_indicators': {
        result = await searchIndicators({
          filter: body.filter || req.query.filter,
          sort: body.sort || req.query.sort,
          limit: parseInt(body.limit || req.query.limit || 50),
          offset: parseInt(body.offset || req.query.offset || 0),
          include_deleted: body.include_deleted === true
        });
        break;
      }

      case 'get_vulnerabilities': {
        result = await getVulnerabilities({
          cve_ids: body.cve_ids || req.query.cve_ids,
          filter: body.filter || req.query.filter,
          limit: parseInt(body.limit || req.query.limit || 20),
          offset: parseInt(body.offset || req.query.offset || 0)
        });
        break;
      }

      // ── Health check — verifies credentials are working ──
      case 'ping': {
        const token = await getToken();
        result = {
          status: 'ok',
          base_url: CS_BASE,
          authenticated: !!token,
          token_preview: token ? token.substring(0, 12) + '...' : null
        };
        break;
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }

    return res.status(200).json(result);

  } catch (err) {
    console.error('[CrowdStrike]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
