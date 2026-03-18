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
//   device_search    — Find endpoint by local_ip or FQL filter; returns hostname, OS, last_seen, tags

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
  // Build query string — handle arrays by repeating the key (CrowdStrike requirement)
  const sp = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (Array.isArray(val)) {
      val.forEach(v => sp.append(key, v));
    } else if (val !== undefined && val !== null) {
      sp.append(key, val);
    }
  }
  const qs = sp.toString();
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

  const queryParams = { limit, offset };
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

      // ── Device search — find endpoint by IP, hostname, or FQL filter ──
      // POST body: { filter: "local_ip:'10.20.14.1'" } or { hostname: 'WS-CORP-001' }
      case 'device_search': {
        const deviceFilter = body.filter ||
          (body.local_ip ? `local_ip:'${body.local_ip}'` : null) ||
          (body.hostname ? `hostname:'${body.hostname}'` : null) ||
          req.query.filter;
        if (!deviceFilter) return res.status(400).json({ error: 'Missing filter or local_ip/hostname' });
        const searchResp = await csGet('/devices/queries/devices/v1', {
          filter: deviceFilter,
          limit: parseInt(body.limit || req.query.limit || 5)
        });
        const deviceIds = searchResp.resources || [];
        if (!deviceIds.length) { result = { devices: [], total: 0 }; break; }
        // Fetch full device details
        const detailResp = await csGet('/devices/entities/devices/v2', { ids: deviceIds });
        const devices = (detailResp.resources || []).map(d => ({
          device_id: d.device_id,
          hostname: d.hostname,
          local_ip: d.local_ip,
          external_ip: d.external_ip,
          os_version: d.os_version,
          platform_name: d.platform_name,
          machine_domain: d.machine_domain,
          ou: (d.ou || []).join(', '),
          system_manufacturer: d.system_manufacturer,
          system_product_name: d.system_product_name,
          agent_version: d.agent_version,
          first_seen: d.first_seen,
          last_seen: d.last_seen,
          status: d.status,
          tags: d.tags || [],
          groups: (d.groups || [])
        }));
        result = { devices, total: devices.length };
        break;
      }

      // ── Detection queries — search and get full detection details ──
      case 'query_detections': {
        // Search detections by IP, hostname, user, or FQL filter
        // POST body: { filter: "...", limit: 20, offset: 0, sort: "created_timestamp|desc" }
        // Shorthand: { hostname: 'WS-001' } or { ip: '10.20.14.1' } or { user: 'jdoe' }
        let dFilter = body.filter || '';
        if (!dFilter) {
          const parts = [];
          if (body.hostname) parts.push(`device.hostname:'${body.hostname}'`);
          if (body.ip) parts.push(`device.local_ip:'${body.ip}'`);
          if (body.user) parts.push(`behaviors.user_name:'${body.user}'`);
          if (body.severity) parts.push(`max_severity_displayname:'${body.severity}'`);
          if (body.start_time) parts.push(`created_timestamp:>'${body.start_time}'`);
          dFilter = parts.join('+');
        }
        const dParams = {
          filter: dFilter,
          limit: parseInt(body.limit || 20),
          offset: parseInt(body.offset || 0),
          sort: body.sort || 'created_timestamp|desc'
        };
        const dIdsResp = await csGet('/detects/queries/detects/v1', dParams);
        const dIds = dIdsResp.resources || [];
        if (!dIds.length) { result = { detections: [], total: 0 }; break; }
        // Fetch full detection details
        const dDetailsResp = await csPost('/detects/entities/summaries/GET/v1', { ids: dIds });
        const detections = (dDetailsResp.resources || []).map(d => ({
          detection_id: d.detection_id,
          created_timestamp: d.created_timestamp,
          hostname: (d.device || {}).hostname || '',
          local_ip: (d.device || {}).local_ip || '',
          external_ip: (d.device || {}).external_ip || '',
          os_version: (d.device || {}).os_version || '',
          status: d.status,
          max_severity: d.max_severity,
          max_severity_displayname: d.max_severity_displayname,
          max_confidence: d.max_confidence,
          first_behavior: d.first_behavior,
          last_behavior: d.last_behavior,
          behaviors: (d.behaviors || []).map(b => ({
            tactic: b.tactic,
            tactic_id: b.tactic_id,
            technique: b.technique,
            technique_id: b.technique_id,
            display_name: b.display_name,
            description: b.description,
            severity: b.severity,
            confidence: b.confidence,
            cmdline: b.cmdline,
            filename: b.filename,
            filepath: b.filepath,
            parent_details: b.parent_details || {},
            user_name: b.user_name,
            sha256: b.sha256,
            md5: b.md5,
            pattern_disposition_description: b.pattern_disposition_description,
            pattern_disposition_details: b.pattern_disposition_details || {}
          })),
          hostinfo: d.hostinfo || {},
          quarantined_files: d.quarantined_files || []
        }));
        result = { detections, total: dIdsResp.meta ? dIdsResp.meta.pagination.total : dIds.length };
        break;
      }

      case 'get_detections': {
        // Get full detection details by IDs
        // POST body: { ids: ['ldt:abc123:456'] }
        const detIds = body.ids;
        if (!detIds || !detIds.length) return res.status(400).json({ error: 'Missing ids array' });
        const detResp = await csPost('/detects/entities/summaries/GET/v1', { ids: detIds });
        result = detResp;
        break;
      }

      // ── Incident queries — search and get incident details ──
      case 'query_incidents': {
        // Search incidents by FQL filter or shorthand params
        let iFilter = body.filter || '';
        if (!iFilter) {
          const iParts = [];
          if (body.hostname) iParts.push(`hosts.hostname:'${body.hostname}'`);
          if (body.status) iParts.push(`status:'${body.status}'`); // new, in_progress, closed, reopened
          if (body.start_time) iParts.push(`start:>'${body.start_time}'`);
          if (body.assigned_to) iParts.push(`assigned_to_name:'${body.assigned_to}'`);
          iFilter = iParts.join('+');
        }
        const iParams = {
          filter: iFilter,
          limit: parseInt(body.limit || 20),
          offset: parseInt(body.offset || 0),
          sort: body.sort || 'start.desc'
        };
        const iIdsResp = await csGet('/incidents/queries/incidents/v1', iParams);
        const iIds = iIdsResp.resources || [];
        if (!iIds.length) { result = { incidents: [], total: 0 }; break; }
        // Fetch full incident details
        const iDetailsResp = await csPost('/incidents/entities/incidents/GET/v1', { ids: iIds });
        result = {
          incidents: iDetailsResp.resources || [],
          total: iIdsResp.meta ? iIdsResp.meta.pagination.total : iIds.length
        };
        break;
      }

      case 'get_incidents': {
        // Get full incident details by IDs
        const incIds = body.ids;
        if (!incIds || !incIds.length) return res.status(400).json({ error: 'Missing ids array' });
        const incResp = await csPost('/incidents/entities/incidents/GET/v1', { ids: incIds });
        result = incResp;
        break;
      }

      // ── Network containment — for Response Center ──
      case 'contain_host': {
        // Contain or lift containment on a device
        // POST body: { device_id: 'abc123', action: 'contain' | 'lift_containment' }
        const deviceId = body.device_id;
        const containAction = body.contain_action || 'contain'; // 'contain' or 'lift_containment'
        if (!deviceId) return res.status(400).json({ error: 'Missing device_id' });
        const containResp = await csPost('/devices/entities/devices-actions/v2', {
          action_name: containAction,
          ids: [deviceId]
        });
        result = containResp;
        break;
      }

      // ── Real-Time Response session — run commands on endpoint ──
      case 'rtr_session': {
        // Start an RTR session
        const rtrDeviceId = body.device_id;
        if (!rtrDeviceId) return res.status(400).json({ error: 'Missing device_id' });
        const sessionResp = await csPost('/real-time-response/entities/sessions/v1', {
          device_id: rtrDeviceId,
          queue_offline: body.queue_offline || false
        });
        result = sessionResp;
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

      // ── Scope probe — test which API families are accessible ──
      case 'probe_scopes': {
        const token = await getToken();
        const probes = [
          // Recon (Digital Risk Protection / External Cyber Risk)
          { name: 'Recon: Monitoring Rules', path: '/recon/queries/rules/v1?limit=1' },
          { name: 'Recon: Notifications', path: '/recon/queries/notifications/v1?limit=1' },
          { name: 'Recon: Exposed Data Records', path: '/recon/queries/notifications-exposed-data-records/v1?limit=1' },
          // Exposure Management / EASM
          { name: 'EASM: External Assets', path: '/fem/queries/external-assets/v1?limit=1' },
          { name: 'Discover: Assets', path: '/discover/queries/assets/v1?limit=1' },
          // Spotlight (Vulnerability Management)
          { name: 'Spotlight: Vulnerabilities', path: '/spotlight/queries/vulnerabilities/v1?limit=1&filter=status%3A%5B%27open%27%5D' },
          { name: 'Spotlight: Combined Vulns', path: '/spotlight/combined/vulnerabilities/v1?limit=1&filter=status%3A%5B%27open%27%5D' },
          // Zero Trust Assessment
          { name: 'ZTA: Assessments', path: '/zero-trust-assessment/queries/assessments/v1?limit=1' },
          // Known working (control)
          { name: 'Intel: Actors (control)', path: '/intel/queries/actors/v1?limit=1' },
          { name: 'Devices (control)', path: '/devices/queries/devices/v1?limit=1' },
          { name: 'Detections', path: '/detects/queries/detects/v1?limit=1' },
          { name: 'Incidents', path: '/incidents/queries/incidents/v1?limit=1' },
        ];

        const results = [];
        for (const probe of probes) {
          try {
            const resp = await fetch(`${CS_BASE}${probe.path}`, {
              headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
            });
            const data = await resp.json();
            const resourceCount = data.resources ? data.resources.length : 0;
            const totalCount = data.meta && data.meta.pagination ? data.meta.pagination.total : null;
            results.push({
              name: probe.name,
              status: resp.status,
              accessible: resp.status === 200,
              resources: resourceCount,
              total: totalCount,
              error: resp.status !== 200 ? (data.errors || data.message || null) : null
            });
          } catch (e) {
            results.push({ name: probe.name, status: 'error', accessible: false, error: e.message });
          }
        }
        result = { probes: results };
        break;
      }

      // ── Recon: Query monitoring rules ──
      case 'recon_rules': {
        const ruleData = await csGet('/recon/queries/rules/v1', {
          limit: parseInt(body.limit || 20),
          offset: parseInt(body.offset || 0),
          q: body.q || undefined
        });
        const ruleIds = ruleData.resources || [];
        if (!ruleIds.length) { result = { rules: [], total: 0 }; break; }
        const ruleDetails = await csGet('/recon/entities/rules/v1', { ids: ruleIds });
        result = { rules: ruleDetails.resources || [], total: ruleData.meta?.pagination?.total || ruleIds.length };
        break;
      }

      // ── Recon: Query notifications ──
      case 'recon_notifications': {
        const notifParams = { limit: parseInt(body.limit || 20), offset: parseInt(body.offset || 0) };
        if (body.filter) notifParams.filter = body.filter;
        if (body.q) notifParams.q = body.q;
        if (body.sort) notifParams.sort = body.sort;
        const notifData = await csGet('/recon/queries/notifications/v1', notifParams);
        const notifIds = notifData.resources || [];
        if (!notifIds.length) { result = { notifications: [], total: 0 }; break; }
        // Use non-translated detailed endpoint (more reliable)
        const notifDetails = await csGet('/recon/entities/notifications-detailed/v1', { ids: notifIds });
        result = { notifications: notifDetails.resources || [], total: notifData.meta?.pagination?.total || notifIds.length };
        break;
      }

      // ── Recon: Exposed data records ──
      case 'recon_exposed_data': {
        const edrParams = { limit: parseInt(body.limit || 20), offset: parseInt(body.offset || 0) };
        if (body.filter) edrParams.filter = body.filter;
        const edrData = await csGet('/recon/queries/notifications-exposed-data-records/v1', edrParams);
        const edrIds = edrData.resources || [];
        if (!edrIds.length) { result = { records: [], total: 0 }; break; }
        const edrDetails = await csGet('/recon/entities/notifications-exposed-data-records/v1', { ids: edrIds.slice(0, 50) });
        result = { records: edrDetails.resources || [], total: edrData.meta?.pagination?.total || edrIds.length };
        break;
      }

      // ── EASM: External assets ──
      case 'easm_assets': {
        const easmParams = { limit: parseInt(body.limit || 20), offset: parseInt(body.offset || 0) };
        if (body.filter) easmParams.filter = body.filter;
        const easmIdData = await csGet('/fem/queries/external-assets/v1', easmParams);
        const easmIds = easmIdData.resources || [];
        if (!easmIds.length) { result = { assets: [], total: 0 }; break; }
        // Fetch full asset details (GET with ids param)
        const easmDetails = await csGet('/fem/entities/external-assets/v1', { ids: easmIds.slice(0, 50) });
        result = {
          assets: easmDetails.resources || [],
          total: easmIdData.meta?.pagination?.total || easmIds.length
        };
        break;
      }

      // ── Discover: IT assets ──
      case 'discover_assets': {
        const discParams = { limit: parseInt(body.limit || 20), offset: parseInt(body.offset || 0) };
        if (body.filter) discParams.filter = body.filter;
        const discData = await csGet('/discover/queries/assets/v1', discParams);
        result = discData;
        break;
      }

      // ── Spotlight: Vulnerabilities ──
      case 'spotlight_vulns': {
        const slParams = { limit: parseInt(body.limit || 20) };
        if (body.filter) slParams.filter = body.filter;
        else slParams.filter = "status:['open']";
        const slData = await csGet('/spotlight/combined/vulnerabilities/v1', slParams);
        result = slData;
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
