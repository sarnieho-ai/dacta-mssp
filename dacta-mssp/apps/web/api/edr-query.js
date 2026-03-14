// Vercel Serverless Function — EDR Live Detection Capability Query
// Queries EDR vendor APIs to check real-time detection capability per MITRE technique
// Used by Rule Testing Lab for live detection readiness assessment
//
// Supported vendors: CrowdStrike, Microsoft Defender for Endpoint, Heimdal, Trend Micro
// Falls back to static EDR_MITRE_COVERAGE map when API credentials are not configured
//
// Credentials resolved from org_connectors DB (credentials_ref) or Vercel env vars

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

// ── CrowdStrike defaults from env ──
const CS_BASE = process.env.CROWDSTRIKE_BASE_URL || 'https://api.us-2.crowdstrike.com';
const CS_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID || '';
const CS_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET || '';

// ── Token caches ──
let _csToken = null, _csTokenExpiry = 0;
let _mdeToken = null, _mdeTokenExpiry = 0;

// ── Get CrowdStrike OAuth2 Token ──
async function getCSToken(baseUrl, clientId, clientSecret) {
  const now = Date.now();
  if (_csToken && now < _csTokenExpiry - 60000) return _csToken;
  const resp = await fetch(`${baseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}`
  });
  if (!resp.ok) throw new Error(`CS auth failed: ${resp.status}`);
  const data = await resp.json();
  _csToken = data.access_token;
  _csTokenExpiry = now + (data.expires_in * 1000);
  return _csToken;
}

// ── Get MDE OAuth2 Token (Microsoft Graph / Security API) ──
async function getMDEToken(tenantId, clientId, clientSecret) {
  const now = Date.now();
  if (_mdeToken && now < _mdeTokenExpiry - 60000) return _mdeToken;
  const resp = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=client_credentials&client_id=${encodeURIComponent(clientId)}&client_secret=${encodeURIComponent(clientSecret)}&scope=${encodeURIComponent('https://api.securitycenter.microsoft.com/.default')}`
  });
  if (!resp.ok) throw new Error(`MDE auth failed: ${resp.status}`);
  const data = await resp.json();
  _mdeToken = data.access_token;
  _mdeTokenExpiry = now + (data.expires_in * 1000);
  return _mdeToken;
}

// ── Resolve EDR credentials from org_connectors ──
async function resolveEDRCreds(orgId) {
  try {
    const resp = await fetch(
      `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&connector_type=eq.edr&select=vendor,api_endpoint,auth_type,credentials_ref,metadata`,
      { headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` } }
    );
    const data = await resp.json();
    if (!data || data.length === 0) return null;
    const conn = data[0];
    const creds = conn.credentials_ref
      ? (typeof conn.credentials_ref === 'string' ? JSON.parse(conn.credentials_ref) : conn.credentials_ref)
      : {};
    return { vendor: conn.vendor, apiEndpoint: conn.api_endpoint, creds, metadata: conn.metadata || {} };
  } catch (e) {
    console.warn('[EDR-Query] Failed to resolve creds:', e.message);
    return null;
  }
}

// ── CrowdStrike: Query recent detections by MITRE technique ──
async function queryCrowdStrike(techniques, baseUrl, clientId, clientSecret) {
  const token = await getCSToken(baseUrl, clientId, clientSecret);
  const results = {};
  
  // Query detections from last 90 days that match any of our techniques
  const techniqueFilter = techniques.map(t => `behaviors.tactic_id:'${t}'`).join(',');
  const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  
  // Use the detection query endpoint
  const queryResp = await fetch(
    `${baseUrl}/detects/queries/detects/v1?filter=created_timestamp:>'${since}'&limit=500&sort=created_timestamp|desc`,
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
  );
  
  if (!queryResp.ok) {
    console.warn('[EDR-Query] CS detection query failed:', queryResp.status);
    return { vendor: 'CrowdStrike', live: false, error: `API ${queryResp.status}` };
  }
  
  const queryData = await queryResp.json();
  const detectionIds = (queryData.resources || []).slice(0, 200); // Limit to 200 for detail fetch
  
  if (detectionIds.length === 0) {
    return { vendor: 'CrowdStrike', live: true, detections: 0, techniques: {} };
  }
  
  // Get detection details to extract MITRE techniques
  const detailResp = await fetch(`${baseUrl}/detects/entities/summaries/GET/v1`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids: detectionIds })
  });
  
  if (detailResp.ok) {
    const details = await detailResp.json();
    const resources = details.resources || [];
    
    resources.forEach(det => {
      const behaviors = det.behaviors || [];
      behaviors.forEach(b => {
        const tid = b.tactic_id || '';
        if (tid && techniques.includes(tid)) {
          if (!results[tid]) results[tid] = { detected: 0, prevented: 0, last_seen: null };
          results[tid].detected++;
          if (b.pattern_disposition_details && b.pattern_disposition_details.kill_process) {
            results[tid].prevented++;
          }
          if (!results[tid].last_seen || b.timestamp > results[tid].last_seen) {
            results[tid].last_seen = b.timestamp;
          }
        }
      });
    });
  }
  
  return { vendor: 'CrowdStrike', live: true, detections: detectionIds.length, techniques: results };
}

// ── Microsoft Defender for Endpoint: Query alerts by MITRE technique ──
async function queryMDE(techniques, tenantId, clientId, clientSecret, baseUrl) {
  const token = await getMDEToken(tenantId, clientId, clientSecret);
  const apiBase = baseUrl || 'https://api.securitycenter.microsoft.com';
  const results = {};
  
  const since = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString();
  
  // MDE alerts include mitreTechniques array — query recent alerts
  const alertResp = await fetch(
    `${apiBase}/api/alerts?$top=500&$filter=alertCreationTime ge ${since}&$orderby=alertCreationTime desc`,
    { headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' } }
  );
  
  if (!alertResp.ok) {
    console.warn('[EDR-Query] MDE alert query failed:', alertResp.status);
    return { vendor: 'Microsoft Defender for Endpoint', live: false, error: `API ${alertResp.status}` };
  }
  
  const alertData = await alertResp.json();
  const alerts = alertData.value || [];
  
  alerts.forEach(alert => {
    const mitreTechs = alert.mitreTechniques || [];
    mitreTechs.forEach(tech => {
      // MDE sometimes uses sub-techniques (T1059.001), normalize to parent
      const parentTech = tech.split('.')[0];
      if (techniques.includes(parentTech) || techniques.includes(tech)) {
        const key = techniques.includes(tech) ? tech : parentTech;
        if (!results[key]) results[key] = { detected: 0, prevented: 0, last_seen: null };
        results[key].detected++;
        // Check if MDE blocked the threat
        if (alert.status === 'Resolved' || (alert.evidence && alert.evidence.some(e => e.detectionStatus === 'Prevented'))) {
          results[key].prevented++;
        }
        if (!results[key].last_seen || alert.alertCreationTime > results[key].last_seen) {
          results[key].last_seen = alert.alertCreationTime;
        }
      }
    });
  });
  
  return { vendor: 'Microsoft Defender for Endpoint', live: true, detections: alerts.length, techniques: results };
}

// ── Heimdal: Query detections ──
async function queryHeimdal(techniques, baseUrl, apiKey, customerId) {
  const results = {};
  
  // Heimdal Vigilance EDR detections
  const resp = await fetch(`${baseUrl}/v1/vigilance-edr/detections?limit=500&customer_id=${customerId}`, {
    headers: { Authorization: `Bearer ${apiKey}`, Accept: 'application/json' }
  });
  
  if (!resp.ok) {
    return { vendor: 'Heimdal', live: false, error: `API ${resp.status}` };
  }
  
  const data = await resp.json();
  const detections = data.data || data.items || data.results || [];
  
  // Heimdal detections may include MITRE mapping
  detections.forEach(det => {
    const mitre = det.mitre_technique || det.technique_id || '';
    const parentTech = mitre.split('.')[0];
    if (parentTech && (techniques.includes(parentTech) || techniques.includes(mitre))) {
      const key = techniques.includes(mitre) ? mitre : parentTech;
      if (!results[key]) results[key] = { detected: 0, prevented: 0, last_seen: null };
      results[key].detected++;
      if (det.action === 'blocked' || det.action === 'quarantined' || det.status === 'prevented') {
        results[key].prevented++;
      }
    }
  });
  
  return { vendor: 'Heimdal', live: true, detections: detections.length, techniques: results };
}

// ── Trend Micro Vision One: Query detections ──
async function queryTrendMicro(techniques, baseUrl, apiToken) {
  const results = {};
  
  const resp = await fetch(`${baseUrl}/v3.0/workbench/alerts?top=500&orderBy=createdDateTime desc`, {
    headers: { Authorization: `Bearer ${apiToken}`, Accept: 'application/json' }
  });
  
  if (!resp.ok) {
    return { vendor: 'Trend Micro', live: false, error: `API ${resp.status}` };
  }
  
  const data = await resp.json();
  const alerts = data.items || data.value || [];
  
  alerts.forEach(alert => {
    const indicators = alert.indicators || alert.matchedRules || [];
    indicators.forEach(ind => {
      const mitre = ind.mitreTechniqueId || ind.technique || '';
      const parentTech = mitre.split('.')[0];
      if (parentTech && (techniques.includes(parentTech) || techniques.includes(mitre))) {
        const key = techniques.includes(mitre) ? mitre : parentTech;
        if (!results[key]) results[key] = { detected: 0, prevented: 0, last_seen: null };
        results[key].detected++;
      }
    });
  });
  
  return { vendor: 'Trend Micro', live: true, detections: alerts.length, techniques: results };
}

// ── Main handler ──
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  
  try {
    const { org_id, techniques, vendor_hint } = req.body || {};
    
    if (!org_id || !techniques || !Array.isArray(techniques)) {
      return res.status(400).json({ error: 'Required: org_id (string), techniques (array of MITRE IDs)' });
    }
    
    // Resolve EDR credentials for this org
    const edrInfo = await resolveEDRCreds(org_id);
    
    if (!edrInfo || !edrInfo.vendor) {
      return res.json({
        live: false,
        reason: 'no_edr_configured',
        message: 'No EDR connector configured for this organization',
        techniques: {}
      });
    }
    
    const vendorLower = edrInfo.vendor.toLowerCase();
    const creds = edrInfo.creds || {};
    let result;
    
    // Check if credentials are available
    const hasCredentials = Object.keys(creds).length > 0 ||
      (vendorLower.includes('crowdstrike') && CS_CLIENT_ID) ||
      (vendorLower.includes('heimdal') && process.env.HEIMDAL_API_KEY);
    
    if (!hasCredentials) {
      return res.json({
        live: false,
        reason: 'no_credentials',
        vendor: edrInfo.vendor,
        message: `EDR vendor "${edrInfo.vendor}" configured but API credentials not set. Configure credentials in Settings > Connectors to enable live detection queries.`,
        techniques: {}
      });
    }
    
    // Route to the correct vendor query
    if (vendorLower.includes('crowdstrike') || vendorLower.includes('falcon')) {
      const baseUrl = edrInfo.apiEndpoint || creds.base_url || CS_BASE;
      const clientId = creds.client_id || CS_CLIENT_ID;
      const clientSecret = creds.client_secret || CS_CLIENT_SECRET;
      result = await queryCrowdStrike(techniques, baseUrl, clientId, clientSecret);
      
    } else if (vendorLower.includes('microsoft') || vendorLower.includes('defender') || vendorLower.includes('mde')) {
      const tenantId = creds.tenant_id || process.env.MDE_TENANT_ID || '';
      const clientId = creds.client_id || process.env.MDE_CLIENT_ID || '';
      const clientSecret = creds.client_secret || process.env.MDE_CLIENT_SECRET || '';
      const baseUrl = edrInfo.apiEndpoint || creds.base_url || 'https://api.securitycenter.microsoft.com';
      if (!tenantId || !clientId || !clientSecret) {
        return res.json({
          live: false,
          reason: 'incomplete_credentials',
          vendor: edrInfo.vendor,
          message: 'MDE requires tenant_id, client_id, and client_secret. Configure in Settings > Connectors.',
          techniques: {}
        });
      }
      result = await queryMDE(techniques, tenantId, clientId, clientSecret, baseUrl);
      
    } else if (vendorLower.includes('heimdal')) {
      const baseUrl = edrInfo.apiEndpoint || creds.base_url || 'https://api.heimdalsecurity.com';
      const apiKey = creds.api_key || creds.token || process.env.HEIMDAL_API_KEY || '';
      const customerId = creds.customer_id || process.env.HEIMDAL_CUSTOMER_ID || '';
      result = await queryHeimdal(techniques, baseUrl, apiKey, customerId);
      
    } else if (vendorLower.includes('trend') || vendorLower.includes('vision')) {
      const baseUrl = edrInfo.apiEndpoint || creds.base_url || 'https://api.xdr.trendmicro.com';
      const apiToken = creds.api_key || creds.token || process.env.TRENDMICRO_API_TOKEN || '';
      result = await queryTrendMicro(techniques, baseUrl, apiToken);
      
    } else {
      return res.json({
        live: false,
        reason: 'unsupported_vendor',
        vendor: edrInfo.vendor,
        message: `Live API query not supported for "${edrInfo.vendor}". Using static coverage map.`,
        techniques: {}
      });
    }
    
    return res.json(result);
    
  } catch (e) {
    console.error('[EDR-Query] Error:', e.message);
    return res.json({
      live: false,
      reason: 'api_error',
      error: e.message,
      techniques: {}
    });
  }
};
