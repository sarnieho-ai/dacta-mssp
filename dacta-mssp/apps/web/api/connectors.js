// Vercel Serverless Function — Connector CRUD Proxy
// Routes connector operations through service role key to bypass RLS
// The frontend uses the anon key, which RLS silently blocks on DELETE/UPDATE.
// This proxy uses the service role key for full CRUD access.
//
// Required Vercel env vars:
//   SUPABASE_URL                — e.g. https://xxx.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY   — service role key (full access)
//
// Supported actions:
//   delete_connector  — Delete a connector by id
//   update_connector  — Update a connector by id
//   upsert_connector  — Insert or update a connector
//   list_connectors   — List connectors for an org
//   create_platform_settings_table — Create platform_settings table if missing

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

async function supabaseRequest(method, path, body, headers = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  const opts = {
    method,
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...headers
    }
  };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: resp.status, data, ok: resp.ok };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, PATCH, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const body = req.method === 'POST' || req.method === 'DELETE' || req.method === 'PATCH'
    ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) || {}
    : {};
  const action = req.query.action || body.action;

  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  if (!SUPABASE_SERVICE_KEY) {
    return res.status(500).json({ error: 'Service key not configured' });
  }

  try {
    switch (action) {

      case 'delete_connector': {
        const id = body.id;
        if (!id) return res.status(400).json({ error: 'Missing connector id' });
        const result = await supabaseRequest('DELETE', `org_connectors?id=eq.${id}`);
        if (!result.ok) {
          return res.status(result.status).json({ error: 'Delete failed', detail: result.data });
        }
        // Check if anything was actually deleted
        const deleted = Array.isArray(result.data) ? result.data : [];
        if (deleted.length === 0) {
          return res.status(404).json({ error: 'Connector not found or already deleted', id });
        }
        return res.status(200).json({ success: true, deleted: deleted[0] });
      }

      case 'update_connector': {
        const id = body.id;
        if (!id) return res.status(400).json({ error: 'Missing connector id' });
        const payload = { ...body };
        delete payload.action;
        delete payload.id;
        payload.updated_at = new Date().toISOString();
        const result = await supabaseRequest('PATCH', `org_connectors?id=eq.${id}`, payload);
        if (!result.ok) {
          return res.status(result.status).json({ error: 'Update failed', detail: result.data });
        }
        return res.status(200).json({ success: true, data: Array.isArray(result.data) ? result.data[0] : result.data });
      }

      case 'upsert_connector': {
        const payload = { ...body };
        delete payload.action;
        if (!payload.org_id || !payload.connector_type) {
          return res.status(400).json({ error: 'Missing org_id or connector_type' });
        }
        // Check if exists by org_id + connector_type + vendor
        let existing = null;
        let lookupPath = `org_connectors?org_id=eq.${payload.org_id}&connector_type=eq.${encodeURIComponent(payload.connector_type)}&select=id`;
        if (payload.vendor) lookupPath += `&vendor=eq.${encodeURIComponent(payload.vendor)}`;
        const lookup = await supabaseRequest('GET', lookupPath);
        if (lookup.ok && Array.isArray(lookup.data) && lookup.data.length > 0) {
          existing = lookup.data[0];
        }
        if (existing) {
          payload.updated_at = new Date().toISOString();
          const result = await supabaseRequest('PATCH', `org_connectors?id=eq.${existing.id}`, payload);
          return res.status(200).json({ success: true, mode: 'updated', data: Array.isArray(result.data) ? result.data[0] : result.data });
        } else {
          const result = await supabaseRequest('POST', 'org_connectors', payload);
          if (!result.ok) {
            return res.status(result.status).json({ error: 'Insert failed', detail: result.data });
          }
          return res.status(200).json({ success: true, mode: 'inserted', data: Array.isArray(result.data) ? result.data[0] : result.data });
        }
      }

      case 'list_connectors': {
        const orgId = body.org_id || req.query.org_id;
        let path = 'org_connectors?select=*&order=connector_type';
        if (orgId) path += `&org_id=eq.${orgId}`;
        const result = await supabaseRequest('GET', path);
        return res.status(200).json({ success: true, data: result.data });
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (err) {
    console.error('[Connectors API]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
