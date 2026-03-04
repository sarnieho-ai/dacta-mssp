// Vercel Serverless Function — Jira API Proxy
// Handles CORS, authentication, and pagination for Jira Cloud REST API v3
// All credentials read from Vercel Environment Variables — never hardcode secrets

// Required env vars: JIRA_EMAIL, JIRA_API_TOKEN, JIRA_INSTANCE, JIRA_CLOUD_ID, JIRA_TEAM_ID, SUPABASE_URL, SUPABASE_ANON_KEY
const _JE = process.env.JIRA_EMAIL || '';
const _JT = process.env.JIRA_API_TOKEN || '';
const _JI = process.env.JIRA_INSTANCE || 'dactaglobal-sg.atlassian.net';
const _CID = process.env.JIRA_CLOUD_ID || '';
const _TID = process.env.JIRA_TEAM_ID || '';

// Server-side in-memory cache (survives across warm invocations on same Vercel instance)
const _serverCache = {};
const _serverCacheTime = {};
const _SERVER_CACHE_TTL = 30000; // 30 seconds — balances freshness vs. speed

// Contact directory cache — longer TTL (24h) since contacts rarely change
const _contactCache = {};
const _contactCacheTime = {};
const _CONTACT_CACHE_TTL = 86400000; // 24 hours

function _getCached(key) {
  if (_serverCache[key] && (Date.now() - _serverCacheTime[key]) < _SERVER_CACHE_TTL) {
    return _serverCache[key];
  }
  return null;
}
function _setCache(key, data) {
  _serverCache[key] = data;
  _serverCacheTime[key] = Date.now();
}

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }

// ── Supabase REST API helpers (server-side, bypasses client RLS issues) ──
const _SB_URL = process.env.SUPABASE_URL || '';
const _SB_KEY = process.env.SUPABASE_ANON_KEY || '';

async function _sbGet(table, query) {
  try {
    const r = await fetch(`${_SB_URL}/rest/v1/${table}?${query}`, {
      headers: { 'apikey': _SB_KEY, 'Authorization': `Bearer ${_SB_KEY}`, 'Accept': 'application/json' }
    });
    if (r.status === 404 || r.status === 406) return []; // Table doesn't exist yet
    if (!r.ok) { console.warn('[SB] GET error:', r.status); return []; }
    return await r.json();
  } catch(e) { console.warn('[SB] GET failed:', e.message); return []; }
}

async function _sbUpsert(table, row, conflictCol) {
  try {
    const r = await fetch(`${_SB_URL}/rest/v1/${table}`, {
      method: 'POST',
      headers: {
        'apikey': _SB_KEY, 'Authorization': `Bearer ${_SB_KEY}`,
        'Content-Type': 'application/json', 'Accept': 'application/json',
        'Prefer': `resolution=merge-duplicates${conflictCol ? `,on_conflict=${conflictCol}` : ''}`
      },
      body: JSON.stringify(row)
    });
    if (!r.ok) {
      const errText = await r.text();
      console.warn('[SB] UPSERT error:', r.status, errText);
      // If table doesn't exist, fall back to server cache only
      return null;
    }
    const data = await r.json();
    return Array.isArray(data) ? data[0] : data;
  } catch(e) { console.warn('[SB] UPSERT failed:', e.message); return null; }
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Credentials from Vercel env vars
  if (!_JE || !_JT) {
    return res.status(500).json({ error: 'Server misconfigured: JIRA_EMAIL and JIRA_API_TOKEN environment variables are required' });
  }
  const JIRA_EMAIL = _JE;
  const JIRA_TOKEN = _JT;
  const JIRA_INSTANCE = _JI;

  const auth = Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString('base64');
  const baseUrl = `https://${JIRA_INSTANCE}`;

  // Helper: paginated count
  async function countJql(jql) {
    let total = 0, npt = null, pg = 0;
    while (pg < 100) {
      const payload = { jql, maxResults: 100, fields: ['key'] };
      if (npt) payload.nextPageToken = npt;
      const r = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      });
      const d = await r.json();
      total += (d.issues || []).length;
      pg++;
      if (d.isLast || !d.nextPageToken) break;
      npt = d.nextPageToken;
    }
    return total;
  }

  // Helper: search with fields
  async function searchJql(jql, fields, maxResults, nextPageToken) {
    const payload = { jql, fields, maxResults: maxResults || 50 };
    if (nextPageToken) payload.nextPageToken = nextPageToken;
    const r = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload)
    });
    return r.json();
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {});
    let { action } = req.query;

    // Fallback: if no action in query params, check body for endpoint or jql
    if (!action && body.endpoint) {
      action = body.endpoint;
    }
    if (!action && body.jql) {
      action = 'search';
    }

    // ─── ACTION: users ──────────────────────────────────────
    if (action === 'users') {
      // Get all users assignable to the DAC project
      const r = await fetch(`${baseUrl}/rest/api/3/user/assignable/search?project=DAC&maxResults=100`, {
        headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
      });
      const users = await r.json();
      return res.status(200).json(Array.isArray(users) ? users : []);
    }

    // ─── ACTION: dashboard ────────────────────────────────────
    if (action === 'dashboard') {
      // Time range mapping for JQL
      const timeRange = req.query.timeRange || '24h';
      const timeRangeMap = {
        '1h': '-1h', '4h': '-4h', '12h': '-12h', '24h': '-24h',
        '7d': '-168h', '30d': '-720h'
      };
      const recentJql = timeRangeMap[timeRange] || '-24h';
      const isRelative = recentJql.startsWith('-');
      const createdFilter = isRelative ? ('created >= "' + recentJql + '"') : ('created >= ' + recentJql);
      const updatedFilter = isRelative ? ('updated >= "' + recentJql + '"') : ('updated >= ' + recentJql);

      // Check server-side cache (keyed by time range)
      var cached = _getCached('dashboard_' + timeRange);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cached);
      }
      const B = 'project = DAC AND type = "[System] Incident"';
      const [
        openCount, p1Count, p2Count, p3Count, p4Count,
        closedTodayCount, canceledTodayCount, completedTodayCount,
        todayCount, weekCount, recentData
      ] = await Promise.all([
        countJql(`${B} AND status="Open"`),
        countJql(`${B} AND status="Open" AND priority="P1 - Critical"`),
        countJql(`${B} AND status="Open" AND priority="P2 - High"`),
        countJql(`${B} AND status="Open" AND priority="P3 - Medium"`),
        countJql(`${B} AND status="Open" AND priority="P4 - Low"`),
        countJql(`${B} AND status="Closed" AND ${updatedFilter}`),
        countJql(`${B} AND status="Canceled" AND ${updatedFilter}`),
        countJql(`${B} AND status="Completed" AND ${updatedFilter}`),
        countJql(`${B} AND ${createdFilter}`),
        countJql(`${B} AND created >= startOfWeek()`),
        searchJql(`${B} AND status="Open" ORDER BY created DESC`, [
          'summary','status','priority','assignee','created','updated','issuetype',
          'labels','customfield_10002','customfield_10050','customfield_10072','customfield_10038'
        ], 20)
      ]);

      const dashResult = {
        kpi: {
          open: openCount, p1: p1Count, p2: p2Count, p3: p3Count, p4: p4Count,
          closedToday: closedTodayCount, canceledToday: canceledTodayCount,
          completedToday: completedTodayCount,
          todayNew: todayCount, weekNew: weekCount,
          resolvedToday: closedTodayCount + completedTodayCount + canceledTodayCount
        },
        recentTickets: (recentData.issues || []).map(normalizeIssue)
      };
      _setCache('dashboard_' + timeRange, dashResult);
      return res.status(200).json(dashResult);
    }

    // ─── ACTION: triage ───────────────────────────────────────
    if (action === 'triage') {
      const body = req.body || {};
      let jqlParts = ['project = DAC AND type = "[System] Incident"'];

      // Date range filter
      if (body.dateFrom) jqlParts.push('created >= "' + body.dateFrom + '"');
      if (body.dateTo) jqlParts.push('created <= "' + body.dateTo + '"');

      if (body.status && body.status !== 'all') jqlParts.push(`status="${body.status}"`);
      if (body.priority && body.priority !== 'all') jqlParts.push(`priority="${body.priority}"`);
      if (body.org && body.org !== 'all') jqlParts.push(`"Organizations" = "${body.org}"`);
      if (body.assignee && body.assignee !== 'all') {
        jqlParts.push(body.assignee === 'Unassigned' ? 'assignee is EMPTY' : `assignee = "${body.assignee}"`);
      }
      if (body.label && body.label !== 'all') jqlParts.push(`labels = "${body.label}"`);
      if (body.search) jqlParts.push(`summary ~ "${body.search}"`);

      const jql = jqlParts.join(' AND ') + ' ORDER BY created DESC';
      const data = await searchJql(jql, [
        'summary','status','priority','assignee','reporter','created','updated','issuetype',
        'labels','customfield_10002','customfield_10050','customfield_10072','customfield_10068',
        'customfield_10038','customfield_10406','customfield_10472','customfield_10473','customfield_10573',
        'customfield_10010'
      ], body.maxResults || 50, body.nextPageToken);

      return res.status(200).json({
        issues: (data.issues || []).map(normalizeIssue),
        isLast: data.isLast,
        nextPageToken: data.nextPageToken
      });
    }

    // ─── ACTION: issue ────────────────────────────────────────
    if (action === 'issue') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}?expand=changelog,renderedFields`, {
        headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
      });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: comments ─────────────────────────────────────
    if (action === 'comments') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}/comment`, {
        headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
      });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: search (generic) ─────────────────────────────
    if (action === 'search') {
      const data = await searchJql(
        body.jql || 'project = DAC AND type = "[System] Incident" ORDER BY created DESC',
        body.fields || ['summary','status','priority','assignee','created','updated','issuetype','labels','customfield_10002','customfield_10050','customfield_10072','customfield_10038'],
        body.maxResults || 50,
        body.nextPageToken
      );
      return res.status(200).json(data);
    }

    // ─── ACTION: counts (batch) ───────────────────────────────
    if (action === 'counts') {
      const body = req.body || {};
      const queries = body.queries || {};
      const entries = Object.entries(queries);
      const results = {};
      const promises = entries.map(([key, jql]) => countJql(jql).then(total => { results[key] = total; }));
      await Promise.all(promises);
      return res.status(200).json(results);
    }

    // ─── ACTION: transitions ──────────────────────────────────
    if (action === 'transitions') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}/transitions`, {
        headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
      });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: transition (change status) ───────────────────
    if (action === 'transition') {
      const body = req.body || {};
      const key = body.key;
      const transitionId = body.transitionId;
      if (!key || !transitionId) return res.status(400).json({ error: 'Missing key or transitionId' });
      const payload = { transition: { id: transitionId } };
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}/transitions`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (r.status === 204) return res.status(200).json({ success: true });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: assign ──────────────────────────────────────
    if (action === 'assign') {
      const body = req.body || {};
      const key = body.key;
      const accountId = body.accountId;
      if (!key) return res.status(400).json({ error: 'Missing key' });
      const payload = { accountId: accountId || null }; // null = unassign
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}/assignee`, {
        method: 'PUT',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (r.status === 204) return res.status(200).json({ success: true });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: comment ─────────────────────────────────────
    if (action === 'addcomment') {
      const body = req.body || {};
      const key = body.key;
      const text = body.text;
      if (!key || !text) return res.status(400).json({ error: 'Missing key or text' });
      const adfBody = {
        body: {
          type: 'doc', version: 1,
          content: [{ type: 'paragraph', content: [{ type: 'text', text }] }]
        }
      };
      const r = await fetch(`${baseUrl}/rest/api/3/issue/${key}/comment`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(adfBody)
      });
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: replyCustomer (JSM "Reply to customer" via servicedesk API) ──
    if (action === 'replyCustomer') {
      const body = req.body || {};
      const key = body.key;
      const text = body.text;
      const isPublic = body.isPublic !== false; // default to public (customer-visible)
      if (!key || !text) return res.status(400).json({ error: 'Missing key or text' });
      // JSM Service Desk comment endpoint (public = visible to customer = "Reply to customer")
      const jsmPayload = {
        body: text,
        public: isPublic
      };
      const r = await fetch(`${baseUrl}/rest/servicedesc/1/servicedesk/request/${key}/comment`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(jsmPayload)
      });
      // Fallback to REST API v2 if servicedesk API fails
      if (r.status >= 400) {
        // Try the legacy JSM comment endpoint
        const r2 = await fetch(`${baseUrl}/rest/api/2/issue/${key}/comment`, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            body: text,
            properties: isPublic ? [{ key: 'sd.public.comment', value: { internal: false } }] : []
          })
        });
        return res.status(r2.status).json(await r2.json());
      }
      return res.status(r.status).json(await r.json());
    }

    // ─── ACTION: sla (fetch SLA data for a ticket) ───────────
    if (action === 'sla') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });
      const result = { source: 'none', jsmSLA: null, fields: null };
      // Try fetching SLA info from JSM Service Desk API
      try {
        const r = await fetch(`${baseUrl}/rest/servicedesc/1/servicedesk/request/${key}/sla`, {
          headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
        });
        if (r.status === 200) {
          result.jsmSLA = await r.json();
          result.source = 'jsm';
        }
      } catch(e) { /* fallback below */ }
      // Also fetch Dacta SLA custom fields (customfield_10472, 10473, 10573)
      try {
        const r2 = await fetch(`${baseUrl}/rest/api/3/issue/${key}?fields=customfield_10472,customfield_10473,customfield_10573,customfield_10020,customfield_10010,priority,created`, {
          headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
        });
        if (r2.status < 400) {
          const issueData = await r2.json();
          result.fields = issueData.fields || {};
          if (!result.source || result.source === 'none') result.source = 'fields';
        }
      } catch(e2) { /* continue */ }
      if (result.source === 'none') {
        return res.status(500).json({ error: 'SLA fetch failed' });
      }
      return res.status(200).json(result);
    }

    // ─── ACTION: requestParticipants (fetch JSM request participants) ───
    if (action === 'requestParticipants') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });
      const result = { participants: [], source: 'none' };
      // Try JSM Service Desk API for request participants
      try {
        const r = await fetch(`${baseUrl}/rest/servicedesc/1/servicedesk/request/${key}/participant`, {
          headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
        });
        if (r.status === 200) {
          const data = await r.json();
          result.participants = (data.values || []).map(p => ({
            accountId: p.accountId,
            displayName: p.displayName || p.name || '',
            emailAddress: p.emailAddress || ''
          }));
          result.source = 'jsm';
        }
      } catch(e) { /* fallback below */ }
      // Also try issue fields for request participants (customfield_10039)
      if (result.participants.length === 0) {
        try {
          const r2 = await fetch(`${baseUrl}/rest/api/3/issue/${key}?fields=customfield_10039,customfield_10002,reporter`, {
            headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
          });
          if (r2.status < 400) {
            const issueData = await r2.json();
            const fields = issueData.fields || {};
            // customfield_10039 = Request participants (array of user objects)
            if (fields.customfield_10039 && Array.isArray(fields.customfield_10039)) {
              result.participants = fields.customfield_10039.map(p => ({
                accountId: p.accountId || '',
                displayName: p.displayName || p.name || '',
                emailAddress: p.emailAddress || ''
              }));
              result.source = 'fields';
            }
            // Also include reporter as fallback
            if (fields.reporter) {
              result.reporter = {
                accountId: fields.reporter.accountId || '',
                displayName: fields.reporter.displayName || '',
                emailAddress: fields.reporter.emailAddress || ''
              };
            }
            // Include organizations
            if (fields.customfield_10002 && Array.isArray(fields.customfield_10002)) {
              result.organizations = fields.customfield_10002.map(o => o.name || '');
            }
          }
        } catch(e2) { /* continue */ }
      }

      // ── Resolve null emails via per-participant user lookup (GDPR workaround) ──
      if (result.participants.length > 0) {
        const resolvedParticipants = await Promise.all(
          result.participants.map(async (p) => {
            if (p.emailAddress && p.emailAddress.indexOf('@') !== -1) return p; // already has email
            if (!p.accountId) return p;
            try {
              const userResp = await fetch(`${baseUrl}/rest/api/3/user?accountId=${encodeURIComponent(p.accountId)}`, {
                headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
              });
              if (userResp.status === 200) {
                const userData = await userResp.json();
                if (userData.emailAddress) {
                  p.emailAddress = userData.emailAddress;
                }
              }
            } catch(ue) { /* skip failed lookups */ }
            return p;
          })
        );
        result.participants = resolvedParticipants;
      }
      // Also resolve reporter email if null
      if (result.reporter && !result.reporter.emailAddress && result.reporter.accountId) {
        try {
          const rptResp = await fetch(`${baseUrl}/rest/api/3/user?accountId=${encodeURIComponent(result.reporter.accountId)}`, {
            headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
          });
          if (rptResp.status === 200) {
            const rptData = await rptResp.json();
            if (rptData.emailAddress) result.reporter.emailAddress = rptData.emailAddress;
          }
        } catch(re) { /* skip */ }
      }

      // ── Contact Directory: resolve GDPR-blocked emails & auto-save resolved ones ──
      const orgName = (result.organizations && result.organizations[0]) || '';
      for (const p of result.participants) {
        if (p.emailAddress && p.emailAddress.indexOf('@') !== -1) {
          // Email resolved — auto-save to directory for future lookups
          const saveKey = p.accountId || p.displayName;
          if (saveKey && !_contactCache[saveKey]) {
            _contactCache[saveKey] = { email: p.emailAddress, display_name: p.displayName, jira_org: orgName };
            _contactCacheTime[saveKey] = Date.now();
            // Fire-and-forget save to Supabase
            _sbUpsert('contact_directory', {
              account_id: p.accountId || '', display_name: p.displayName || '',
              email: p.emailAddress, jira_org: orgName, source: 'jira_api',
              updated_at: new Date().toISOString()
            }, 'account_id').catch(() => {});
          }
        } else {
          // GDPR blocked — check contact directory for cached email
          const lookupKey = p.accountId || p.displayName;
          // Check in-memory contact cache first
          if (_contactCache[lookupKey] && _contactCache[lookupKey].email) {
            p.emailAddress = _contactCache[lookupKey].email;
            p._resolvedFrom = 'contact_cache';
          } else {
            // Try Supabase directory
            let sbContacts = [];
            if (p.accountId) {
              sbContacts = await _sbGet('contact_directory', `select=*&account_id=eq.${encodeURIComponent(p.accountId)}`);
            }
            if ((!sbContacts || sbContacts.length === 0) && p.displayName) {
              sbContacts = await _sbGet('contact_directory', `select=*&display_name=eq.${encodeURIComponent(p.displayName)}`);
            }
            if (sbContacts && sbContacts.length > 0 && sbContacts[0].email) {
              p.emailAddress = sbContacts[0].email;
              p._resolvedFrom = 'contact_directory';
              _contactCache[lookupKey] = sbContacts[0];
              _contactCacheTime[lookupKey] = Date.now();
            }
          }
        }
      }
      // Same for reporter
      if (result.reporter && result.reporter.emailAddress && result.reporter.emailAddress.indexOf('@') !== -1) {
        const rKey = result.reporter.accountId || result.reporter.displayName;
        if (rKey && !_contactCache[rKey]) {
          _contactCache[rKey] = { email: result.reporter.emailAddress, display_name: result.reporter.displayName, jira_org: orgName };
          _contactCacheTime[rKey] = Date.now();
          _sbUpsert('contact_directory', {
            account_id: result.reporter.accountId || '', display_name: result.reporter.displayName || '',
            email: result.reporter.emailAddress, jira_org: orgName, source: 'jira_api',
            updated_at: new Date().toISOString()
          }, 'account_id').catch(() => {});
        }
      }

      return res.status(200).json(result);
    }

    // ─── ACTION: replyCustomer (JSM visible to customer) ──────
    if (action === 'replyCustomer') {
      const body = req.body || {};
      const key = body.key;
      const text = body.text;
      const isPublic = body.isPublic !== false;
      if (!key || !text) return res.status(400).json({ error: 'Missing key or text' });
      // Try JSM Service Desk request comment (public = Reply to customer)
      try {
        const r = await fetch(`${baseUrl}/rest/servicedesc/1/servicedesk/request/${key}/comment`, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ body: text, public: isPublic })
        });
        if (r.status < 400) return res.status(r.status).json(await r.json());
      } catch(e) { /* fallback */ }
      // Fallback: REST API v2 with sd.public.comment property
      const r2 = await fetch(`${baseUrl}/rest/api/2/issue/${key}/comment`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          body: text,
          properties: isPublic ? [{ key: 'sd.public.comment', value: { internal: false } }] : []
        })
      });
      return res.status(r2.status).json(await r2.json());
    }


        // ─── ACTION: assignable (list users) ─────────────────────
    if (action === 'assignable') {
      const r = await fetch(`${baseUrl}/rest/api/3/user/assignable/search?project=DAC&maxResults=50`, {
        headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
      });
      const users = await r.json();
      const mapped = (Array.isArray(users) ? users : []).map(u => ({
        accountId: u.accountId,
        displayName: u.displayName,
        avatar: (u.avatarUrls || {})['24x24'] || null
      }));
      return res.status(200).json(mapped);
    }

    // ─── ACTION: opsdata (JSM Ops schedules/routing/escalation) ─────
    if (action === 'opsdata') {
      const opsBase = `https://api.atlassian.com/jsm/ops/api/${_CID}/v1`;
      const opsHeaders = { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' };

      const [schedulesR, routingR, escalationsR] = await Promise.all([
        fetch(`${opsBase}/schedules?expand=rotation`, { headers: opsHeaders }),
        fetch(`${opsBase}/teams/${_TID}/routing-rules`, { headers: opsHeaders }),
        fetch(`${opsBase}/teams/${_TID}/escalations`, { headers: opsHeaders })
      ]);
      const [schedules, routing, escalations] = await Promise.all([
        schedulesR.json(), routingR.json(), escalationsR.json()
      ]);

      // Fetch on-call participants for each schedule
      const scheduleVals = schedules.values || [];
      const onCallPromises = scheduleVals.map(s =>
        fetch(`${opsBase}/schedules/${s.id}/on-calls?flat=false`, { headers: opsHeaders }).then(r => r.json())
      );
      const onCallResults = await Promise.all(onCallPromises);

      // Resolve user IDs to display names
      const userIds = new Set();
      scheduleVals.forEach(s => (s.rotations || []).forEach(r => (r.participants || []).forEach(p => { if (p.type === 'user') userIds.add(p.id); })));
      onCallResults.forEach(oc => (oc.onCallParticipants || []).forEach(p => { if (p.type === 'user') userIds.add(p.id); }));

      const userMap = {};
      const jiraApi = `https://api.atlassian.com/ex/jira/${_CID}/rest/api/3`;
      await Promise.all([...userIds].map(async uid => {
        try {
          const r = await fetch(`${jiraApi}/user?accountId=${uid}`, { headers: opsHeaders });
          const d = await r.json();
          userMap[uid] = d.displayName || uid;
        } catch { userMap[uid] = uid; }
      }));

      return res.status(200).json({
        team: '[SOC] Alert Ops',
        teamId: _TID,
        schedules: scheduleVals.map((s, i) => ({
          id: s.id, name: s.name, timezone: s.timezone, enabled: s.enabled,
          rotations: (s.rotations || []).map(r => ({
            id: r.id, name: r.name, type: r.type, length: r.length,
            startDate: r.startDate, endDate: r.endDate,
            participants: (r.participants || []).map(p => ({ type: p.type, id: p.id, name: userMap[p.id] || p.id })),
            timeRestriction: r.timeRestriction
          })),
          onCall: (onCallResults[i]?.onCallParticipants || []).map(p => ({ type: p.type, id: p.id, name: userMap[p.id] || p.id }))
        })),
        routingRules: (routing.values || []).map(r => ({
          id: r.id, name: r.name, isDefault: r.isDefault, order: r.order,
          criteria: r.criteria, timezone: r.timezone,
          timeRestriction: r.timeRestriction || null,
          notify: r.notify
        })),
        escalationPolicies: (escalations.values || []).map(e => ({
          id: e.id, name: e.name, enabled: e.enabled,
          rules: (e.rules || []).map(r => ({
            condition: r.condition, notifyType: r.notifyType, delay: r.delay,
            recipient: r.recipient
          })),
          repeat: e.repeat || null
        })),
        userMap
      });
    }

    // ─── ACTION: dashvisuals (full data for dashboard visuals) ────
    if (action === 'dashvisuals') {
      // Time range support — same mapping as dashboard action
      const timeRange = req.query.timeRange || '24h';
      const timeRangeMap = {
        '1h': '-1h', '4h': '-4h', '12h': '-12h', '24h': '-24h',
        '7d': '-168h', '30d': '-720h'
      };
      const recentJql = timeRangeMap[timeRange] || '-24h';
      const isRelative = recentJql.startsWith('-');
      const createdFilter = isRelative ? ('created >= "' + recentJql + '"') : ('created >= ' + recentJql);

      // Check server-side cache (keyed by time range)
      var cachedVis = _getCached('dashvisuals_' + timeRange);
      if (cachedVis) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cachedVis);
      }
      const B = 'project = DAC AND type = "[System] Incident"';
      const BT = `${B} AND ${createdFilter}`; // time-filtered base

      // Parallel: count queries + fetch recent tickets for distribution analysis
      // Use BT (time-filtered) for totals so numbers change with time picker
      const [
        totalAll, totalOpen, inProgressCount, escalatedCount,
        resolvedAllTime, resolvedWeek,
        p1All, p2All, p3All, p4All,
        recentBatch, weekBatch
      ] = await Promise.all([
        countJql(BT),
        countJql(`${BT} AND status = "Open"`),
        countJql(`${BT} AND status = "In Progress"`),
        countJql(`${BT} AND status = "Escalated"`),
        countJql(`${B} AND status in ("Closed","Completed","Canceled") AND ${createdFilter}`),
        countJql(`${B} AND status in ("Closed","Completed","Canceled") AND updated >= startOfWeek()`),
        countJql(`${BT} AND priority = "P1 - Critical"`),
        countJql(`${BT} AND priority = "P2 - High"`),
        countJql(`${BT} AND priority = "P3 - Medium"`),
        countJql(`${BT} AND priority = "P4 - Low"`),
        searchJql(`${BT} ORDER BY created DESC`,
          ['created','priority','status','customfield_10002'], 200),
        searchJql(`${B} AND created >= -14d ORDER BY created DESC`,
          ['created'], 1000)
      ]);

      // Process recent tickets for distributions
      const issues = (recentBatch.issues || []).map(iss => ({
        created: iss.fields?.created || '',
        priority: (iss.fields?.priority || {}).name || '',
        status: (iss.fields?.status || {}).name || '',
        org: ((iss.fields?.customfield_10002 || [])[0] || {}).name || '\u2014'
      }));

      // Hourly distribution (today, SGT = UTC+8)
      const now = new Date();
      const todayStr = new Date(now.getTime() + 8 * 3600000).toISOString().slice(0, 10);
      const hourlyToday = new Array(24).fill(0);
      issues.forEach(i => {
        if (!i.created) return;
        const d = new Date(i.created);
        const sgtDate = new Date(d.getTime() + 8 * 3600000);
        if (sgtDate.toISOString().slice(0, 10) === todayStr) {
          hourlyToday[sgtDate.getUTCHours()]++;
        }
      });

      // 7-day heatmap (Mon=0 ... Sun=6, each has 24 hourly buckets)
      // Uses dedicated 7-day query (weekBatch) for full coverage
      const heatmap = Array.from({length: 7}, () => new Array(24).fill(0));
      const sevenDaysAgo = new Date(now.getTime() - 14 * 86400000);
      const weekIssues = (weekBatch.issues || []);
      weekIssues.forEach(iss => {
        const created = iss.fields?.created || '';
        if (!created) return;
        const d = new Date(created);
        if (d < sevenDaysAgo) return;
        const sgtD = new Date(d.getTime() + 8 * 3600000);
        const dow = (sgtD.getDay() + 6) % 7; // Mon=0
        const hour = sgtD.getUTCHours();
        heatmap[dow][hour]++;
      });

      // Daily trend (last 14 days)
      const dailyTrend = new Array(14).fill(0);
      issues.forEach(i => {
        if (!i.created) return;
        const d = new Date(i.created);
        const daysAgo = Math.floor((now.getTime() - d.getTime()) / 86400000);
        if (daysAgo >= 0 && daysAgo < 14) dailyTrend[13 - daysAgo]++;
      });

      // Org distribution
      const orgDist = {};
      issues.forEach(i => {
        orgDist[i.org] = (orgDist[i.org] || 0) + 1;
      });

      // Status distribution
      const statusDist = {};
      issues.forEach(i => {
        statusDist[i.status] = (statusDist[i.status] || 0) + 1;
      });

      // Priority distribution across open tickets (from the recent batch)
      const prioDist = { p1: 0, p2: 0, p3: 0, p4: 0 };
      issues.forEach(i => {
        if (i.status === 'Open') {
          if (i.priority.includes('P1')) prioDist.p1++;
          else if (i.priority.includes('P2')) prioDist.p2++;
          else if (i.priority.includes('P3')) prioDist.p3++;
          else if (i.priority.includes('P4')) prioDist.p4++;
        }
      });

      const visResult = {
        totalAll, totalOpen, inProgressCount, escalatedCount,
        resolvedAllTime, resolvedWeek,
        p1All, p2All, p3All, p4All,
        hourlyToday, heatmap, dailyTrend,
        orgDist, statusDist, prioDist,
        issueCount: issues.length
      };
      _setCache('dashvisuals_' + timeRange, visResult);
      return res.status(200).json(visResult);
    }

    // ─── ACTION: telemetry (extended dashboard data) ─────────
    if (action === 'telemetry') {
      // Time range support
      const timeRange = req.query.timeRange || '24h';
      const timeRangeMap = {
        '1h': '-1h', '4h': '-4h', '12h': '-12h', '24h': '-24h',
        '7d': '-168h', '30d': '-720h'
      };
      const recentJql = timeRangeMap[timeRange] || '-24h';
      const isRelative = recentJql.startsWith('-');
      const createdFilter = isRelative ? ('created >= "' + recentJql + '"') : ('created >= ' + recentJql);

      // Check server-side cache (keyed by time range)
      var cachedTele = _getCached('telemetry_' + timeRange);
      if (cachedTele) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cachedTele);
      }
      const B = 'project = DAC AND type = "[System] Incident"';
      const BT = `${B} AND ${createdFilter}`; // time-filtered base
      const now = new Date();
      const queries = {};
      // MTTR proxy: count by status within time range
      queries.inProgress = `${BT} AND status = "In Progress"`;
      queries.escalated = `${BT} AND status = "Escalated"`;
      queries.clientResponded = `${BT} AND status = "Client Responded"`;
      queries.reportedTo = `${BT} AND status = "Reported To"`;
      queries.notified = `${BT} AND status = "Notified"`;
      // Trends
      queries.yesterday = `${B} AND created >= "-2d" AND created < "-1d"`;
      queries.twoDaysAgo = `${B} AND created >= "-3d" AND created < "-2d"`;
      // By priority within time range
      queries.allP1 = `${BT} AND priority = "P1 - Critical"`;
      queries.allP2 = `${BT} AND priority = "P2 - High"`;
      queries.allP3 = `${BT} AND priority = "P3 - Medium"`;
      queries.allP4 = `${BT} AND priority = "P4 - Low"`;
      // Resolved this week
      queries.resolvedWeek = `${B} AND status in ("Closed","Completed","Canceled") AND updated >= startOfWeek()`;
      // Top assignees within time range
      const [counts, recentAssignees] = await Promise.all([
        (async () => {
          const results = {};
          await Promise.all(Object.entries(queries).map(([key, jql]) => countJql(jql).then(c => { results[key] = c; })));
          return results;
        })(),
        searchJql(`${BT} AND assignee is not EMPTY ORDER BY created DESC`, ['assignee','status','priority','created'], 100)
      ]);
      // Compute assignee distribution
      const assigneeCounts = {};
      (recentAssignees.issues || []).forEach(iss => {
        const name = iss.fields?.assignee?.displayName || 'Unknown';
        if (!assigneeCounts[name]) assigneeCounts[name] = {total:0,open:0};
        assigneeCounts[name].total++;
        if ((iss.fields?.status?.name || '') === 'Open') assigneeCounts[name].open++;
      });
      const teleResult = { counts, assigneeCounts };
      _setCache('telemetry_' + timeRange, teleResult);
      return res.status(200).json(teleResult);
    }

    // ─── ACTION: createticket ─────────────────────────────────
    if (action === 'createticket') {
      const body = req.body || {};
      const summary = body.summary;
      const priority = body.priority || 'P3 - Medium';
      const descriptionText = body.description || '';
      if (!summary) return res.status(400).json({ error: 'Missing summary' });
      const payload = {
        fields: {
          project: { key: 'DAC' },
          issuetype: { id: '10011' }, // [System] Incident
          summary: summary,
          priority: { name: priority },
          description: {
            type: 'doc', version: 1,
            content: [{ type: 'paragraph', content: [{ type: 'text', text: descriptionText || 'Created from DACTA SIEMLess' }] }]
          }
        }
      };
      if (body.assigneeId) payload.fields.assignee = { accountId: body.assigneeId };
      const r = await fetch(`${baseUrl}/rest/api/3/issue`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      });
      const result = await r.json();
      return res.status(r.status >= 400 ? r.status : 200).json(result);
    }

    // ─── ACTION: orgMembers (fetch members of a JSM organization) ───
    if (action === 'orgMembers') {
      const orgId = req.query.orgId;
      if (!orgId) return res.status(400).json({ error: 'Missing orgId parameter' });
      
      const members = [];
      let start = 0;
      const limit = 50;
      let isLast = false;
      
      while (!isLast) {
        try {
          const r = await fetch(`${baseUrl}/rest/servicedeskapi/organization/${orgId}/user?start=${start}&limit=${limit}`, {
            headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
          });
          if (r.status === 200) {
            const data = await r.json();
            const values = data.values || [];
            for (const u of values) {
              members.push({
                accountId: u.accountId || '',
                displayName: u.displayName || u.name || '',
                emailAddress: u.emailAddress || '',
                active: u.active !== false
              });
            }
            isLast = data.isLastPage !== false;
            start += limit;
          } else {
            // If API returns error (e.g. 403, 404), break and return what we have
            console.warn(`[orgMembers] API returned ${r.status} for org ${orgId}`);
            break;
          }
        } catch(e) {
          console.warn('[orgMembers] Error:', e.message);
          break;
        }
      }
      
      // For any members without email, try individual user lookup
      const resolvedMembers = await Promise.all(
        members.map(async (m) => {
          if (m.emailAddress && m.emailAddress.indexOf('@') !== -1) return m;
          if (!m.accountId) return m;
          try {
            const ur = await fetch(`${baseUrl}/rest/api/3/user?accountId=${encodeURIComponent(m.accountId)}`, {
              headers: { 'Authorization': `Basic ${auth}`, 'Accept': 'application/json' }
            });
            if (ur.status === 200) {
              const ud = await ur.json();
              if (ud.emailAddress) m.emailAddress = ud.emailAddress;
            }
          } catch(e) { /* skip */ }
          return m;
        })
      );
      
      return res.status(200).json({ members: resolvedMembers, orgId: orgId, count: resolvedMembers.length });
    }

    // ─── ACTION: organizations ───────────────────────────────
    if (action === 'organizations') {
      // Get all unique JSM organizations from DAC project tickets
      let allOrgs = {};
      let npt = null;
      let page = 0;
      while (page < 50) {
        const payload = { 
          jql: 'project = DAC ORDER BY created DESC', 
          fields: ['customfield_10002', 'created'],
          maxResults: 100 
        };
        if (npt) payload.nextPageToken = npt;
        const r = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify(payload)
        });
        const d = await r.json();
        for (const issue of (d.issues || [])) {
          const orgs = issue.fields?.customfield_10002 || [];
          const created = issue.fields?.created || '';
          for (const org of orgs) {
            if (!allOrgs[org.id]) {
              allOrgs[org.id] = { jira_org_id: org.id, name: org.name, ticket_count: 0, latest_ticket_date: created };
            }
            allOrgs[org.id].ticket_count++;
            if (created > allOrgs[org.id].latest_ticket_date) {
              allOrgs[org.id].latest_ticket_date = created;
            }
          }
        }
        page++;
        if (d.isLast || !d.nextPageToken) break;
        npt = d.nextPageToken;
      }
      return res.status(200).json({ organizations: Object.values(allOrgs) });
    }

    // ─── ACTION: contactDirectory (get all cached contacts) ────
    if (action === 'contactDirectory') {
      const contacts = await _sbGet('contact_directory', 'select=*');
      return res.status(200).json({ contacts: contacts || [] });
    }

    // ─── ACTION: getEscalationMatrix (load per-client escalation config) ────
    if (action === 'getEscalationMatrix') {
      const orgId = req.query.orgId || '';
      // Try Supabase first
      let matrix = null;
      if (orgId) {
        const rows = await _sbGet('escalation_matrix', `select=*&org_id=eq.${encodeURIComponent(orgId)}`);
        if (rows && rows.length > 0) matrix = rows[0];
      }
      // Fallback to server cache
      if (!matrix && orgId) {
        const cacheKey = 'esc_matrix_' + orgId;
        const cached = _getCached(cacheKey);
        if (cached) matrix = cached;
      }
      return res.status(200).json({ matrix: matrix || null });
    }

    // ─── ACTION: getAllEscalationMatrices (load all client configs) ────
    if (action === 'getAllEscalationMatrices') {
      const rows = await _sbGet('escalation_matrix', 'select=*');
      return res.status(200).json({ matrices: rows || [] });
    }

    // ─── ACTION: saveEscalationMatrix (upsert per-client escalation config) ────
    if (action === 'saveEscalationMatrix') {
      const body = req.body || {};
      const { orgId, orgName, contacts, sla, escalationTiers, notes } = body;
      if (!orgId) return res.status(400).json({ error: 'Missing orgId' });
      const row = {
        org_id: orgId,
        org_name: orgName || '',
        contacts: JSON.stringify(contacts || []),
        sla: JSON.stringify(sla || {}),
        escalation_tiers: JSON.stringify(escalationTiers || []),
        notes: notes || '',
        updated_at: new Date().toISOString()
      };
      // Try Supabase
      const result = await _sbUpsert('escalation_matrix', row, 'org_id');
      // Always update server cache
      const cacheKey = 'esc_matrix_' + orgId;
      _serverCache[cacheKey] = row;
      _serverCacheTime[cacheKey] = Date.now();
      return res.status(200).json({ success: true, matrix: result || row });
    }

    // ─── ACTION: deleteEscalationContact (remove a contact from matrix) ────
    if (action === 'deleteEscalationContact') {
      // This is handled client-side by re-saving the full matrix without the contact
      return res.status(200).json({ success: true, note: 'Use saveEscalationMatrix with updated contacts array' });
    }

    // ─── ACTION: saveContact (upsert a contact into directory) ────
    if (action === 'saveContact') {
      const body = req.body || {};
      const { accountId, displayName, emailAddress, jiraOrg, source } = body;
      if (!accountId && !displayName) return res.status(400).json({ error: 'Missing accountId or displayName' });
      const contact = {
        account_id: accountId || '',
        display_name: displayName || '',
        email: emailAddress || '',
        jira_org: jiraOrg || '',
        source: source || 'manual', // 'jira_api', 'manual', 'analyst'
        updated_at: new Date().toISOString()
      };
      const result = await _sbUpsert('contact_directory', contact, 'account_id');
      // Also update server-side cache
      _setCache('contact_' + (accountId || displayName), contact);
      return res.status(200).json({ success: true, contact: result || contact });
    }

    // ─── ACTION: lookupContact (find contact by accountId or name) ────
    if (action === 'lookupContact') {
      const accountId = req.query.accountId || '';
      const name = req.query.name || '';
      // Check server cache first
      const cacheKey = 'contact_' + (accountId || name);
      const cached = _getCached(cacheKey);
      if (cached) return res.status(200).json({ contact: cached, source: 'cache' });
      // Try Supabase
      let contacts = [];
      if (accountId) {
        contacts = await _sbGet('contact_directory', `select=*&account_id=eq.${encodeURIComponent(accountId)}`);
      } else if (name) {
        contacts = await _sbGet('contact_directory', `select=*&display_name=eq.${encodeURIComponent(name)}`);
      }
      if (contacts && contacts.length > 0) {
        _setCache(cacheKey, contacts[0]);
        return res.status(200).json({ contact: contacts[0], source: 'directory' });
      }
      return res.status(200).json({ contact: null, source: 'none' });
    }

    return res.status(400).json({ error: 'Unknown action' });

  } catch (err) {
    console.error('Jira proxy error:', err);
    return res.status(500).json({ error: 'Internal proxy error', message: err.message });
  }
}

// Normalize a Jira issue into a flat, frontend-friendly object
function normalizeIssue(issue) {
  const f = issue.fields || {};
  const orgs = (f.customfield_10002 || []).map(o => o.name);
  const severity = f.customfield_10050;
  const assignee = f.assignee;
  const reporter = f.reporter;
  const workCat = f.customfield_10038;

  const requestTypeData = f.customfield_10010;
  const requestTypeName = requestTypeData?.requestType?.name || '';
  const issueTypeName = (f.issuetype || {}).name || '';
  const statusName = (f.status || {}).name || 'Unknown';
  const queueOrigin = 'SOC Alerts';

  return {
    key: issue.key,
    id: issue.id,
    summary: f.summary || '',
    status: statusName,
    statusCat: (f.status || {}).statusCategory?.key || '',
    priority: (f.priority || {}).name || 'None',
    priorityShort: ((f.priority || {}).name || '').split(' - ')[0] || '',
    assignee: assignee ? assignee.displayName : 'Unassigned',
    assigneeId: assignee ? assignee.accountId : null,
    assigneeAvatar: assignee ? (assignee.avatarUrls || {})['24x24'] : null,
    reporter: reporter ? reporter.displayName : 'Unknown',
    created: f.created || '',
    updated: f.updated || '',
    issueType: issueTypeName,
    labels: f.labels || [],
    orgs,
    org: orgs[0] || '—',
    severity: severity && typeof severity === 'object' ? (severity.value || '') : (severity || ''),
    useCase: f.customfield_10072 || '',
    threatLib: f.customfield_10068 || '',
    workCategory: workCat && typeof workCat === 'object' ? (workCat.value || '') : (workCat || ''),
    reportedTo: f.customfield_10406 && typeof f.customfield_10406 === 'object' ? (f.customfield_10406.value || '') : '',
    slaAcknowledge: f.customfield_10472 || null,
    slaRespond: f.customfield_10473 || null,
    slaInvestigate: f.customfield_10573 || null,
    queueOrigin,
    requestType: requestTypeName || issueTypeName.replace('[System] ', ''),
    source: 'Jira'
  };
}
