// Vercel Serverless Function — Jira API Proxy
// Handles CORS, authentication, and pagination for Jira Cloud REST API v3
// Credentials stored as base64-encoded constants (server-side only, never exposed to browser)

const _JE = 'c2FybmllLmhvQGRhY3RhZ2xvYmFsLmNvbQ=='; // email
const _JT = 'QVRBVFQzeEZmR0YwS3FTUXExdGZIT0hmVlNiWlVTQ3ZNMnFCVFRBazlQUndnaElvT0pUOVRqOFZFZjRzdjllVEp0cGxGWW5vSkRsakFWU2RTdC1aYUJZZ2xIWl9nQzUyenItSFM4czJDWTNCZUJCbWh6czVVSEROLVNsOVZZWlk4M1g0YW9rSm1TVFQ3Tjh1RXlhSHlSOFhGbkVMWGZaWGJnNWR2cFlXcTFxNW83ZW1jQzhnSWhrPThFMzU2NkY2'; // token
const _JI = 'dactaglobal-sg.atlassian.net';
const _CID = '018ce0b3-5943-4d3f-9542-d005b0ce2872'; // Atlassian Cloud ID
const _TID = 'de6cdba5-d36e-486c-8ace-a41c3eb69b8b'; // [SOC] Alert Ops team ID

// Server-side in-memory cache (survives across warm invocations on same Vercel instance)
const _serverCache = {};
const _serverCacheTime = {};
const _SERVER_CACHE_TTL = 30000; // 30 seconds — balances freshness vs. speed

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

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Credentials (env vars override encoded defaults)
  const JIRA_EMAIL = process.env.JIRA_EMAIL || _d(_JE);
  const JIRA_TOKEN = process.env.JIRA_TOKEN || _d(_JT);
  const JIRA_INSTANCE = process.env.JIRA_INSTANCE || _JI;

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
      // Check server-side cache first
      var cached = _getCached('dashboard');
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
        countJql(`${B} AND status="Closed" AND updated >= startOfDay()`),
        countJql(`${B} AND status="Canceled" AND updated >= startOfDay()`),
        countJql(`${B} AND status="Completed" AND updated >= startOfDay()`),
        countJql(`${B} AND created >= startOfDay()`),
        countJql(`${B} AND created >= startOfWeek()`),
        searchJql(`${B} ORDER BY created DESC`, [
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
      _setCache('dashboard', dashResult);
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
      // Check server-side cache first
      var cachedVis = _getCached('dashvisuals');
      if (cachedVis) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cachedVis);
      }
      const B = 'project = DAC AND type = "[System] Incident"';

      // Parallel: count queries + fetch 200 recent tickets for distribution analysis
      const [
        totalAll, totalOpen, inProgressCount, escalatedCount,
        resolvedAllTime, resolvedWeek,
        p1All, p2All, p3All, p4All,
        recentBatch, weekBatch
      ] = await Promise.all([
        countJql(B),
        countJql(`${B} AND status = "Open"`),
        countJql(`${B} AND status = "In Progress"`),
        countJql(`${B} AND status = "Escalated"`),
        countJql(`${B} AND status in ("Closed","Completed","Canceled")`),
        countJql(`${B} AND status in ("Closed","Completed","Canceled") AND updated >= startOfWeek()`),
        countJql(`${B} AND priority = "P1 - Critical"`),
        countJql(`${B} AND priority = "P2 - High"`),
        countJql(`${B} AND priority = "P3 - Medium"`),
        countJql(`${B} AND priority = "P4 - Low"`),
        searchJql(`${B} ORDER BY created DESC`,
          ['created','priority','status','customfield_10002'], 200),
        searchJql(`${B} AND created >= -7d ORDER BY created DESC`,
          ['created'], 500)
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
      const sevenDaysAgo = new Date(now.getTime() - 7 * 86400000);
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
      _setCache('dashvisuals', visResult);
      return res.status(200).json(visResult);
    }

    // ─── ACTION: telemetry (extended dashboard data) ─────────
    if (action === 'telemetry') {
      // Check server-side cache first
      var cachedTele = _getCached('telemetry');
      if (cachedTele) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cachedTele);
      }
      const B = 'project = DAC AND type = "[System] Incident"';
      const now = new Date();
      const queries = {};
      // MTTR proxy: avg time tickets stay open (count by status)
      queries.inProgress = `${B} AND status = "In Progress"`;
      queries.escalated = `${B} AND status = "Escalated"`;
      queries.clientResponded = `${B} AND status = "Client Responded"`;
      queries.reportedTo = `${B} AND status = "Reported To"`;
      queries.notified = `${B} AND status = "Notified"`;
      // Trends
      queries.yesterday = `${B} AND created >= "-2d" AND created < "-1d"`;
      queries.twoDaysAgo = `${B} AND created >= "-3d" AND created < "-2d"`;
      // By priority (all)
      queries.allP1 = `${B} AND priority = "P1 - Critical"`;
      queries.allP2 = `${B} AND priority = "P2 - High"`;
      queries.allP3 = `${B} AND priority = "P3 - Medium"`;
      queries.allP4 = `${B} AND priority = "P4 - Low"`;
      // Resolved this week
      queries.resolvedWeek = `${B} AND status in ("Closed","Completed","Canceled") AND updated >= startOfWeek()`;
      // Top assignees (fetch recent with assignee)
      const [counts, recentAssignees] = await Promise.all([
        (async () => {
          const results = {};
          await Promise.all(Object.entries(queries).map(([key, jql]) => countJql(jql).then(c => { results[key] = c; })));
          return results;
        })(),
        searchJql(`${B} AND assignee is not EMPTY ORDER BY created DESC`, ['assignee','status','priority','created'], 100)
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
      _setCache('telemetry', teleResult);
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

    return res.status(400).json({ error: 'Unknown action. Use: dashboard, triage, issue, comments, search, counts, transitions, transition, assign, addcomment, assignable, createticket, opsdata, dashvisuals' });

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
