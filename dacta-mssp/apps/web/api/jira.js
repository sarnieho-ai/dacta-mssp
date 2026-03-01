// Vercel Serverless Function — Jira API Proxy
// Handles CORS, authentication, and pagination for Jira Cloud REST API v3
// Credentials are stored as Vercel environment variables (JIRA_EMAIL, JIRA_TOKEN, JIRA_INSTANCE)

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const JIRA_EMAIL = process.env.JIRA_EMAIL;
  const JIRA_TOKEN = process.env.JIRA_TOKEN;
  const JIRA_INSTANCE = process.env.JIRA_INSTANCE || 'dactaglobal-sg.atlassian.net';

  if (!JIRA_EMAIL || !JIRA_TOKEN) {
    return res.status(500).json({ error: 'Jira credentials not configured. Set JIRA_EMAIL and JIRA_TOKEN environment variables.' });
  }

  const auth = Buffer.from(`${JIRA_EMAIL}:${JIRA_TOKEN}`).toString('base64');
  const baseUrl = `https://${JIRA_INSTANCE}`;

  try {
    const { action } = req.query;

    // ─── ACTION: search ───────────────────────────────────────
    // POST body: { jql, fields, maxResults, nextPageToken }
    if (action === 'search') {
      const body = req.body || {};
      const jql = body.jql || 'project=DAC ORDER BY created DESC';
      const fields = body.fields || ['summary', 'status', 'priority', 'assignee', 'reporter', 'created', 'updated', 'issuetype', 'labels', 'customfield_10002', 'customfield_10050', 'customfield_10072', 'customfield_10038'];
      const maxResults = body.maxResults || 50;
      const payload = { jql, fields, maxResults };
      if (body.nextPageToken) payload.nextPageToken = body.nextPageToken;

      const resp = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const data = await resp.json();
      return res.status(resp.status).json(data);
    }

    // ─── ACTION: count ────────────────────────────────────────
    // Uses pagination to count total issues matching JQL
    // POST body: { jql }
    if (action === 'count') {
      const body = req.body || {};
      const jql = body.jql || 'project=DAC';
      let total = 0;
      let nextPageToken = null;
      let pages = 0;

      while (pages < 100) {
        const payload = { jql, maxResults: 100, fields: ['key'] };
        if (nextPageToken) payload.nextPageToken = nextPageToken;

        const resp = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${auth}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify(payload)
        });

        const data = await resp.json();
        const issues = data.issues || [];
        total += issues.length;
        pages++;

        if (data.isLast || !data.nextPageToken) break;
        nextPageToken = data.nextPageToken;
      }

      return res.status(200).json({ total, pages });
    }

    // ─── ACTION: counts ───────────────────────────────────────
    // Batch count: runs multiple JQL queries in parallel
    // POST body: { queries: { key: jql, ... } }
    if (action === 'counts') {
      const body = req.body || {};
      const queries = body.queries || {};
      const results = {};

      // Helper: count single JQL (paginated)
      async function countJql(jql) {
        let total = 0;
        let nextPageToken = null;
        let pages = 0;
        while (pages < 100) {
          const payload = { jql, maxResults: 100, fields: ['key'] };
          if (nextPageToken) payload.nextPageToken = nextPageToken;
          const resp = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
            method: 'POST',
            headers: {
              'Authorization': `Basic ${auth}`,
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
          });
          const data = await resp.json();
          total += (data.issues || []).length;
          pages++;
          if (data.isLast || !data.nextPageToken) break;
          nextPageToken = data.nextPageToken;
        }
        return total;
      }

      // Run all counts in parallel
      const entries = Object.entries(queries);
      const promises = entries.map(([key, jql]) => countJql(jql).then(total => ({ key, total })));
      const countResults = await Promise.all(promises);
      countResults.forEach(({ key, total }) => { results[key] = total; });

      return res.status(200).json(results);
    }

    // ─── ACTION: issue ────────────────────────────────────────
    // GET: ?action=issue&key=DAC-12345
    if (action === 'issue') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });

      const resp = await fetch(`${baseUrl}/rest/api/3/issue/${key}?expand=changelog,renderedFields`, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json'
        }
      });

      const data = await resp.json();
      return res.status(resp.status).json(data);
    }

    // ─── ACTION: comments ─────────────────────────────────────
    if (action === 'comments') {
      const key = req.query.key;
      if (!key) return res.status(400).json({ error: 'Missing key parameter' });

      const resp = await fetch(`${baseUrl}/rest/api/3/issue/${key}/comment`, {
        headers: {
          'Authorization': `Basic ${auth}`,
          'Accept': 'application/json'
        }
      });

      const data = await resp.json();
      return res.status(resp.status).json(data);
    }

    // ─── ACTION: dashboard ────────────────────────────────────
    // All-in-one: fetches KPI counts + recent tickets + org breakdown
    if (action === 'dashboard') {
      const BASE_JQL = 'project=DAC';

      // Parallel fetch: counts + recent tickets
      async function countJql(jql) {
        let total = 0;
        let npt = null;
        let pg = 0;
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

      const [
        openCount,
        p1Count,
        p2Count,
        p3Count,
        p4Count,
        closedTodayCount,
        canceledTodayCount,
        completedTodayCount,
        todayCount,
        weekCount,
        recentTickets
      ] = await Promise.all([
        countJql(`${BASE_JQL} AND status="Open"`),
        countJql(`${BASE_JQL} AND status="Open" AND priority="P1 - Critical"`),
        countJql(`${BASE_JQL} AND status="Open" AND priority="P2 - High"`),
        countJql(`${BASE_JQL} AND status="Open" AND priority="P3 - Medium"`),
        countJql(`${BASE_JQL} AND status="Open" AND priority="P4 - Low"`),
        countJql(`${BASE_JQL} AND status="Closed" AND updated >= startOfDay()`),
        countJql(`${BASE_JQL} AND status="Canceled" AND updated >= startOfDay()`),
        countJql(`${BASE_JQL} AND status="Completed" AND updated >= startOfDay()`),
        countJql(`${BASE_JQL} AND created >= startOfDay()`),
        countJql(`${BASE_JQL} AND created >= startOfWeek()`),
        // Recent 20 tickets for the dashboard feed
        fetch(`${baseUrl}/rest/api/3/search/jql`, {
          method: 'POST',
          headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({
            jql: `${BASE_JQL} ORDER BY created DESC`,
            maxResults: 20,
            fields: ['summary', 'status', 'priority', 'assignee', 'created', 'updated', 'issuetype', 'labels', 'customfield_10002', 'customfield_10050', 'customfield_10072', 'customfield_10038']
          })
        }).then(r => r.json())
      ]);

      return res.status(200).json({
        kpi: {
          open: openCount,
          p1: p1Count,
          p2: p2Count,
          p3: p3Count,
          p4: p4Count,
          closedToday: closedTodayCount,
          canceledToday: canceledTodayCount,
          completedToday: completedTodayCount,
          todayNew: todayCount,
          weekNew: weekCount,
          resolvedToday: closedTodayCount + completedTodayCount + canceledTodayCount
        },
        recentTickets: (recentTickets.issues || []).map(normalizeIssue)
      });
    }

    // ─── ACTION: triage ───────────────────────────────────────
    // Fetches triage queue with optional filters
    // POST body: { status, priority, org, assignee, maxResults, nextPageToken }
    if (action === 'triage') {
      const body = req.body || {};
      let jqlParts = ['project=DAC'];

      if (body.status && body.status !== 'all') {
        jqlParts.push(`status="${body.status}"`);
      }
      if (body.priority && body.priority !== 'all') {
        jqlParts.push(`priority="${body.priority}"`);
      }
      if (body.org && body.org !== 'all') {
        jqlParts.push(`"Organizations" = "${body.org}"`);
      }
      if (body.assignee && body.assignee !== 'all') {
        if (body.assignee === 'Unassigned') {
          jqlParts.push('assignee is EMPTY');
        } else {
          jqlParts.push(`assignee = "${body.assignee}"`);
        }
      }
      if (body.label && body.label !== 'all') {
        jqlParts.push(`labels = "${body.label}"`);
      }
      if (body.search) {
        jqlParts.push(`summary ~ "${body.search}"`);
      }

      const jql = jqlParts.join(' AND ') + ' ORDER BY created DESC';
      const payload = {
        jql,
        maxResults: body.maxResults || 50,
        fields: ['summary', 'status', 'priority', 'assignee', 'reporter', 'created', 'updated', 'issuetype', 'labels', 'customfield_10002', 'customfield_10050', 'customfield_10072', 'customfield_10068', 'customfield_10038', 'customfield_10406', 'customfield_10472', 'customfield_10473', 'customfield_10573']
      };
      if (body.nextPageToken) payload.nextPageToken = body.nextPageToken;

      const resp = await fetch(`${baseUrl}/rest/api/3/search/jql`, {
        method: 'POST',
        headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await resp.json();
      return res.status(200).json({
        issues: (data.issues || []).map(normalizeIssue),
        isLast: data.isLast,
        nextPageToken: data.nextPageToken
      });
    }

    return res.status(400).json({ error: 'Unknown action. Use: search, count, counts, issue, comments, dashboard, triage' });

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

  return {
    key: issue.key,
    id: issue.id,
    summary: f.summary || '',
    status: (f.status || {}).name || 'Unknown',
    statusCat: (f.status || {}).statusCategory?.key || '',
    priority: (f.priority || {}).name || 'None',
    priorityShort: ((f.priority || {}).name || '').split(' - ')[0] || '',
    assignee: assignee ? assignee.displayName : 'Unassigned',
    assigneeAvatar: assignee ? assignee.avatarUrls?.['24x24'] : null,
    reporter: reporter ? reporter.displayName : 'Unknown',
    created: f.created || '',
    updated: f.updated || '',
    issueType: (f.issuetype || {}).name || '',
    labels: f.labels || [],
    orgs: orgs,
    org: orgs[0] || '—',
    severity: severity && typeof severity === 'object' ? (severity.value || '') : (severity || ''),
    useCase: f.customfield_10072 || '',
    threatLib: f.customfield_10068 || '',
    workCategory: workCat && typeof workCat === 'object' ? (workCat.value || '') : (workCat || ''),
    reportedTo: f.customfield_10406 && typeof f.customfield_10406 === 'object' ? (f.customfield_10406.value || '') : '',
    slaAcknowledge: f.customfield_10472 || null,
    slaRespond: f.customfield_10473 || null,
    slaInvestigate: f.customfield_10573 || null,
    source: 'Jira'
  };
}
