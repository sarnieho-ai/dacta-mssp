// Vercel Serverless Function — Jira API Proxy
// Handles CORS, authentication, and pagination for Jira Cloud REST API v3
// Credentials stored as base64-encoded constants (server-side only, never exposed to browser)

const _JE = 'c2FybmllLmhvQGRhY3RhZ2xvYmFsLmNvbQ=='; // email
const _JT = 'QVRBVFQzeEZmR0YwS3FTUXExdGZIT0hmVlNiWlVTQ3ZNMnFCVFRBazlQUndnaElvT0pUOVRqOFZFZjRzdjllVEp0cGxGWW5vSkRsakFWU2RTdC1aYUJZZ2xIWl9nQzUyenItSFM4czJDWTNCZUJCbWh6czVVSEROLVNsOVZZWlk4M1g0YW9rSm1TVFQ3Tjh1RXlhSHlSOFhGbkVMWGZaWGJnNWR2cFlXcTFxNW83ZW1jQzhnSWhrPThFMzU2NkY2'; // token
const _JI = 'dactaglobal-sg.atlassian.net';

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
    const { action } = req.query;

    // ─── ACTION: dashboard ────────────────────────────────────
    if (action === 'dashboard') {
      const B = 'project = DAC AND ("request type" = "Elastic Alerts (DAC)" OR (status = Open AND "request type" != "Elastic Alerts (DAC)") OR status = "Client Responded" OR (Organizations = "DG_Demo Client" AND resolution = Unresolved) OR (Organizations = "Dacta Global" AND status = Escalated) OR issuetype in ("[System] Incident", "Incident ticket"))';
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

      return res.status(200).json({
        kpi: {
          open: openCount, p1: p1Count, p2: p2Count, p3: p3Count, p4: p4Count,
          closedToday: closedTodayCount, canceledToday: canceledTodayCount,
          completedToday: completedTodayCount,
          todayNew: todayCount, weekNew: weekCount,
          resolvedToday: closedTodayCount + completedTodayCount + canceledTodayCount
        },
        recentTickets: (recentData.issues || []).map(normalizeIssue)
      });
    }

    // ─── ACTION: triage ───────────────────────────────────────
    if (action === 'triage') {
      const body = req.body || {};
      let jqlParts = ['project = DAC AND ("request type" = "Elastic Alerts (DAC)" OR (status = Open AND "request type" != "Elastic Alerts (DAC)") OR status = "Client Responded" OR (Organizations = "DG_Demo Client" AND resolution = Unresolved) OR (Organizations = "Dacta Global" AND status = Escalated) OR issuetype in ("[System] Incident", "Incident ticket"))'];

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
      const body = req.body || {};
      const data = await searchJql(
        body.jql || 'project = DAC AND ("request type" = "Elastic Alerts (DAC)" OR (status = Open AND "request type" != "Elastic Alerts (DAC)") OR status = "Client Responded" OR (Organizations = "DG_Demo Client" AND resolution = Unresolved) OR (Organizations = "Dacta Global" AND status = Escalated) OR issuetype in ("[System] Incident", "Incident ticket")) ORDER BY created DESC',
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

    return res.status(400).json({ error: 'Unknown action. Use: dashboard, triage, issue, comments, search, counts, transitions, transition, assign, addcomment, assignable' });

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

  // Compute queue origin from request type + issuetype + status + org
  const requestTypeData = f.customfield_10010;
  const requestTypeName = requestTypeData?.requestType?.name || '';
  const issueTypeName = (f.issuetype || {}).name || '';
  const statusName = (f.status || {}).name || 'Unknown';

  let queueOrigin = 'General';
  if (requestTypeName === 'Elastic Alerts' || requestTypeName === 'Elastic Alerts (DAC)') {
    queueOrigin = 'Elastic Alerts';
  } else if (issueTypeName.includes('Incident')) {
    queueOrigin = 'SOC Alerts';
  }
  // Overlay queue context from status / org
  if (statusName === 'Client Responded') queueOrigin = 'Client Responded';
  if (statusName === 'Escalated') queueOrigin = 'Escalated';
  if (statusName === 'In Progress') queueOrigin = queueOrigin === 'General' ? 'In Progress' : queueOrigin;
  const orgName = orgs[0] || '';
  if (orgName === 'DG_Demo Client') queueOrigin = 'Demo Client';

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
