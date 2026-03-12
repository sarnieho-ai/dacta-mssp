// Jira Webhook Handler — receives push notifications from Jira Cloud
// Configure webhook in Jira: Settings → System → WebHooks → Add
// URL: https://dacta-siemless.vercel.app/api/jira-webhook
// Events: Issue Created, Issue Updated
// JQL Filter: project = DAC AND type = "[System] Incident"

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const payload = req.body;
    if (!payload || !payload.webhookEvent) {
      return res.status(400).json({ error: 'Invalid webhook payload' });
    }

    const event = payload.webhookEvent;
    const issue = payload.issue;

    if (!issue || !issue.key) {
      return res.status(200).json({ ok: true, message: 'No issue in payload, ignoring' });
    }

    const key = issue.key;
    const fields = issue.fields || {};
    const summary = fields.summary || '';
    const priority = fields.priority ? fields.priority.name : 'P3 - Medium';
    const status = fields.status ? fields.status.name : 'Open';
    const created = fields.created || new Date().toISOString();
    const org = fields.customfield_10002 ? (fields.customfield_10002[0] ? fields.customfield_10002[0].name : '') : '';

    // Extract priority short code
    let priorityShort = 'P3';
    const priName = (priority || '').toUpperCase();
    if (priName.includes('P1') || priName.includes('CRITICAL') || priName.includes('HIGHEST')) priorityShort = 'P1';
    else if (priName.includes('P2') || priName.includes('HIGH')) priorityShort = 'P2';
    else if (priName.includes('P4') || priName.includes('LOW') || priName.includes('LOWEST')) priorityShort = 'P4';

    console.log(`[JiraWebhook] ${event}: ${key} (${priorityShort}) — ${summary.substring(0, 60)}`);

    // Return ticket data in a normalized format — the frontend will poll this
    // via the webhook-events endpoint or SSE in future
    return res.status(200).json({
      ok: true,
      event: event,
      ticket: {
        key,
        summary,
        priority: priorityShort,
        status,
        org,
        created,
        timestamp: new Date().toISOString()
      }
    });

  } catch (err) {
    console.error('[JiraWebhook] Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
}
