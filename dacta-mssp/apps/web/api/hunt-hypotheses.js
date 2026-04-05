// Vercel Serverless Function — AI Hunt Hypothesis Generator
// Lightweight endpoint: takes IOC+actor context, returns JSON hypotheses
// Uses Haiku for fast, cheap hypothesis generation

const { setCors, requireAuth } = require('./lib/auth');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  // Auth check — requireAuth returns user on success, null on failure (sends 401)
  const user = await requireAuth(req, res);
  if (!user) return;

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY not configured' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { org_name, sector, ioc_summary, actor_summary } = body;

    if (!ioc_summary) {
      return res.status(400).json({ error: 'ioc_summary is required' });
    }

    const systemPrompt = `You are an expert SOC threat hunter generating actionable hunt hypotheses for a specific organization.
You will be given live IOC data and threat actor intelligence. Generate 3-5 hunt hypotheses that are SPECIFIC to this organization's industry and threat landscape.
Each hypothesis must include a concrete Elastic/SIEM query (ECS field names) that a SOC analyst can copy-paste.
Focus on the intersection of the IOCs, the actors targeting this sector, and the org's unique attack surface.

RESPOND ONLY WITH A VALID JSON ARRAY — no markdown, no backticks, no explanation outside the JSON.
Schema: [{"title": "string", "severity": "critical|high|medium", "mitre": "TXXXX.XXX — Technique Name", "description": "2-3 sentences explaining what to hunt for and why it matters for THIS org specifically", "ioc": "specific IOC value or pattern from the data", "siem_query": "Elastic/ECS query syntax", "hunt_scope": "which log sources to check"}]

Guidelines:
- For gaming/hospitality: focus on POS malware, payment systems, guest data exfiltration, casino management systems, lateral movement through hotel networks
- For financial services: focus on SWIFT/payment fraud, ATM jackpotting, account takeover, insider trading data theft, supply chain attacks on banking infra
- For professional services: focus on client data exfiltration, legal privilege exploitation, M&A data theft, email compromise targeting advisory clients
- Each hypothesis must reference actual IOC values from the provided data
- SIEM queries must use ECS field names (process.name, destination.ip, url.domain, file.hash.*, dns.question.name, etc.)`;

    const userContent = `Organization: ${org_name || 'Unknown'}
Sector: ${sector || 'Multi-Sector'}

IOC SUMMARY:
${ioc_summary}

THREAT ACTORS TARGETING THIS ORG:
${actor_summary || 'No specific threat actors identified for this org.'}`;

    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 2000,
        system: systemPrompt,
        messages: [{ role: 'user', content: userContent }]
      })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('[HuntHyp] Claude API error:', resp.status, errText);
      return res.status(502).json({ error: 'AI service error: ' + resp.status });
    }

    const data = await resp.json();
    const text = data.content?.[0]?.text || '';

    // Parse JSON from response
    let hypotheses;
    try {
      const cleaned = text.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      hypotheses = JSON.parse(cleaned);
    } catch (e) {
      // Try to extract JSON array
      const m = text.match(/\[\s*\{[\s\S]*\}\s*\]/);
      if (m) {
        hypotheses = JSON.parse(m[0]);
      } else {
        return res.status(200).json({ hypotheses: [], raw: text, error: 'Could not parse AI response' });
      }
    }

    return res.status(200).json({ hypotheses: hypotheses });

  } catch (err) {
    console.error('[HuntHyp] Error:', err);
    return res.status(500).json({ error: err.message });
  }
};
