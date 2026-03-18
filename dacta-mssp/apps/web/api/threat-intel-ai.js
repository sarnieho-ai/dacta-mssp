// Vercel Serverless Function — Threat Intel AI Analyzer
// Uses Anthropic Claude to extract entities and generate SIGMA rules from threat reports
// Required env var: ANTHROPIC_API_KEY

const { setCors, requireAuth } = require('./lib/auth');
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

async function callClaude(systemPrompt, userPrompt, maxTokens = 2048) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: maxTokens,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    })
  });
  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Claude API error (${resp.status}): ${err}`);
  }
  const data = await resp.json();
  return (data.content && data.content[0]) ? data.content[0].text : '';
}

// ── Action: extract_entities ──
// Extract APT groups, CVEs, malware, techniques, vulnerabilities, tools from report text
async function extractEntities(reportName, reportText) {
  const system = `You are a senior cyber threat intelligence analyst. Extract structured entities from threat intelligence reports. Return ONLY valid JSON, no markdown fences.`;
  const user = `Analyze this threat intelligence report and extract all mentioned entities.

Report Title: ${reportName}
Report Content: ${reportText}

Return a JSON object with these arrays (each item is a string). Include ONLY entities explicitly mentioned or strongly implied:
{
  "apt_groups": ["LAPSUS$", "APT29", ...],
  "malware": ["Cobalt Strike", "Mimikatz", ...],
  "cves": ["CVE-2024-1234", ...],
  "techniques": ["Credential Dumping", "Spear Phishing", ...],
  "mitre_ids": ["T1003", "T1566.001", ...],
  "vulnerabilities": ["Ivanti EPMM RCE", "Next.js middleware bypass", ...],
  "tools": ["PowerShell", "PsExec", ...],
  "target_sectors": ["Financial Services", "Government", ...],
  "iocs": ["evil.com", "192.168.1.1", "abc123hash", ...]
}

Only include categories that have at least one entity. Be precise — do not hallucinate entities not in the text.`;

  const raw = await callClaude(system, user, 1024);
  // Parse JSON from response (handle potential markdown fences)
  let cleaned = raw.trim();
  if (cleaned.startsWith('```')) {
    cleaned = cleaned.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
  }
  return JSON.parse(cleaned);
}

// ── Action: generate_sigma ──
// Generate a complete, production-quality SIGMA rule from a threat report
async function generateSigmaRule(reportName, reportText, entities) {
  const system = `You are an expert detection engineer who writes production-quality Sigma rules. You specialize in creating actionable detection rules from threat intelligence reports. Return ONLY the raw YAML Sigma rule, no markdown fences, no explanations before or after.`;
  
  const entityContext = entities ? `\nExtracted entities: ${JSON.stringify(entities)}` : '';
  
  const user = `Generate a complete, production-quality Sigma rule based on this threat intelligence report.

Report Title: ${reportName}
Report Content: ${reportText}${entityContext}

Requirements:
1. The rule MUST be directly actionable — real field names, real detection values
2. Use the most relevant technique/threat from the report
3. Include proper logsource (category + product)
4. Include realistic detection logic with selection criteria
5. Include meaningful false positives
6. Include MITRE ATT&CK tags where applicable
7. Set appropriate severity level
8. Author should be "DACTA AI Engine"
9. Date should be today: ${new Date().toISOString().split('T')[0].replace(/-/g, '/')}
10. Status should be "experimental"
11. Description should explain WHAT the rule detects and WHY (referencing the threat report)

Return ONLY the raw YAML. No markdown fences. No explanations.`;

  return await callClaude(system, user, 2048);
}

// ── Action: generate_rule_rationale ──
// Generate a human-readable analysis of what detection rules can be derived
async function generateRationale(reportName, reportText, entities) {
  const system = `You are a senior SOC detection engineer explaining threat intelligence to analysts. Be concise, specific, and actionable.`;
  
  const entityContext = entities ? `\nExtracted entities: ${JSON.stringify(entities)}` : '';
  
  const user = `Based on this threat intelligence report, explain what detection rules should be created and why.

Report Title: ${reportName}
Report Content: ${reportText}${entityContext}

Provide a brief analysis (3-5 paragraphs max) covering:
1. Key threats identified and their risk level
2. Specific detection opportunities (what behaviors/indicators to look for)
3. Recommended log sources needed
4. Priority detection rules to create first

Be specific — reference actual techniques, tools, and IOCs from the report. Use plain language an L1 SOC analyst can understand.`;

  return await callClaude(system, user, 1500);
}

// ── Main handler ──
export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // SECURITY: Require authenticated session
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent


  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI service not configured', configured: false });
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
  const action = body.action;
  const reportName = body.report_name || '';
  const reportText = body.report_text || '';

  if (!action) return res.status(400).json({ error: 'Missing action' });
  if (!reportText) return res.status(400).json({ error: 'Missing report_text' });

  try {
    let result;

    switch (action) {
      case 'extract_entities': {
        const entities = await extractEntities(reportName, reportText);
        result = { entities };
        break;
      }

      case 'generate_sigma': {
        const entities = body.entities || null;
        const sigma = await generateSigmaRule(reportName, reportText, entities);
        result = { sigma };
        break;
      }

      case 'generate_rationale': {
        const entities = body.entities || null;
        const rationale = await generateRationale(reportName, reportText, entities);
        result = { rationale };
        break;
      }

      case 'full_analysis': {
        // Combined: extract entities + generate rationale + generate sigma — all in one call
        const entities = await extractEntities(reportName, reportText);
        const [rationale, sigma] = await Promise.all([
          generateRationale(reportName, reportText, entities),
          generateSigmaRule(reportName, reportText, entities)
        ]);
        result = { entities, rationale, sigma };
        break;
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }

    return res.status(200).json(result);
  } catch (err) {
    console.error('[ThreatIntelAI]', action, err.message);
    return res.status(500).json({ error: err.message, action });
  }
}
