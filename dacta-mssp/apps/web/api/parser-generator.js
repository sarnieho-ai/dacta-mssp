// Vercel Serverless Function — DACTA Parser Generator
// Lightweight Claude-powered log parser that analyses sample log lines
// and returns structured parser definitions (fields, regex, parsed sample).

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

const SYSTEM_PROMPT = `You are a log parsing expert. Your ONLY job is to analyse sample log lines and produce a structured parser definition.

You MUST respond with a single JSON object (no markdown fences, no extra text) with these keys:
- format_name (string): detected log format (e.g. "CEF Syslog", "JSON Structured", "CSV", "Windows XML Event")
- vendor (string): detected vendor if possible (e.g. "Fortinet", "CrowdStrike", "Microsoft")
- delimiter (string): field delimiter used (e.g. "|", ",", "space-delimited", "key=value pairs")
- fields (array of objects): each with { name (string), type (string — one of: string, integer, ip_address, timestamp, float, boolean, enum), format (string — example pattern or allowed values), confidence (integer 0-100) }
- regex_pattern (string): a named-capture-group regex that extracts all fields from a single log line
- parsed_sample (object): the first sample log line parsed into field=value pairs using your regex
- notes (string): any caveats or observations about the log format

Be thorough — extract ALL meaningful fields including timestamps, IPs, ports, actions, categories, severities, device IDs, and message content.
For CEF logs, extract both the CEF header fields AND the extension key=value pairs.
For JSON logs, flatten nested keys using dot notation.
For syslog, include the syslog header fields (timestamp, hostname, facility).

Respond ONLY with valid JSON. No markdown, no explanation text outside the JSON.`;

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY not configured' });
  }

  try {
    const { log_samples, org_name, source_name } = req.body || {};

    if (!log_samples || !log_samples.trim()) {
      return res.status(400).json({ error: 'log_samples is required' });
    }

    // Build user prompt
    let userPrompt = `Analyse these sample log lines and generate a complete parser definition.\n\nSample logs:\n${log_samples.trim()}`;
    if (org_name) userPrompt += `\n\nOrganization context: ${org_name}`;
    if (source_name) userPrompt += `\nLog source: ${source_name}`;

    // Call Claude Haiku for fast parsing
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        model: 'claude-3-5-haiku-20241022',
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userPrompt }]
      })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error('[ParserGen] Claude API error:', resp.status, errText);
      let errMsg = `AI service error: ${resp.status}`;
      try {
        const errObj = JSON.parse(errText);
        if (errObj.error && errObj.error.message) errMsg = errObj.error.message;
      } catch(e) { /* ignore */ }
      return res.status(502).json({ error: errMsg });
    }

    const data = await resp.json();
    const textBlock = (data.content || []).find(b => b.type === 'text');
    const rawText = textBlock ? textBlock.text : '';

    // Try to parse JSON from Claude's response
    let parsed = null;
    try {
      // Try direct parse first
      parsed = JSON.parse(rawText.trim());
    } catch (e) {
      // Try extracting from markdown fences
      const jsonMatch = rawText.match(/```(?:json)?\s*([\s\S]*?)```/) || rawText.match(/(\{[\s\S]*\})/);
      if (jsonMatch) {
        try { parsed = JSON.parse(jsonMatch[1].trim()); } catch (e2) { /* fall through */ }
      }
    }

    return res.status(200).json({
      response: rawText,
      parsed: parsed,
      model: data.model,
      usage: data.usage
    });

  } catch (err) {
    console.error('[ParserGen] Error:', err);
    return res.status(500).json({ error: err.message });
  }
};
