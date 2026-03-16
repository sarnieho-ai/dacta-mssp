// Vercel Serverless Function — DACTA Parser Generator v5
// maxDuration: 60s (set in vercel.json)
// Returns flat JSON with all parser fields at top level.

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

const SYSTEM_PROMPT = `You are a log parsing expert. Analyse sample log lines and produce a structured parser definition.

Respond with ONLY a JSON object (no markdown fences, no extra text):
{
  "format_name": "detected log format",
  "vendor": "detected vendor",
  "delimiter": "field delimiter",
  "fields": [{"name":"field","type":"string|integer|ip_address|timestamp|float|boolean|enum","format":"pattern","confidence":90}],
  "regex_pattern": "named-capture-group regex",
  "parsed_sample": {"field":"value"},
  "notes": "observations"
}

Extract ALL fields. Respond ONLY with valid JSON.`;

module.exports = async function handler(req, res) {
  // CORS + no-cache
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'ANTHROPIC_API_KEY not configured' });

  const t0 = Date.now();

  try {
    const { log_samples, org_name, source_name } = req.body || {};
    if (!log_samples || !log_samples.trim()) {
      return res.status(400).json({ error: 'log_samples is required' });
    }

    let userPrompt = `Analyse these log lines and generate a parser definition.\n\nSample logs:\n${log_samples.trim().substring(0, 3000)}`;
    if (org_name) userPrompt += `\n\nOrg: ${org_name}`;
    if (source_name) userPrompt += `\nSource: ${source_name}`;

    // Call Claude — use AbortController for timeout safety
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 50000); // 50s timeout (Vercel max is 60)

    let claudeResp;
    try {
      claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 4096,
          system: SYSTEM_PROMPT,
          messages: [{ role: 'user', content: userPrompt }]
        }),
        signal: controller.signal
      });
    } catch (fetchErr) {
      clearTimeout(timeout);
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: 'Claude API fetch failed: ' + (fetchErr.name === 'AbortError' ? 'Request timed out (50s)' : fetchErr.message),
        response: ''
      });
    }
    clearTimeout(timeout);

    if (!claudeResp.ok) {
      const errText = await claudeResp.text().catch(() => '');
      let errMsg = `Claude API error: ${claudeResp.status}`;
      try { const e = JSON.parse(errText); if (e.error?.message) errMsg = e.error.message; } catch(e) {}
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: errMsg,
        response: errText.substring(0, 500)
      });
    }

    // Read full response as text first (safer than .json() which can throw on truncation)
    let responseBody = '';
    try {
      responseBody = await claudeResp.text();
    } catch(readErr) {
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: 'Failed to read Claude response body: ' + readErr.message,
        response: ''
      });
    }

    // Parse the Anthropic API response
    let apiData;
    try {
      apiData = JSON.parse(responseBody);
    } catch(e) {
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: 'Claude returned non-JSON (' + responseBody.length + ' chars)',
        response: responseBody.substring(0, 500)
      });
    }

    const textBlock = (apiData.content || []).find(b => b.type === 'text');
    const rawText = textBlock ? textBlock.text : '';

    if (!rawText) {
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: 'Claude returned empty text. Stop reason: ' + (apiData.stop_reason || 'unknown') + '. Content blocks: ' + (apiData.content || []).length,
        response: JSON.stringify(apiData).substring(0, 500)
      });
    }

    // Parse the AI's JSON output — multiple strategies
    let parsed = null;
    let parseStrategy = 'none';

    // Strategy 1: Direct parse
    try { parsed = JSON.parse(rawText.trim()); parseStrategy = 'direct'; } catch(e) {}

    // Strategy 2: Markdown fences
    if (!parsed) {
      const m = rawText.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (m) { try { parsed = JSON.parse(m[1].trim()); parseStrategy = 'fenced'; } catch(e) {} }
    }

    // Strategy 3: First { to last }
    if (!parsed) {
      const fb = rawText.indexOf('{'); const lb = rawText.lastIndexOf('}');
      if (fb >= 0 && lb > fb) { try { parsed = JSON.parse(rawText.substring(fb, lb + 1)); parseStrategy = 'brute'; } catch(e) {} }
    }

    if (!parsed) {
      return res.status(200).json({
        _v: 5, _ok: false, _ts: new Date().toISOString(),
        _ms: Date.now() - t0,
        error: 'Server could not extract JSON from AI text (' + rawText.length + ' chars). First 100: ' + rawText.substring(0, 100),
        response: rawText
      });
    }

    // Success — return flat fields
    return res.status(200).json({
      _v: 5,
      _ok: true,
      _ts: new Date().toISOString(),
      _ms: Date.now() - t0,
      _strategy: parseStrategy,
      format_name: parsed.format_name || 'Unknown',
      vendor: parsed.vendor || 'Unknown',
      delimiter: parsed.delimiter || 'N/A',
      fields: parsed.fields || [],
      regex_pattern: parsed.regex_pattern || '',
      parsed_sample: parsed.parsed_sample || {},
      notes: parsed.notes || '',
      response: rawText,
      model: apiData.model,
      usage: apiData.usage
    });

  } catch (err) {
    return res.status(200).json({
      _v: 5, _ok: false, _ts: new Date().toISOString(),
      _ms: Date.now() - t0,
      error: 'Unhandled: ' + err.message,
      response: ''
    });
  }
};
