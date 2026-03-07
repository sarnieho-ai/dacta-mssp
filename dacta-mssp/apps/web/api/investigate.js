// Vercel Serverless Function — DACTA AI Investigation Engine
// Three-Phase LLM-Driven Investigation: Investigate → Synthesize → Adversarial Challenge
// Uses same PII vault and tool infrastructure as copilot.js
// Required env vars: ANTHROPIC_API_KEY, ELASTIC_URL, ELASTIC_API_KEY

const { PiiVault } = require('./lib/pii-vault.js');
const https = require('https');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const ELASTIC_URL = process.env.ELASTIC_URL || '';
const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || '';

function elasticFetchOptions(opts) {
  if (process.env.ELASTIC_SKIP_SSL_VERIFY === 'true') {
    const agent = new https.Agent({ rejectUnauthorized: false });
    return { ...opts, agent };
  }
  return opts;
}

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const OPENCTI_URL = process.env.OPENCTI_URL || _d('aHR0cDovLzYxLjEzLjIxNC4xOTg6ODA4MA==');
const OPENCTI_TOKEN = process.env.OPENCTI_TOKEN || _d('NjE4OTZjMTQtNWM0OS00NDQ2LTllMDEtYTI4MWRmNTNmY2Qz');

// CrowdStrike credentials
const CS_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID || '';
const CS_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET || '';
const CS_BASE_URL = process.env.CROWDSTRIKE_BASE_URL || 'https://api.us-2.crowdstrike.com';

// ═══════════════════════════════════════════════
// PHASE 1: INVESTIGATOR SYSTEM PROMPT
// The LLM acts as an unbiased forensic investigator
// ═══════════════════════════════════════════════
const INVESTIGATOR_PROMPT = `You are a senior SOC forensic investigator at DACTA SIEMLess MSSP. You are conducting Phase 1 of a structured investigation on a security alert.

## Your Mandate
- You are an UNBIASED investigator. You have NO agenda — not to prove true positive, not to prove false positive.
- Follow the evidence wherever it leads. Observe, hypothesize, test, refine.
- Use your tools aggressively. Query SIEM logs, check threat intel, look up IOCs. Don't theorize — VERIFY.
- Document every finding as a neutral observation with its source and significance.

## Investigation Methodology
1. **OBSERVE**: Read the alert data. What do you see? What stands out?
2. **HYPOTHESIZE**: What could explain this alert? (Both malicious and benign explanations)
3. **QUERY**: Use tools to test your hypotheses. Search for corroborating or contradicting evidence.
4. **REFINE**: Based on results, update your understanding. Follow new leads.
5. **DOCUMENT**: Record each finding neutrally — what was found, where, and what it means.

## Tool Usage Strategy
- Start with the alert context and extract IOCs (IPs, hashes, domains, hostnames, processes)
- Query Elastic SIEM for: child processes, network connections, file events, EDR actions, auth events
- Check DACTA TIP for IOC reputation and MITRE technique context
- Look at alert history on the same host — is this a recurring pattern?
- Check CrowdStrike alert data if available in the logs
- Search for lateral movement indicators across the environment

## Output Format
You MUST respond with a valid JSON object (no markdown, no code fences) containing:
{
  "observations": [
    {
      "finding": "What was observed",
      "source": "Where this came from (e.g., 'Elastic SIEM query', 'DACTA TIP lookup', 'Alert context')",
      "significance": "Why this matters for the investigation",
      "tools_used": ["tool names used to discover this"]
    }
  ],
  "hypotheses_tested": [
    {
      "hypothesis": "What was being tested",
      "result": "confirmed|refuted|inconclusive",
      "evidence": "What evidence supports this result"
    }
  ],
  "preliminary_assessment": "Your current best understanding of the situation based on evidence gathered",
  "confidence": 0-100,
  "open_questions": ["Things that couldn't be answered with available tools"],
  "tools_summary": {
    "total_queries": 0,
    "siem_queries": 0,
    "tip_lookups": 0,
    "findings_from_tools": 0
  }
}

CRITICAL: Output ONLY the JSON object. No explanatory text before or after.`;

// ═══════════════════════════════════════════════
// PHASE 2: SYNTHESIZER SYSTEM PROMPT
// Builds narrative and preliminary verdict from Phase 1 findings
// ═══════════════════════════════════════════════
const SYNTHESIZER_PROMPT = `You are a senior SOC analyst at DACTA SIEMLess MSSP conducting Phase 2 synthesis of a security investigation.

## Your Task
You have been given the raw investigation findings from Phase 1. Your job is to:
1. Synthesize all observations into a coherent narrative
2. Weigh the evidence — what points toward true positive vs false positive?
3. Reconstruct the attack chain (if this is a real attack) or the benign workflow (if false positive)
4. Provide a preliminary verdict with reasoning

## Synthesis Approach
- Group related findings by category (process activity, network, files, threat intel, user context)
- Identify the strongest pieces of evidence and explain WHY they are strong
- Call out any contradictions in the evidence
- Consider alternative explanations for each finding
- Weight evidence by source reliability: SIEM-confirmed > Threat Intel > Ticket text inference

## Output Format
You MUST respond with a valid JSON object (no markdown, no code fences):
{
  "narrative": "A clear, paragraph-form narrative of what happened based on the evidence. Written as a forensic report.",
  "evidence_summary": {
    "supporting_threat": [
      {"finding": "...", "weight": "critical|high|medium|low", "source": "..."}
    ],
    "supporting_benign": [
      {"finding": "...", "weight": "strong|moderate|weak", "source": "..."}
    ],
    "inconclusive": [
      {"finding": "...", "reason": "Why this doesn't clearly point either way"}
    ]
  },
  "attack_chain": "Description of the attack progression if TP, or the benign workflow if FP",
  "mitre_mapping": [
    {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution", "relevance": "How this technique relates to this alert"}
  ],
  "preliminary_verdict": "TRUE_POSITIVE|FALSE_POSITIVE|SUSPICIOUS",
  "verdict_reasoning": "Why you reached this verdict based on the evidence",
  "confidence": 0-100,
  "key_evidence_count": {"threat": 0, "benign": 0, "inconclusive": 0}
}

CRITICAL: Output ONLY the JSON object. No explanatory text before or after.`;

// ═══════════════════════════════════════════════
// PHASE 3: ADVERSARIAL CHALLENGER SYSTEM PROMPT
// Tries to break the Phase 2 conclusion
// ═══════════════════════════════════════════════
const ADVERSARIAL_PROMPT = `You are a senior SOC quality reviewer at DACTA SIEMLess MSSP conducting Phase 3 adversarial review.

## Your Role — Devil's Advocate
You have been given the investigation findings (Phase 1) and the synthesis/verdict (Phase 2). Your SOLE job is to CHALLENGE the conclusion.

- If Phase 2 says TRUE POSITIVE: You must argue the case for why this could be benign/false positive
- If Phase 2 says FALSE POSITIVE: You must argue the case for why this could be a real threat
- If Phase 2 says SUSPICIOUS: You must argue BOTH sides more forcefully

## Challenge Methodology
1. Identify the WEAKEST links in the Phase 2 reasoning
2. Look for evidence that was overlooked or under-weighted
3. Consider adversary tradecraft that could explain benign-looking evidence
4. Consider legitimate workflows that could explain threatening-looking evidence
5. Check for logical fallacies or confirmation bias in the Phase 2 analysis
6. Use tools to search for additional evidence that could flip the verdict

## Output Format
You MUST respond with a valid JSON object (no markdown, no code fences):
{
  "challenge_direction": "What the Phase 2 verdict was and which direction you're challenging FROM",
  "counter_arguments": [
    {
      "argument": "The specific counter-argument",
      "targets": "Which Phase 2 finding or reasoning this challenges",
      "strength": "strong|moderate|weak",
      "evidence": "What supports this counter-argument"
    }
  ],
  "overlooked_evidence": [
    {
      "finding": "Evidence that Phase 2 didn't adequately consider",
      "significance": "Why this matters"
    }
  ],
  "bias_check": {
    "identified_biases": ["Any confirmation bias, anchoring, or other analytical biases detected"],
    "recommendations": ["How to address them"]
  },
  "stress_test_result": "VERDICT_HOLDS|VERDICT_WEAKENED|VERDICT_SHOULD_FLIP",
  "final_verdict": "TRUE_POSITIVE|FALSE_POSITIVE|SUSPICIOUS",
  "final_confidence": 0-100,
  "final_reasoning": "The definitive conclusion after adversarial testing",
  "recommended_actions": [
    {"action": "What to do next", "priority": "HIGH|MEDIUM|LOW", "type": "containment|investigation|documentation|notification"}
  ]
}

CRITICAL: Output ONLY the JSON object. No explanatory text before or after.`;

// ═══════════════════════════════════════════════
// Tool Definitions (shared across phases)
// ═══════════════════════════════════════════════
const INVESTIGATION_TOOLS = [
  {
    name: "search_siem",
    description: "Search Elastic SIEM logs using Elasticsearch query DSL. Query for log events, alerts, network connections, process executions, authentication events. Supports aggregations. ALWAYS scope queries to the correct client namespace.",
    input_schema: {
      type: "object",
      properties: {
        index: { type: "string", description: "Elasticsearch index pattern. Use 'logs-*-{namespace}-*' for client-scoped queries, '.ds-logs-crowdstrike.alert-{namespace}-*' for CrowdStrike alerts, 'logs-panw.panos-{namespace}-*' for firewall." },
        query: { type: "object", description: "Elasticsearch DSL query. Common fields: source.ip, destination.ip, host.name, process.name, event.action, @timestamp, message" },
        size: { type: "integer", description: "Results count (default 10, max 50)" },
        sort: { type: "array", description: "Sort order. Default: [{'@timestamp': 'desc'}]" },
        aggs: { type: "object", description: "Aggregations for statistics" },
        _source: { type: "array", description: "Fields to return" }
      },
      required: ["query"]
    }
  },
  {
    name: "lookup_threat_intel",
    description: "Look up an IOC (IP, domain, hash, URL) in DACTA TIP threat intelligence platform. Returns threat score, labels, and associated reports.",
    input_schema: {
      type: "object",
      properties: {
        value: { type: "string", description: "The IOC value (IP, domain, hash, URL)" },
        type: { type: "string", enum: ["ipv4-addr", "domain-name", "file-md5", "file-sha1", "file-sha256", "url"], description: "IOC type" }
      },
      required: ["value", "type"]
    }
  },
  {
    name: "lookup_mitre",
    description: "Look up a MITRE ATT&CK technique by ID in DACTA TIP. Returns technique details, kill chain phases, and procedures.",
    input_schema: {
      type: "object",
      properties: {
        technique_id: { type: "string", description: "MITRE technique ID, e.g., 'T1059.001'" }
      },
      required: ["technique_id"]
    }
  }
];

// ═══════════════════════════════════════════════
// Tool Execution Functions
// ═══════════════════════════════════════════════
async function executeSearchSIEM(params) {
  if (!ELASTIC_URL || !ELASTIC_API_KEY) {
    return { error: 'Elastic SIEM not configured', connected: false };
  }
  const index = params.index || 'logs-*';
  const body = {
    size: Math.min(params.size || 10, 50),
    query: params.query || { match_all: {} },
    sort: params.sort || [{ '@timestamp': 'desc' }]
  };
  if (params.aggs) body.aggs = params.aggs;
  if (params._source) body._source = params._source;

  try {
    const resp = await fetch(`${ELASTIC_URL}/${index}/_search`, elasticFetchOptions({
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    }));
    const data = await resp.json();
    const total = data.hits?.total?.value || 0;
    const hits = (data.hits?.hits || []).map(h => {
      const src = h._source || {};
      return {
        _index: h._index,
        timestamp: src['@timestamp'],
        message: src.message ? (src.message.length > 500 ? src.message.substring(0, 500) + '...' : src.message) : undefined,
        source_ip: src.source?.ip,
        destination_ip: src.destination?.ip,
        host_name: src.host?.name,
        user_name: src.user?.name,
        process_name: src.process?.name,
        process_command_line: src.process?.command_line ? (src.process.command_line.length > 300 ? src.process.command_line.substring(0, 300) + '...' : src.process.command_line) : undefined,
        parent_process: src.process?.parent?.name,
        event_action: src.event?.action,
        event_category: src.event?.category,
        event_outcome: src.event?.outcome,
        dataset: src.data_stream?.dataset,
        namespace: src.data_stream?.namespace,
        rule_name: src.rule?.name,
        agent_name: src.agent?.name,
        _raw: total <= 3 ? src : undefined
      };
    });
    const aggs = {};
    if (data.aggregations) {
      for (const [key, val] of Object.entries(data.aggregations)) {
        if (val.buckets) aggs[key] = val.buckets.slice(0, 20).map(b => ({ key: b.key, count: b.doc_count }));
        else if (val.value !== undefined) aggs[key] = val.value;
      }
    }
    return { connected: true, total, hits, aggregations: Object.keys(aggs).length > 0 ? aggs : undefined, timed_out: data.timed_out };
  } catch (err) {
    return { error: `Elastic query failed: ${err.message}`, connected: false };
  }
}

async function executeLookupThreatIntel(params) {
  const { value, type } = params;
  let gqlQuery;
  if (type === 'ipv4-addr') {
    gqlQuery = `{ indicators(first: 10, filters: { mode: and, filters: [{ key: "pattern", values: ["${value}"], operator: eq }] }) { edges { node { id name pattern x_opencti_score pattern_type created_at objectLabel { id value } } } } stixCyberObservables(first: 5, filters: { mode: and, filters: [{ key: "value", values: ["${value}"] }] }) { edges { node { id entity_type observable_value x_opencti_score created_at } } } }`;
  } else {
    gqlQuery = `{ indicators(first: 10, filters: { mode: and, filters: [{ key: "pattern", values: ["${value}"], operator: eq }] }) { edges { node { id name pattern x_opencti_score pattern_type created_at objectLabel { id value } } } } }`;
  }
  try {
    const resp = await fetch(`${OPENCTI_URL}/graphql`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${OPENCTI_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: gqlQuery })
    });
    const data = await resp.json();
    const indicators = data.data?.indicators?.edges?.map(e => ({
      name: e.node.name, score: e.node.x_opencti_score, type: e.node.pattern_type,
      labels: (e.node.objectLabel || []).map(l => l.value), created: e.node.created_at
    })) || [];
    const observables = data.data?.stixCyberObservables?.edges?.map(e => ({
      type: e.node.entity_type, value: e.node.observable_value, score: e.node.x_opencti_score
    })) || [];
    return { connected: true, value, type, found: indicators.length > 0 || observables.length > 0, indicators, observables };
  } catch (err) {
    return { error: `DACTA TIP lookup failed: ${err.message}`, connected: false };
  }
}

async function executeLookupMITRE(params) {
  const { technique_id } = params;
  const stixId = `attack-pattern--${technique_id}`;
  const gqlQuery = `{ attackPatterns(first: 5, filters: { mode: and, filters: [{ key: "x_mitre_id", values: ["${technique_id}"] }] }) { edges { node { id name description x_mitre_id killChainPhases { edges { node { kill_chain_name phase_name } } } } } } }`;
  try {
    const resp = await fetch(`${OPENCTI_URL}/graphql`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${OPENCTI_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: gqlQuery })
    });
    const data = await resp.json();
    const patterns = data.data?.attackPatterns?.edges?.map(e => ({
      name: e.node.name, id: e.node.x_mitre_id,
      description: e.node.description ? (e.node.description.length > 500 ? e.node.description.substring(0, 500) + '...' : e.node.description) : null,
      phases: (e.node.killChainPhases?.edges || []).map(p => p.node.phase_name)
    })) || [];
    return { connected: true, technique_id, found: patterns.length > 0, patterns };
  } catch (err) {
    return { error: `MITRE lookup failed: ${err.message}`, connected: false };
  }
}

async function executeTool(name, input) {
  switch (name) {
    case 'search_siem': return await executeSearchSIEM(input);
    case 'lookup_threat_intel': return await executeLookupThreatIntel(input);
    case 'lookup_mitre': return await executeLookupMITRE(input);
    default: return { error: `Unknown tool: ${name}` };
  }
}

// ═══════════════════════════════════════════════
// Multi-Model LLM API Layer
// Primary: Claude (Phases 1,3), GPT-4o (Phase 2)
// Cross-fallback: If primary fails, try alternate
// ═══════════════════════════════════════════════

// Model routing: which model is primary/fallback per phase
const MODEL_ROUTING = {
  phase1: { primary: 'claude', fallback: 'openai' },
  phase2: { primary: 'openai', fallback: 'claude' },
  phase3: { primary: 'claude', fallback: 'openai' }
};

async function callClaude(body, retries = 2) {
  if (!ANTHROPIC_API_KEY) throw new Error('Anthropic API key not configured');
  for (let attempt = 0; attempt <= retries; attempt++) {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    if (resp.status === 429 && attempt < retries) {
      const waitSec = 8 + (attempt * 5);
      console.log(`[Investigate] Claude rate limited, waiting ${waitSec}s (attempt ${attempt + 1})`);
      await new Promise(r => setTimeout(r, waitSec * 1000));
      continue;
    }
    if (!resp.ok) {
      const errText = await resp.text();
      console.error('[Investigate] Claude API error:', resp.status, errText);
      throw new Error(`Claude API error: ${resp.status}`);
    }
    return await resp.json();
  }
}

async function callOpenAI(body, retries = 2) {
  if (!OPENAI_API_KEY) throw new Error('OpenAI API key not configured');
  for (let attempt = 0; attempt <= retries; attempt++) {
    const resp = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENAI_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
    if (resp.status === 429 && attempt < retries) {
      const waitSec = 8 + (attempt * 5);
      console.log(`[Investigate] OpenAI rate limited, waiting ${waitSec}s (attempt ${attempt + 1})`);
      await new Promise(r => setTimeout(r, waitSec * 1000));
      continue;
    }
    if (!resp.ok) {
      const errText = await resp.text();
      console.error('[Investigate] OpenAI API error:', resp.status, errText);
      throw new Error(`OpenAI API error: ${resp.status}`);
    }
    return await resp.json();
  }
}

// Convert Claude tool format → OpenAI function format
function claudeToolsToOpenAI(tools) {
  return tools.map(t => ({
    type: 'function',
    function: {
      name: t.name,
      description: t.description,
      parameters: t.input_schema
    }
  }));
}

// Normalize OpenAI response → Claude-like format for uniform processing
function normalizeOpenAIResponse(oaiResp) {
  const choice = oaiResp.choices?.[0];
  if (!choice) return { content: [{ type: 'text', text: '{}' }], stop_reason: 'end_turn', usage: { input_tokens: 0, output_tokens: 0 } };

  const msg = choice.message;
  const content = [];

  // Handle tool calls
  if (msg.tool_calls && msg.tool_calls.length > 0) {
    // Include any text content first
    if (msg.content) content.push({ type: 'text', text: msg.content });
    msg.tool_calls.forEach(tc => {
      let parsedArgs;
      try { parsedArgs = JSON.parse(tc.function.arguments); } catch { parsedArgs = {}; }
      content.push({
        type: 'tool_use',
        id: tc.id,
        name: tc.function.name,
        input: parsedArgs
      });
    });
    return {
      content,
      stop_reason: 'tool_use',
      usage: {
        input_tokens: oaiResp.usage?.prompt_tokens || 0,
        output_tokens: oaiResp.usage?.completion_tokens || 0
      }
    };
  }

  // Text response
  content.push({ type: 'text', text: msg.content || '{}' });
  return {
    content,
    stop_reason: choice.finish_reason === 'stop' ? 'end_turn' : choice.finish_reason,
    usage: {
      input_tokens: oaiResp.usage?.prompt_tokens || 0,
      output_tokens: oaiResp.usage?.completion_tokens || 0
    }
  };
}

// ═══════════════════════════════════════════════
// Agentic Tool-Use Loop
// Runs LLM with tools, loops until text response
// ═══════════════════════════════════════════════
// Unified agentic phase runner — works with both Claude and OpenAI
async function runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds = 6, provider = 'claude') {
  const CLAUDE_MODEL = 'claude-sonnet-4-20250514';
  const OPENAI_MODEL = 'gpt-4o';
  const useClaude = provider === 'claude';
  let messages = useClaude
    ? [{ role: 'user', content: userMessage }]
    : [{ role: 'system', content: systemPrompt }, { role: 'user', content: userMessage }];
  let toolLog = [];
  let iteration = 0;
  let totalUsage = { input_tokens: 0, output_tokens: 0 };

  while (iteration <= maxToolRounds) {
    iteration++;
    const isLast = iteration > maxToolRounds;

    if (isLast) {
      messages.push({
        role: 'user',
        content: 'All tool calls complete. Produce your COMPLETE JSON response now. Output ONLY the JSON object with no markdown or code fences.'
      });
    }

    let result;
    if (useClaude) {
      const callBody = {
        model: CLAUDE_MODEL,
        max_tokens: isLast ? 4096 : 2048,
        system: isLast
          ? systemPrompt + '\n\n[FINAL] All tool calls done. Produce your complete JSON response NOW.'
          : systemPrompt,
        messages
      };
      if (!isLast) callBody.tools = INVESTIGATION_TOOLS;
      result = await callClaude(callBody);
    } else {
      // OpenAI path
      const oaiBody = {
        model: OPENAI_MODEL,
        max_tokens: isLast ? 4096 : 2048,
        messages
      };
      if (!isLast) oaiBody.tools = claudeToolsToOpenAI(INVESTIGATION_TOOLS);
      if (isLast) {
        // Update system prompt for final call
        oaiBody.messages = oaiBody.messages.map(m =>
          m.role === 'system'
            ? { ...m, content: m.content + '\n\n[FINAL] All tool calls done. Produce your complete JSON response NOW.' }
            : m
        );
      }
      const oaiResp = await callOpenAI(oaiBody);
      result = normalizeOpenAIResponse(oaiResp);
    }

    if (result.usage) {
      totalUsage.input_tokens += result.usage.input_tokens || 0;
      totalUsage.output_tokens += result.usage.output_tokens || 0;
    }

    if (result.stop_reason === 'tool_use' && !isLast) {
      const toolBlocks = result.content.filter(b => b.type === 'tool_use');

      if (useClaude) {
        messages.push({ role: 'assistant', content: result.content });
      } else {
        // OpenAI: reconstruct assistant message with tool_calls
        const assistantMsg = { role: 'assistant', content: null, tool_calls: [] };
        const textParts = result.content.filter(b => b.type === 'text');
        if (textParts.length > 0) assistantMsg.content = textParts.map(t => t.text).join('');
        toolBlocks.forEach(tb => {
          assistantMsg.tool_calls.push({
            id: tb.id,
            type: 'function',
            function: { name: tb.name, arguments: JSON.stringify(tb.input) }
          });
        });
        messages.push(assistantMsg);
      }

      const toolResults = await Promise.all(toolBlocks.map(async (tb) => {
        const realInput = vault.detokenizeDeep(tb.input);
        const toolResult = await executeTool(tb.name, realInput);
        const tokenizedResult = vault.tokenizeDeep(toolResult);
        toolLog.push({
          tool: tb.name,
          input: tb.input,  // Full input for drill-down
          input_summary: JSON.stringify(tb.input).substring(0, 200),
          result_summary: toolResult.error || `${toolResult.total !== undefined ? toolResult.total + ' hits' : (toolResult.found ? 'FOUND' : 'not found')}`,
          connected: toolResult.connected !== false
        });
        if (useClaude) {
          return { type: 'tool_result', tool_use_id: tb.id, content: JSON.stringify(tokenizedResult) };
        } else {
          return { role: 'tool', tool_call_id: tb.id, content: JSON.stringify(tokenizedResult) };
        }
      }));

      if (useClaude) {
        messages.push({ role: 'user', content: toolResults });
      } else {
        toolResults.forEach(tr => messages.push(tr));
      }
      continue;
    }

    // Got text response
    const text = result.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
    const detokenized = vault.detokenize(text);
    return { text: detokenized, toolLog, usage: totalUsage, iterations: iteration, provider };
  }

  return { text: '{}', toolLog, usage: totalUsage, iterations: iteration, provider };
}

// Run a phase with the assigned primary model, falling back to alternate on failure
async function runPhaseWithFallback(phase, systemPrompt, userMessage, vault, maxToolRounds) {
  const routing = MODEL_ROUTING[phase] || { primary: 'claude', fallback: 'openai' };
  let provider = routing.primary;
  let fallbackUsed = false;

  try {
    const result = await runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds, provider);
    return { ...result, model: provider === 'claude' ? 'claude-sonnet-4' : 'gpt-4o', fallback_used: false };
  } catch (primaryErr) {
    console.warn(`[Investigate] ${phase} primary (${provider}) failed: ${primaryErr.message}. Falling back to ${routing.fallback}`);
    provider = routing.fallback;
    fallbackUsed = true;
    try {
      const result = await runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds, provider);
      return { ...result, model: provider === 'claude' ? 'claude-sonnet-4' : 'gpt-4o', fallback_used: true };
    } catch (fallbackErr) {
      console.error(`[Investigate] ${phase} fallback (${provider}) also failed: ${fallbackErr.message}`);
      throw new Error(`Both ${routing.primary} and ${routing.fallback} failed for ${phase}`);
    }
  }
}

// ═══════════════════════════════════════════════
// Parse JSON from LLM output (handles markdown fences)
// ═══════════════════════════════════════════════
function parsePhaseJSON(text) {
  // Strip markdown code fences if present
  let clean = text.trim();
  if (clean.startsWith('```json')) clean = clean.slice(7);
  else if (clean.startsWith('```')) clean = clean.slice(3);
  if (clean.endsWith('```')) clean = clean.slice(0, -3);
  clean = clean.trim();

  try {
    return JSON.parse(clean);
  } catch (e) {
    // Try to extract JSON from mixed text
    const jsonMatch = clean.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try { return JSON.parse(jsonMatch[0]); } catch (e2) { /* fall through */ }
    }
    console.error('[Investigate] Failed to parse phase JSON:', e.message, 'Raw:', clean.substring(0, 200));
    return null;
  }
}

// ═══════════════════════════════════════════════
// Server-Side Usage Logging
// ═══════════════════════════════════════════════
async function logInvestigationUsage({ ticketKey, phase, model, usage, toolCallLog, latencyMs, fallbackUsed }) {
  if (!SUPABASE_SERVICE_KEY) return;
  const provider = (model || '').includes('gpt') ? 'openai' : 'anthropic';
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/llm_usage_log`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        task_type: `investigation_${phase}`,
        model: model,
        provider: provider,
        input_tokens: usage?.input_tokens || 0,
        output_tokens: usage?.output_tokens || 0,
        latency_ms: latencyMs || 0,
        estimated_cost_usd: 0,
        fallback_used: fallbackUsed || false,
        related_entity_type: 'investigation',
        related_entity_id: ticketKey || null
      })
    });
  } catch (err) {
    console.error('[Investigate] Usage logging failed:', err.message);
  }
}

// ═══════════════════════════════════════════════
// Vercel Config
// ═══════════════════════════════════════════════
export const config = {
  maxDuration: 60
};

// ═══════════════════════════════════════════════
// Main Handler
// ═══════════════════════════════════════════════
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const requestStart = Date.now();

  if (!ANTHROPIC_API_KEY && !OPENAI_API_KEY) {
    return res.status(500).json({ error: 'AI engine not configured. Contact administrator.' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { ticket_key, alert_context, namespace, phase, previous_phases } = body;

    if (!ticket_key || !alert_context) {
      return res.status(400).json({ error: 'ticket_key and alert_context are required' });
    }

    // PII Vault
    const vault = new PiiVault();
    const KNOWN_CLIENTS = ['Naga World', 'NagaWorld', 'EM Services', 'SP Telecom',
      'Toyota Financial', 'Foxwood Technology', 'Foxwood', 'SPMT', 'SP Media',
      'SilverKey', 'Silver Key', 'ADV Partners', 'Dacta Training', 'Dacta Global'];
    vault.registerClientNames(KNOWN_CLIENTS);

    // Build the context message for the LLM
    const alertBrief = `## Alert Under Investigation: ${ticket_key}
**Summary**: ${alert_context.summary || 'N/A'}
**Priority**: ${alert_context.priority || 'Unknown'}
**Organization**: ${alert_context.organization || 'Unknown'}
**Status**: ${alert_context.status || 'Unknown'}
**Labels**: ${alert_context.labels || 'None'}

### Alert Description
${alert_context.description || 'No description available'}

### Extracted IOCs
- IPs: ${(alert_context.iocs?.ips || []).join(', ') || 'None'}
- Domains: ${(alert_context.iocs?.domains || []).join(', ') || 'None'}
- Hashes: ${(alert_context.iocs?.hashes || []).join(', ') || 'None'}
- Files: ${(alert_context.iocs?.files || []).join(', ') || 'None'}
- Hosts: ${(alert_context.iocs?.hosts || []).join(', ') || 'None'}
- Ports: ${(alert_context.iocs?.ports || []).join(', ') || 'None'}

### Detected MITRE Techniques
${(alert_context.techniques || []).map(t => `- ${t.id}: ${t.name} [${t.tactic}]`).join('\n') || 'None detected'}

### Client Namespace for SIEM queries: ${namespace || 'unknown'}
${namespace ? `IMPORTANT: Scope ALL Elastic queries to namespace "${namespace}". Use index "logs-*-${namespace}-*" or filter by data_stream.namespace.` : ''}`;

    const tokenizedBrief = vault.tokenize(alertBrief);

    // Determine which phase to run
    const runPhase = phase || 'phase1';

    if (runPhase === 'phase1') {
      // ── PHASE 1: Investigation (Primary: Claude, Fallback: GPT-4o) ──
      console.log(`[Investigate] Phase 1 starting for ${ticket_key}`);
      const phaseResult = await runPhaseWithFallback(
        'phase1',
        vault.tokenize(INVESTIGATOR_PROMPT),
        tokenizedBrief,
        vault,
        6 // Allow up to 6 tool rounds for thorough investigation
      );

      const parsed = parsePhaseJSON(phaseResult.text);
      const latency = Date.now() - requestStart;
      logInvestigationUsage({ ticketKey: ticket_key, phase: 'phase1', model: phaseResult.model, usage: phaseResult.usage, toolCallLog: phaseResult.toolLog, latencyMs: latency });

      return res.status(200).json({
        phase: 'phase1',
        ticket_key,
        model: phaseResult.model,
        fallback_used: phaseResult.fallback_used,
        result: parsed || { error: 'Failed to parse investigation output', raw: phaseResult.text.substring(0, 2000) },
        tool_calls: phaseResult.toolLog,
        usage: phaseResult.usage,
        iterations: phaseResult.iterations,
        latency_ms: latency
      });
    }

    if (runPhase === 'phase2') {
      // ── PHASE 2: Synthesis (Primary: GPT-4o, Fallback: Claude) ──
      const phase1Data = previous_phases?.phase1;
      if (!phase1Data) return res.status(400).json({ error: 'phase2 requires previous_phases.phase1' });

      console.log(`[Investigate] Phase 2 starting for ${ticket_key}`);
      const synthesisInput = `${tokenizedBrief}\n\n## Phase 1 Investigation Findings\n${vault.tokenize(JSON.stringify(phase1Data, null, 2))}`;
      const tokenizedSynthPrompt = vault.tokenize(SYNTHESIZER_PROMPT);

      // Phase 2: pure synthesis, no tools — try primary (GPT-4o) then fallback
      const routing = MODEL_ROUTING.phase2;
      let phase2Model = routing.primary;
      let fallbackUsed = false;
      let parsedResult, usageResult;

      try {
        if (phase2Model === 'openai') {
          const oaiBody = {
            model: 'gpt-4o',
            max_tokens: 4096,
            messages: [
              { role: 'system', content: tokenizedSynthPrompt },
              { role: 'user', content: synthesisInput }
            ]
          };
          const oaiResp = await callOpenAI(oaiBody);
          const normalized = normalizeOpenAIResponse(oaiResp);
          const text = normalized.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
          parsedResult = parsePhaseJSON(vault.detokenize(text));
          usageResult = normalized.usage;
        } else {
          const callBody = {
            model: 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            system: tokenizedSynthPrompt,
            messages: [{ role: 'user', content: synthesisInput }]
          };
          const claudeResult = await callClaude(callBody);
          const text = claudeResult.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
          parsedResult = parsePhaseJSON(vault.detokenize(text));
          usageResult = claudeResult.usage;
        }
      } catch (primaryErr) {
        console.warn(`[Investigate] Phase 2 primary (${phase2Model}) failed: ${primaryErr.message}. Falling back...`);
        phase2Model = routing.fallback;
        fallbackUsed = true;
        if (phase2Model === 'claude') {
          const callBody = {
            model: 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            system: tokenizedSynthPrompt,
            messages: [{ role: 'user', content: synthesisInput }]
          };
          const claudeResult = await callClaude(callBody);
          const text = claudeResult.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
          parsedResult = parsePhaseJSON(vault.detokenize(text));
          usageResult = claudeResult.usage;
        } else {
          const oaiBody = {
            model: 'gpt-4o',
            max_tokens: 4096,
            messages: [
              { role: 'system', content: tokenizedSynthPrompt },
              { role: 'user', content: synthesisInput }
            ]
          };
          const oaiResp = await callOpenAI(oaiBody);
          const normalized = normalizeOpenAIResponse(oaiResp);
          const text = normalized.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
          parsedResult = parsePhaseJSON(vault.detokenize(text));
          usageResult = normalized.usage;
        }
      }

      const modelName = phase2Model === 'openai' ? 'gpt-4o' : 'claude-sonnet-4';
      const latency = Date.now() - requestStart;
      logInvestigationUsage({ ticketKey: ticket_key, phase: 'phase2', model: modelName, usage: usageResult, latencyMs: latency });

      return res.status(200).json({
        phase: 'phase2',
        ticket_key,
        model: modelName,
        fallback_used: fallbackUsed,
        result: parsedResult || { error: 'Failed to parse synthesis output' },
        usage: usageResult,
        latency_ms: latency
      });
    }

    if (runPhase === 'phase3') {
      // ── PHASE 3: Adversarial Challenge (Primary: Claude, Fallback: GPT-4o) ──
      const phase1Data = previous_phases?.phase1;
      const phase2Data = previous_phases?.phase2;
      if (!phase1Data || !phase2Data) return res.status(400).json({ error: 'phase3 requires previous_phases.phase1 and phase2' });

      console.log(`[Investigate] Phase 3 starting for ${ticket_key}`);
      const adversarialInput = `${tokenizedBrief}\n\n## Phase 1 Investigation Findings\n${vault.tokenize(JSON.stringify(phase1Data, null, 2))}\n\n## Phase 2 Synthesis & Preliminary Verdict\n${vault.tokenize(JSON.stringify(phase2Data, null, 2))}`;

      // Phase 3 gets tools to search for counter-evidence
      const phaseResult = await runPhaseWithFallback(
        'phase3',
        vault.tokenize(ADVERSARIAL_PROMPT),
        adversarialInput,
        vault,
        4 // Fewer tool rounds — focused challenge
      );

      const parsed = parsePhaseJSON(phaseResult.text);
      const latency = Date.now() - requestStart;
      logInvestigationUsage({ ticketKey: ticket_key, phase: 'phase3', model: phaseResult.model, usage: phaseResult.usage, toolCallLog: phaseResult.toolLog, latencyMs: latency });

      return res.status(200).json({
        phase: 'phase3',
        ticket_key,
        model: phaseResult.model,
        fallback_used: phaseResult.fallback_used,
        result: parsed || { error: 'Failed to parse adversarial output', raw: phaseResult.text.substring(0, 2000) },
        tool_calls: phaseResult.toolLog,
        usage: phaseResult.usage,
        iterations: phaseResult.iterations,
        latency_ms: latency
      });
    }

    return res.status(400).json({ error: `Unknown phase: ${runPhase}. Valid: phase1, phase2, phase3` });

  } catch (err) {
    console.error('[Investigate] Handler error:', err);
    return res.status(500).json({ error: err.message });
  }
}
