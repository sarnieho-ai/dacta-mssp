// Vercel Serverless Function — DACTA Copilot AI Proxy
// Agentic Claude-powered copilot with tool-use for Elastic SIEM, DACTA TIP, and Jira
// GDPR/PDPA-compliant: PII is tokenized before reaching any LLM.
// Required env vars: ANTHROPIC_API_KEY, ELASTIC_URL, ELASTIC_API_KEY, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_INSTANCE
// Optional: OPENCTI_URL, OPENCTI_TOKEN (DACTA TIP credentials)
// Optional: ELASTIC_SKIP_SSL_VERIFY=true (for self-signed certs)

const { PiiVault } = require('./lib/pii-vault.js');
const https = require('https');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ELASTIC_URL = process.env.ELASTIC_URL || '';
const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || '';
const JIRA_EMAIL = process.env.JIRA_EMAIL || '';
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN || '';
const JIRA_INSTANCE = process.env.JIRA_INSTANCE || 'dactaglobal-sg.atlassian.net';

// SSL-aware fetch helper for Elastic connections
function elasticFetchOptions(opts) {
  if (process.env.ELASTIC_SKIP_SSL_VERIFY === 'true') {
    const agent = new https.Agent({ rejectUnauthorized: false });
    return { ...opts, agent };
  }
  return opts;
}
// SIEMLess DB — server-side logging (bypasses RLS with service role)
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

// DACTA TIP — fallback to base64-encoded defaults if env vars not set
function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const OPENCTI_URL = process.env.OPENCTI_URL || _d('aHR0cDovLzYxLjEzLjIxNC4xOTg6ODA4MA==');
const OPENCTI_TOKEN = process.env.OPENCTI_TOKEN || _d('NjE4OTZjMTQtNWM0OS00NDQ2LTllMDEtYTI4MWRmNTNmY2Qz');

// ── System Prompt for SOC Copilot ──
const SYSTEM_PROMPT = `You are DACTA Copilot, an AI-powered SOC investigation assistant built into the DACTA SIEMLess MSSP platform. You help SOC analysts investigate security incidents, search SIEM logs, enrich IOCs, look up MITRE ATT&CK techniques, and query Jira tickets.

## Your Role
- You are a senior SOC analyst assistant. Be thorough, precise, and actionable.
- When an analyst asks a question, ALWAYS use tools first to gather evidence before responding. Never reply with just questions — investigate first, then present findings.
- Always ground your analysis in real data from the tools. Never fabricate IOCs, log entries, or alert details.
- Be proactive: if the analyst mentions a ticket ID (e.g., DAC-18819), immediately pull the ticket details, extract IOCs/hostnames/IPs from it, then search SIEM and threat intel. Do not ask the analyst for information you can look up yourself.
- Only ask clarifying questions AFTER you have already gathered and presented initial findings, and only if further specifics would help narrow the investigation.
- For follow-up questions, reference the conversation history to maintain context.

## Response Style
- Be conversational but professional — like a senior analyst briefing a colleague.
- Use clear sections with headers when the response is long.
- Cite specific data points (IP addresses, timestamps, hostnames, ticket IDs) from tool results.
- When presenting log data, highlight the security-relevant fields.
- Provide actionable next steps when appropriate.
- Use markdown formatting: **bold** for emphasis, \`code\` for IPs/hashes/commands, bullet lists for findings.
- Keep responses focused and avoid unnecessary preamble.

## Available Data Sources
- **Elastic SIEM**: Real-time log data from client environments. Supports KQL and Elasticsearch DSL queries. Data is organized by client namespace (e.g., dacta-*, nagaworld-*, foxwood-*).
- **DACTA TIP**: Threat intelligence platform with IOC indicators, MITRE ATT&CK techniques, and threat reports.
- **Jira Service Management**: Incident tickets, alert history, and escalation records. Project key is DAC.

## Client Context
When a client is selected, scope your SIEM queries to that client's namespace. Available clients and their namespaces:
- Dacta Global (namespace: dacta) — Internal, has EDR + Firewall
- Naga World (namespace: nagaworld) — SOCaaS, has EDR + Firewall
- EM Services (namespace: emservices) — SOCaaS, has EDR + Firewall
- SP Telecom (namespace: sptelecom) — SOCaaS, has EDR + Firewall
- Toyota Financial (namespace: toyotafinancial) — SOCaaS, has EDR + Firewall
- Foxwood Technology (namespace: foxwood) — SOCaaS, Firewall only (NO EDR)
- SPMT (namespace: spmt) — SOCaaS, has EDR + Firewall

## Important Rules
1. ALWAYS use tools to verify claims. Never say "this IP is malicious" without checking DACTA TIP and Elastic first.
2. When searching logs, use appropriate index patterns based on the selected client.
3. For IP lookups, check BOTH DACTA TIP (threat intel) AND Elastic (log presence).
4. For ticket searches, construct appropriate JQL queries.
5. When you find something interesting in logs, proactively suggest follow-up queries the analyst could run.
6. If the user asks about a specific host, search across multiple data sources to build a complete picture.
7. Acknowledge limitations — if a client has no EDR, say so rather than searching non-existent EDR indices.`;

// ── Tool Definitions ──
const TOOLS = [
  {
    name: "search_elastic_siem",
    description: "Search Elastic SIEM logs using Elasticsearch query DSL. Use this to search for log events, alerts, network connections, process executions, authentication events, and any other log data. You can search across all clients or filter by a specific client namespace. Supports aggregations for statistics and breakdowns.",
    input_schema: {
      type: "object",
      properties: {
        index: {
          type: "string",
          description: "Elasticsearch index pattern. Use 'logs-*' for all logs, or scope to a client like 'logs-*' with a namespace filter. For CrowdStrike alerts use '.ds-logs-crowdstrike.alert-{namespace}-*'. For firewall logs use 'logs-panw.panos-{namespace}-*'. Default: 'logs-*'"
        },
        query: {
          type: "object",
          description: "Elasticsearch query DSL object. Use bool queries with must/should/filter clauses. Common fields: message, source.ip, destination.ip, host.name, user.name, process.name, event.action, data_stream.namespace, data_stream.dataset, @timestamp"
        },
        size: {
          type: "integer",
          description: "Number of results to return. Default 10, max 50."
        },
        sort: {
          type: "array",
          description: "Sort order. Default: [{'@timestamp': 'desc'}]"
        },
        aggs: {
          type: "object",
          description: "Aggregations for statistics. Example: { 'by_host': { 'terms': { 'field': 'host.name', 'size': 10 } } }"
        },
        _source: {
          type: "array",
          description: "Fields to return in results. If omitted, returns all fields."
        }
      },
      required: ["query"]
    }
  },
  {
    name: "lookup_ioc_opencti",
    description: "Look up an Indicator of Compromise (IOC) in DACTA TIP threat intelligence platform. Checks if an IP address, domain, file hash (MD5/SHA1/SHA256), or URL has been flagged as malicious or suspicious. Returns threat score, indicator type, and associated threat reports.",
    input_schema: {
      type: "object",
      properties: {
        value: {
          type: "string",
          description: "The IOC value to look up: IP address, domain name, file hash, or URL."
        },
        type: {
          type: "string",
          enum: ["ipv4-addr", "domain-name", "file-md5", "file-sha1", "file-sha256", "url"],
          description: "The type of IOC being looked up."
        }
      },
      required: ["value", "type"]
    }
  },
  {
    name: "lookup_mitre_technique",
    description: "Look up a MITRE ATT&CK technique by its ID (e.g., T1059, T1059.001) in DACTA TIP. Returns technique name, description, kill chain phases/tactics, and associated procedures.",
    input_schema: {
      type: "object",
      properties: {
        technique_id: {
          type: "string",
          description: "MITRE ATT&CK technique ID, e.g., 'T1059', 'T1059.001', 'T1566.001'"
        }
      },
      required: ["technique_id"]
    }
  },
  {
    name: "search_jira_tickets",
    description: "Search Jira Service Management tickets using JQL (Jira Query Language). Use to find incident tickets, check alert history, look up specific tickets by key, or search by priority/status/assignee. The project key is DAC.",
    input_schema: {
      type: "object",
      properties: {
        jql: {
          type: "string",
          description: "JQL query string. Examples: 'project = DAC AND priority = P1 ORDER BY created DESC', 'key = DAC-18658', 'project = DAC AND text ~ \"ransomware\" ORDER BY created DESC'"
        },
        max_results: {
          type: "integer",
          description: "Maximum number of results. Default 10, max 50."
        },
        fields: {
          type: "array",
          description: "Specific fields to return. Default: ['summary', 'status', 'priority', 'created', 'assignee', 'description', 'customfield_10050']"
        }
      },
      required: ["jql"]
    }
  },
  {
    name: "get_jira_ticket_details",
    description: "Get full details of a specific Jira ticket including description, comments, and all custom fields. Use when you need the complete ticket content for investigation context.",
    input_schema: {
      type: "object",
      properties: {
        ticket_key: {
          type: "string",
          description: "Jira ticket key, e.g., 'DAC-18658'"
        }
      },
      required: ["ticket_key"]
    }
  }
];

// ── Tool Execution Functions ──

async function executeElasticSearch(params) {
  if (!ELASTIC_URL || !ELASTIC_API_KEY) {
    return { error: 'Elastic SIEM not configured. ELASTIC_URL and ELASTIC_API_KEY environment variables required.' };
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
    
    // Summarize results to fit Claude's context
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
        event_action: src.event?.action,
        event_category: src.event?.category,
        event_outcome: src.event?.outcome,
        dataset: src.data_stream?.dataset,
        namespace: src.data_stream?.namespace,
        rule_name: src.rule?.name,
        agent_name: src.agent?.name,
        // Include raw source for smaller results
        _raw: total <= 3 ? src : undefined
      };
    });
    
    const aggs = {};
    if (data.aggregations) {
      for (const [key, val] of Object.entries(data.aggregations)) {
        if (val.buckets) {
          aggs[key] = val.buckets.slice(0, 20).map(b => ({ key: b.key, count: b.doc_count }));
        } else if (val.value !== undefined) {
          aggs[key] = val.value;
        }
      }
    }
    
    return { total, hits, aggregations: Object.keys(aggs).length > 0 ? aggs : undefined, timed_out: data.timed_out };
  } catch (err) {
    return { error: `Elastic query failed: ${err.message}` };
  }
}

async function executeLookupIOC(params) {
  const { value, type } = params;
  
  // Build the STIX pattern based on type
  let patternSearch = value;
  let gqlQuery;
  
  if (type === 'ipv4-addr') {
    gqlQuery = `{ indicators(first: 10, filters: { mode: and, filters: [{ key: "pattern", values: ["${value}"], operator: eq }] }) { edges { node { id name pattern x_opencti_score pattern_type created_at objectLabel { id value } } } } stixCyberObservables(first: 5, filters: { mode: and, filters: [{ key: "value", values: ["${value}"] }] }) { edges { node { id entity_type observable_value x_opencti_score created_at } } } }`;
  } else if (type === 'domain-name') {
    gqlQuery = `{ indicators(first: 10, filters: { mode: and, filters: [{ key: "pattern", values: ["${value}"], operator: eq }] }) { edges { node { id name pattern x_opencti_score pattern_type created_at objectLabel { id value } } } } }`;
  } else {
    gqlQuery = `{ indicators(first: 10, filters: { mode: and, filters: [{ key: "pattern", values: ["${value}"], operator: eq }] }) { edges { node { id name pattern x_opencti_score pattern_type created_at objectLabel { id value } } } } }`;
  }

  try {
    const resp = await fetch(`${OPENCTI_URL}/graphql`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENCTI_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query: gqlQuery })
    });
    const data = await resp.json();
    
    const indicators = data.data?.indicators?.edges?.map(e => ({
      name: e.node.name,
      pattern: e.node.pattern,
      score: e.node.x_opencti_score,
      type: e.node.pattern_type,
      created: e.node.created_at,
      labels: e.node.objectLabel?.map(l => l.value) || []
    })) || [];
    
    const observables = data.data?.stixCyberObservables?.edges?.map(e => ({
      type: e.node.entity_type,
      value: e.node.observable_value,
      score: e.node.x_opencti_score,
      created: e.node.created_at
    })) || [];
    
    return {
      ioc_value: value,
      ioc_type: type,
      indicators_found: indicators.length,
      indicators,
      observables_found: observables.length,
      observables,
      verdict: indicators.length > 0 ? 'FLAGGED_IN_THREAT_INTEL' : 'NOT_FOUND_IN_THREAT_INTEL'
    };
  } catch (err) {
    return { error: `DACTA TIP lookup failed: ${err.message}`, ioc_value: value };
  }
}

async function executeMITRELookup(params) {
  const { technique_id } = params;
  const gqlQuery = `{ attackPatterns(first: 5, filters: { mode: and, filters: [{ key: "x_mitre_id", values: ["${technique_id}"], operator: eq }] }) { edges { node { id name description x_mitre_id killChainPhases { id kill_chain_name phase_name } objectLabel { id value } } } } }`;

  try {
    const resp = await fetch(`${OPENCTI_URL}/graphql`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${OPENCTI_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query: gqlQuery })
    });
    const data = await resp.json();
    
    const patterns = data.data?.attackPatterns?.edges?.map(e => ({
      mitre_id: e.node.x_mitre_id,
      name: e.node.name,
      description: e.node.description ? (e.node.description.length > 1000 ? e.node.description.substring(0, 1000) + '...' : e.node.description) : null,
      tactics: e.node.killChainPhases?.map(kc => kc.phase_name) || [],
      labels: e.node.objectLabel?.map(l => l.value) || []
    })) || [];
    
    return { technique_id, found: patterns.length > 0, techniques: patterns };
  } catch (err) {
    return { error: `MITRE lookup failed: ${err.message}`, technique_id };
  }
}

async function executeJiraSearch(params) {
  if (!JIRA_EMAIL || !JIRA_API_TOKEN) {
    return { error: 'Jira not configured. JIRA_EMAIL and JIRA_API_TOKEN environment variables required.' };
  }
  
  const jql = params.jql;
  const maxResults = Math.min(params.max_results || 10, 50);
  const fields = params.fields || ['summary', 'status', 'priority', 'created', 'assignee', 'description', 'customfield_10050'];
  
  try {
    const resp = await fetch(`https://${JIRA_INSTANCE}/rest/api/3/search`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString('base64')}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ jql, maxResults, fields })
    });
    const data = await resp.json();
    
    const issues = (data.issues || []).map(iss => {
      const f = iss.fields || {};
      return {
        key: iss.key,
        summary: f.summary,
        status: f.status?.name,
        priority: f.priority?.name,
        severity: f.customfield_10050?.value,
        created: f.created,
        assignee: f.assignee?.displayName,
        description: f.description ? extractJiraText(f.description).substring(0, 500) : null
      };
    });
    
    return { total: data.total || 0, issues };
  } catch (err) {
    return { error: `Jira search failed: ${err.message}` };
  }
}

async function executeJiraTicketDetails(params) {
  if (!JIRA_EMAIL || !JIRA_API_TOKEN) {
    return { error: 'Jira not configured.' };
  }
  
  const { ticket_key } = params;
  
  try {
    // Fetch ticket + comments in parallel
    const [ticketResp, commentsResp] = await Promise.all([
      fetch(`https://${JIRA_INSTANCE}/rest/api/3/issue/${ticket_key}`, {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString('base64')}`,
          'Accept': 'application/json'
        }
      }),
      fetch(`https://${JIRA_INSTANCE}/rest/api/3/issue/${ticket_key}/comment?orderBy=-created&maxResults=10`, {
        headers: {
          'Authorization': `Basic ${Buffer.from(`${JIRA_EMAIL}:${JIRA_API_TOKEN}`).toString('base64')}`,
          'Accept': 'application/json'
        }
      })
    ]);
    
    const ticket = await ticketResp.json();
    const commentsData = await commentsResp.json();
    
    const f = ticket.fields || {};
    const comments = (commentsData.comments || []).map(c => ({
      author: c.author?.displayName,
      created: c.created,
      body: c.body ? extractJiraText(c.body).substring(0, 800) : ''
    }));
    
    return {
      key: ticket.key,
      summary: f.summary,
      status: f.status?.name,
      priority: f.priority?.name,
      severity: f.customfield_10050?.value,
      created: f.created,
      updated: f.updated,
      assignee: f.assignee?.displayName,
      reporter: f.reporter?.displayName,
      description: f.description ? extractJiraText(f.description).substring(0, 2000) : null,
      labels: f.labels || [],
      comments: comments.slice(0, 10)
    };
  } catch (err) {
    return { error: `Jira ticket fetch failed: ${err.message}`, ticket_key };
  }
}

// Helper: Extract plain text from Jira ADF (Atlassian Document Format)
function extractJiraText(doc) {
  if (typeof doc === 'string') return doc;
  if (!doc || !doc.content) return '';
  
  function walk(nodes) {
    let text = '';
    for (const node of (nodes || [])) {
      if (node.type === 'text') {
        text += node.text || '';
      } else if (node.type === 'hardBreak') {
        text += '\n';
      } else if (node.type === 'paragraph' || node.type === 'heading') {
        text += walk(node.content || []) + '\n';
      } else if (node.type === 'bulletList' || node.type === 'orderedList') {
        for (const item of (node.content || [])) {
          text += '• ' + walk(item.content || []);
        }
      } else if (node.type === 'codeBlock') {
        text += walk(node.content || []) + '\n';
      } else if (node.content) {
        text += walk(node.content);
      }
    }
    return text;
  }
  
  return walk(doc.content).trim();
}

// ── Execute a tool call ──
async function executeTool(name, input) {
  switch (name) {
    case 'search_elastic_siem':
      return await executeElasticSearch(input);
    case 'lookup_ioc_opencti':
      return await executeLookupIOC(input);
    case 'lookup_mitre_technique':
      return await executeMITRELookup(input);
    case 'search_jira_tickets':
      return await executeJiraSearch(input);
    case 'get_jira_ticket_details':
      return await executeJiraTicketDetails(input);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ── Server-Side Usage Logging (SIEMLess DB) ──
// Logs LLM usage with service role key, bypassing RLS safely.
// Fire-and-forget — errors are logged but do not block the response.
async function logUsageServerSide({ model, usage, toolCallLog, piiStats, sessionId, latencyMs }) {
  if (!SUPABASE_SERVICE_KEY) return; // Skip if not configured
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/llm_usage_log`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        task_type: 'copilot_query',
        model: model,
        provider: 'anthropic',
        input_tokens: usage?.input_tokens || 0,
        output_tokens: usage?.output_tokens || 0,
        latency_ms: latencyMs || 0,
        estimated_cost_usd: 0,
        fallback_used: false,
        related_entity_type: 'copilot_session',
        related_entity_id: sessionId || null
      })
    });
  } catch (err) {
    console.error('[Copilot] Usage logging failed (non-blocking):', err.message);
  }
}

// ── Vercel Config ──
export const config = {
  maxDuration: 120 // seconds — allows for multi-tool agentic loops
};

// ── Conversation History Trimming ──
// Keeps the conversation manageable by summarizing older assistant messages
function trimConversation(messages) {
  if (!messages || messages.length <= 4) return messages;
  
  const trimmed = [];
  const keepRecent = 4; // Keep the last 4 messages in full (2 exchanges)
  
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    const isRecent = i >= messages.length - keepRecent;
    
    if (isRecent) {
      // Keep recent messages in full
      trimmed.push(msg);
    } else if (msg.role === 'user' && typeof msg.content === 'string') {
      // Keep user messages but truncate if very long
      trimmed.push({
        role: 'user',
        content: msg.content.length > 500 ? msg.content.substring(0, 500) + '... [truncated]' : msg.content
      });
    } else if (msg.role === 'assistant' && typeof msg.content === 'string') {
      // Summarize older assistant text responses
      trimmed.push({
        role: 'assistant',
        content: msg.content.length > 800 ? msg.content.substring(0, 800) + '\n\n[Earlier analysis truncated for brevity — key findings above]' : msg.content
      });
    } else if (msg.role === 'assistant' && Array.isArray(msg.content)) {
      // This is a tool-use turn from the agentic loop — skip it entirely
      // (tool_use blocks + tool_result blocks from prior turns are not needed)
      continue;
    } else if (msg.role === 'user' && Array.isArray(msg.content)) {
      // This is a tool_result turn — skip it
      continue;
    } else {
      trimmed.push(msg);
    }
  }
  
  // Ensure valid alternating user/assistant pattern
  // Claude requires messages to alternate, so fix any broken sequences
  const fixed = [];
  for (let i = 0; i < trimmed.length; i++) {
    const msg = trimmed[i];
    if (fixed.length === 0) {
      fixed.push(msg);
    } else if (fixed[fixed.length - 1].role === msg.role) {
      // Same role back-to-back — merge or skip
      if (msg.role === 'user' && typeof msg.content === 'string' && typeof fixed[fixed.length - 1].content === 'string') {
        fixed[fixed.length - 1].content += '\n' + msg.content;
      } else {
        // Skip duplicate role
        continue;
      }
    } else {
      fixed.push(msg);
    }
  }
  
  return fixed;
}

// ── Main Handler ──
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const requestStart = Date.now();

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY environment variable not configured.' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { messages, client_context } = body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array is required' });
    }

    // ── PII Tokenization Vault ──
    // Initialize a per-request vault. All PII is tokenized before Claude sees it.
    // Tool call arguments are detokenized server-side before hitting real APIs.
    // Tool results are re-tokenized before returning to Claude.
    // Final response is detokenized before returning to the analyst.
    const vault = new PiiVault();

    // Register known client/org names for tokenization
    if (client_context?.name) {
      vault.registerClientNames([client_context.name]);
    }
    // Register all known client names for cross-client protection
    const KNOWN_CLIENTS = ['Naga World', 'NagaWorld', 'EM Services', 'SP Telecom',
      'Toyota Financial', 'Foxwood Technology', 'Foxwood', 'SPMT', 'SP Media',
      'SilverKey', 'Silver Key', 'ADV Partners', 'Dacta Training', 'Dacta Global'];
    vault.registerClientNames(KNOWN_CLIENTS);

    // Build system prompt with client context
    let systemPrompt = SYSTEM_PROMPT;
    if (client_context) {
      systemPrompt += `\n\n## Current Session Context\n- Selected client: ${client_context.name || 'All Clients'}\n- Client namespace: ${client_context.namespace || 'all'}\n- Client type: ${client_context.type || 'unknown'}\n- Available connectors: ${(client_context.connectors || []).map(c => c.display_name + ' (' + c.connector_type + ')').join(', ') || 'unknown'}`;
      if (client_context.namespace && client_context.namespace !== 'all') {
        systemPrompt += `\n\n**CRITICAL: A specific client is selected. You MUST scope ALL Elastic SIEM queries to namespace "${client_context.namespace}" by adding a filter on data_stream.namespace. Use index pattern "logs-*-${client_context.namespace}-*" or add {"term":{"data_stream.namespace":"${client_context.namespace}"}} to your query filter. Do NOT return results from other clients. For Jira queries, filter by organization "${client_context.name}".`;
      }
    }
    // Tokenize system prompt (protects client names in context)
    systemPrompt = vault.tokenizeSystemPrompt(systemPrompt);

    // ── Model Strategy ──
    // Haiku for tool rounds (fast, cheap, higher rate limits: 50K input tokens/min)
    // Sonnet for final synthesis (higher quality analysis)
    const TOOL_MODEL = 'claude-haiku-4-5-20251001';
    const SYNTH_MODEL = 'claude-sonnet-4-20250514';

    // ── API call with retry on 429 ──
    async function callClaude(body, retries = 2) {
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
          // Rate limited — wait and retry
          const waitSec = 10 + (attempt * 5); // 10s, then 15s
          console.log(`[Copilot] Rate limited (429), waiting ${waitSec}s before retry ${attempt + 1}/${retries}`);
          await new Promise(r => setTimeout(r, waitSec * 1000));
          continue;
        }

        if (!resp.ok) {
          const errText = await resp.text();
          console.error('[Copilot] Claude API error:', resp.status, errText);
          throw new Error(`Claude API error: ${resp.status}`);
        }

        return await resp.json();
      }
    }

    // Trim conversation history to avoid timeout on follow-ups
    let currentMessages = trimConversation(messages);

    // Tokenize ALL messages before Claude sees them
    currentMessages = vault.tokenizeMessages(currentMessages);
    console.log('[Copilot] PII Vault initialized:', JSON.stringify(vault.getStats()));
    const maxToolRounds = 4; // Max 4 tool rounds to stay within rate limits
    let iteration = 0;
    let toolCallLog = [];

    while (iteration < maxToolRounds + 1) { // +1 for the final synthesis call
      iteration++;
      const isLastRound = iteration > maxToolRounds;

      // Tool rounds: Haiku (fast, high rate limit)
      // Final synthesis: Sonnet (quality), no tools so it MUST produce text
      const callBody = {
        model: isLastRound ? SYNTH_MODEL : TOOL_MODEL,
        max_tokens: isLastRound ? 4096 : 2048,
        system: systemPrompt,
        messages: currentMessages
      };
      if (!isLastRound) {
        callBody.tools = TOOLS;
      }

      const claudeData = await callClaude(callBody);

      // Check if Claude wants to use tools (only possible if tools were provided)
      if (claudeData.stop_reason === 'tool_use' && !isLastRound) {
        const toolUseBlocks = claudeData.content.filter(b => b.type === 'tool_use');
        
        // Add Claude's response (with tool_use) to messages
        currentMessages.push({ role: 'assistant', content: claudeData.content });

        // Execute all tool calls in parallel
        // PII Flow: Claude sends tokenized args → detokenize → real API → tokenize results → back to Claude
        const toolResults = await Promise.all(toolUseBlocks.map(async (toolBlock) => {
          // Detokenize tool arguments so real APIs get real values
          const realInput = vault.detokenizeDeep(toolBlock.input);
          const result = await executeTool(toolBlock.name, realInput);
          // Tokenize tool results before Claude sees them
          const tokenizedResult = vault.tokenizeDeep(result);
          toolCallLog.push({
            tool: toolBlock.name,
            input: toolBlock.input, // Log the tokenized version (safe)
            output_summary: result.error ? result.error : `${JSON.stringify(result).length} bytes`
          });
          return {
            type: 'tool_result',
            tool_use_id: toolBlock.id,
            content: JSON.stringify(tokenizedResult)
          };
        }));

        // Add tool results back for Claude to process
        currentMessages.push({ role: 'user', content: toolResults });
        continue;
      }

      // Claude produced a text response — extract and detokenize for the analyst
      const textBlocks = claudeData.content.filter(b => b.type === 'text');
      const tokenizedResponse = textBlocks.map(b => b.text).join('\n');
      // Detokenize: restore real PII values for the analyst's eyes only
      const responseText = vault.detokenize(tokenizedResponse);

      console.log('[Copilot] PII Vault final stats:', JSON.stringify(vault.getStats()));

      // Server-side usage logging (fire-and-forget, non-blocking)
      const requestLatency = Date.now() - requestStart;
      logUsageServerSide({
        model: claudeData.model,
        usage: claudeData.usage,
        toolCallLog,
        piiStats: vault.getStats(),
        latencyMs: requestLatency
      });

      return res.status(200).json({
        response: responseText,
        tool_calls: toolCallLog,
        model: claudeData.model,
        usage: claudeData.usage,
        pii_vault: vault.getStats() // Return stats (never real values) for UI display
      });
    }

    // Should never reach here
    return res.status(200).json({
      response: 'Analysis complete. Please ask a follow-up question if you need more details.',
      tool_calls: toolCallLog,
      model: SYNTH_MODEL,
      usage: {}
    });

  } catch (err) {
    console.error('[Copilot] Handler error:', err);
    return res.status(500).json({ error: err.message });
  }
}
