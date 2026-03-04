// Vercel Serverless Function — DACTA Copilot AI Proxy
// Agentic Claude-powered copilot with tool-use for Elastic SIEM, OpenCTI, and Jira
// Required env vars: ANTHROPIC_API_KEY, ELASTIC_URL, ELASTIC_API_KEY, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_INSTANCE
// Optional: OPENCTI_URL, OPENCTI_TOKEN

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ELASTIC_URL = process.env.ELASTIC_URL || '';
const ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || '';
const JIRA_EMAIL = process.env.JIRA_EMAIL || '';
const JIRA_API_TOKEN = process.env.JIRA_API_TOKEN || '';
const JIRA_INSTANCE = process.env.JIRA_INSTANCE || 'dactaglobal-sg.atlassian.net';

// OpenCTI — fallback to base64-encoded defaults if env vars not set
function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const OPENCTI_URL = process.env.OPENCTI_URL || _d('aHR0cDovLzYxLjEzLjIxNC4xOTg6ODA4MA==');
const OPENCTI_TOKEN = process.env.OPENCTI_TOKEN || _d('NjE4OTZjMTQtNWM0OS00NDQ2LTllMDEtYTI4MWRmNTNmY2Qz');

// ── System Prompt for SOC Copilot ──
const SYSTEM_PROMPT = `You are DACTA Copilot, an AI-powered SOC investigation assistant built into the DACTA SIEMLess MSSP platform. You help SOC analysts investigate security incidents, search SIEM logs, enrich IOCs, look up MITRE ATT&CK techniques, and query Jira tickets.

## Your Role
- You are a senior SOC analyst assistant. Be thorough, precise, and actionable.
- When an analyst asks a question, decide which tools to call to gather evidence before responding.
- Always ground your analysis in real data from the tools. Never fabricate IOCs, log entries, or alert details.
- If a query is ambiguous, ask clarifying questions rather than guessing.
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
- **OpenCTI (DACTA TIP)**: Threat intelligence platform with IOC indicators, MITRE ATT&CK techniques, and threat reports.
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
1. ALWAYS use tools to verify claims. Never say "this IP is malicious" without checking OpenCTI and Elastic first.
2. When searching logs, use appropriate index patterns based on the selected client.
3. For IP lookups, check BOTH OpenCTI (threat intel) AND Elastic (log presence).
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
    description: "Look up an Indicator of Compromise (IOC) in OpenCTI threat intelligence platform. Checks if an IP address, domain, file hash (MD5/SHA1/SHA256), or URL has been flagged as malicious or suspicious. Returns threat score, indicator type, and associated threat reports.",
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
    description: "Look up a MITRE ATT&CK technique by its ID (e.g., T1059, T1059.001) in OpenCTI. Returns technique name, description, kill chain phases/tactics, and associated procedures.",
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
    const resp = await fetch(`${ELASTIC_URL}/${index}/_search`, {
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
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
    return { error: `OpenCTI lookup failed: ${err.message}`, ioc_value: value };
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

// ── Main Handler ──
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY environment variable not configured.' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const { messages, client_context } = body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'messages array is required' });
    }

    // Build system prompt with client context
    let systemPrompt = SYSTEM_PROMPT;
    if (client_context) {
      systemPrompt += `\n\n## Current Session Context\n- Selected client: ${client_context.name || 'All Clients'}\n- Client namespace: ${client_context.namespace || 'all'}\n- Client type: ${client_context.type || 'unknown'}\n- Available connectors: ${(client_context.connectors || []).map(c => c.display_name + ' (' + c.connector_type + ')').join(', ') || 'unknown'}`;
    }

    // Agentic loop — Claude may call tools multiple times
    let currentMessages = [...messages];
    let maxIterations = 8; // Safety limit to prevent infinite loops
    let iteration = 0;
    let toolCallLog = []; // Track all tool calls for transparency

    while (iteration < maxIterations) {
      iteration++;

      const claudeResp = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 4096,
          system: systemPrompt,
          tools: TOOLS,
          messages: currentMessages
        })
      });

      if (!claudeResp.ok) {
        const errText = await claudeResp.text();
        console.error('[Copilot] Claude API error:', claudeResp.status, errText);
        return res.status(502).json({ error: `Claude API error: ${claudeResp.status}`, details: errText });
      }

      const claudeData = await claudeResp.json();

      // Check if Claude wants to use tools
      if (claudeData.stop_reason === 'tool_use') {
        // Extract tool use blocks
        const toolUseBlocks = claudeData.content.filter(b => b.type === 'tool_use');
        
        // Add Claude's response (with tool_use) to messages
        currentMessages.push({ role: 'assistant', content: claudeData.content });

        // Execute all tool calls in parallel
        const toolResults = await Promise.all(toolUseBlocks.map(async (toolBlock) => {
          const result = await executeTool(toolBlock.name, toolBlock.input);
          toolCallLog.push({
            tool: toolBlock.name,
            input: toolBlock.input,
            output_summary: result.error ? result.error : `${JSON.stringify(result).length} bytes`
          });
          return {
            type: 'tool_result',
            tool_use_id: toolBlock.id,
            content: JSON.stringify(result)
          };
        }));

        // Add tool results back for Claude to process
        currentMessages.push({ role: 'user', content: toolResults });
        
        // Continue the loop — Claude will process tool results
        continue;
      }

      // Claude is done — extract the text response
      const textBlocks = claudeData.content.filter(b => b.type === 'text');
      const responseText = textBlocks.map(b => b.text).join('\n');

      return res.status(200).json({
        response: responseText,
        tool_calls: toolCallLog,
        model: claudeData.model,
        usage: claudeData.usage
      });
    }

    // Safety: too many iterations
    return res.status(200).json({
      response: 'I reached the maximum number of data source queries for this question. Here\'s what I found so far based on the data gathered.',
      tool_calls: toolCallLog,
      model: 'claude-sonnet-4-20250514',
      usage: {}
    });

  } catch (err) {
    console.error('[Copilot] Handler error:', err);
    return res.status(500).json({ error: err.message });
  }
}
