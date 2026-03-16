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

// Heimdal credentials (for direct EDR calls)
const HM_BASE = process.env.HEIMDAL_BASE_URL || 'https://dashboard.heimdalsecurity.com/api/heimdalapi/2.0';
const HM_API_KEY = process.env.HEIMDAL_API_KEY || '';
const HM_CUSTOMER_ID = process.env.HEIMDAL_CUSTOMER_ID || '';

function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const OPENCTI_URL = process.env.OPENCTI_URL || _d('aHR0cDovLzYxLjEzLjIxNC4xOTg6ODA4MA==');
const OPENCTI_TOKEN = process.env.OPENCTI_TOKEN || _d('NjE4OTZjMTQtNWM0OS00NDQ2LTllMDEtYTI4MWRmNTNmY2Qz');

// CrowdStrike credentials
const CS_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID || '';
const CS_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET || '';
const CS_BASE_URL = process.env.CROWDSTRIKE_BASE_URL || 'https://api.us-2.crowdstrike.com';

// ═══════════════════════════════════════════════
// Organization Context Loader
// ═══════════════════════════════════════════════
// Org ID resolution: namespace → org_id mapping
// This is the authoritative mapping used when the organizations table
// is empty or unreachable. Keeps investigation working regardless of DB state.
// ═══════════════════════════════════════════════
const NAMESPACE_TO_ORG_ID = {
  'dacta':           '9ce7a126-4e9d-434e-b952-f4c4fce56fa1',
  'nagaworld':       '3a57db8a-7787-414c-9e28-1c14de388d31',
  'emservices':      'bc08ccf3-7143-47ff-97af-07b735208186',
  'sptelecom':       '00145232-a625-4b8b-be55-989b35b1c7c2',
  'toyotafinancial': 'a1cffb2a-32f3-4cb6-b29e-3fa40d8e08a6',
  'foxwood':         'f6463102-adc3-4bdc-a014-ba197d0fada6',
  'spmt':            'b8672c8b-3907-48b0-8c58-b61aa38fbf4b',
  'silverkey':       '93281f08-dbad-4d0d-8656-ab7618f373a4',
  'advpartners':     'bb0db674-d91f-4a21-9c71-984c10749feb',
  'dactatraining':   '3a6e0c3a-0bf7-4614-9299-bb9c02b0507d'
};

// Reverse map: org name fragments → namespace (for name-based resolution)
const ORG_NAME_TO_NAMESPACE = {
  'dacta global': 'dacta', 'dacta': 'dacta',
  'naga world': 'nagaworld', 'nagaworld': 'nagaworld',
  'em services': 'emservices', 'em service': 'emservices',
  'sp telecom': 'sptelecom', 'sptele': 'sptelecom',
  'toyota financial': 'toyotafinancial', 'toyota': 'toyotafinancial',
  'foxwood': 'foxwood', 'foxwood technology': 'foxwood',
  'spmt': 'spmt', 'sp media': 'spmt',
  'silverkey': 'silverkey', 'silver key': 'silverkey',
  'adv partners': 'advpartners', 'advpartners': 'advpartners',
  'dacta training': 'dactatraining', 'dactatraining': 'dactatraining'
};

// Resolves org name → org_id → connectors + log sources
// Uses a 3-tier resolution strategy:
//   1. Query organizations table (DB, via service role key)
//   2. Match orgName against ORG_NAME_TO_NAMESPACE → NAMESPACE_TO_ORG_ID
//   3. Use the namespace parameter directly → NAMESPACE_TO_ORG_ID
// ═══════════════════════════════════════════════
async function loadOrgContext(orgName, namespace) {
  if (!SUPABASE_SERVICE_KEY) return { orgId: null, connectors: [], logSources: [], indexPatterns: [], edrStatus: null };
  const headers = {
    'apikey': SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
    'Accept': 'application/json'
  };
  try {
    // Step 1: Resolve org name to org_id
    // Strategy: Try organizations table first, then fallback to namespace maps
    let orgId = null;
    let resolvedVia = 'none';

    // 1a. Try organizations table (may be empty if RLS blocks or not yet populated)
    if (orgName) {
      try {
        const orgResp = await fetch(`${SUPABASE_URL}/rest/v1/organizations?select=id,name,short_name`, { headers });
        if (orgResp.ok) {
          const orgs = await orgResp.json();
          if (orgs.length > 0) {
            const nameLower = orgName.toLowerCase().trim();
            let org = orgs.find(o => o.name.toLowerCase() === nameLower);
            if (!org) org = orgs.find(o => {
              const dbName = o.name.toLowerCase();
              return (nameLower.includes(dbName) && dbName.length > 3) ||
                     (dbName.includes(nameLower) && nameLower.length > 3);
            });
            if (!org) org = orgs.find(o =>
              o.short_name && o.short_name.length >= 3 && nameLower.includes(o.short_name.toLowerCase())
            );
            if (org) { orgId = org.id; resolvedVia = 'organizations_table'; }
          }
        }
      } catch (e) {
        console.warn('[Investigate] organizations table query failed:', e.message);
      }
    }

    // 1b. Fallback: resolve via org name → namespace → org_id map
    if (!orgId && orgName) {
      const nameLower = orgName.toLowerCase().trim();
      const matchedNS = ORG_NAME_TO_NAMESPACE[nameLower];
      if (matchedNS && NAMESPACE_TO_ORG_ID[matchedNS]) {
        orgId = NAMESPACE_TO_ORG_ID[matchedNS];
        resolvedVia = 'name_to_namespace_map';
      } else {
        // Fuzzy: check if any key is contained in orgName
        for (const [fragment, ns] of Object.entries(ORG_NAME_TO_NAMESPACE)) {
          if (nameLower.includes(fragment) && NAMESPACE_TO_ORG_ID[ns]) {
            orgId = NAMESPACE_TO_ORG_ID[ns];
            resolvedVia = 'name_fragment_match';
            break;
          }
        }
      }
    }

    // 1c. Fallback: resolve via namespace parameter directly
    if (!orgId && namespace) {
      const ns = namespace.toLowerCase().trim();
      if (NAMESPACE_TO_ORG_ID[ns]) {
        orgId = NAMESPACE_TO_ORG_ID[ns];
        resolvedVia = 'namespace_direct';
      }
    }

    if (!orgId) {
      console.log('[Investigate] Could not resolve org_id for:', orgName, '/ namespace:', namespace);
      return { orgId: null, connectors: [], logSources: [], indexPatterns: [], edrStatus: null };
    }
    console.log(`[Investigate] Resolved org_id=${orgId} via ${resolvedVia} (orgName="${orgName}", namespace="${namespace}")`);

    // Step 2: Load connectors and log sources in parallel
    const [connResp, lsResp] = await Promise.all([
      fetch(`${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&select=id,connector_type,vendor,display_name,is_enabled,api_endpoint,auth_type,credentials_ref,health_status,metadata`, { headers }),
      fetch(`${SUPABASE_URL}/rest/v1/client_log_sources?org_id=eq.${orgId}&select=source_name,vendor,source_type,index_pattern,status`, { headers })
    ]);

    // Note: fetch ALL connectors (not just is_enabled=true) so we know the org's full tooling picture
    const allConnectors = connResp.ok ? await connResp.json() : [];
    const enabledConnectors = allConnectors.filter(c => c.is_enabled !== false);
    const logSources = lsResp.ok ? await lsResp.json() : [];

    // Step 3: Extract all unique index patterns
    const indexPatterns = [];
    logSources.forEach(ls => {
      if (ls.index_pattern) {
        ls.index_pattern.split(/\s+/).forEach(idx => {
          if (idx && !indexPatterns.includes(idx)) indexPatterns.push(idx);
        });
      }
    });

    // Step 4: Build EDR status summary (globally aware)
    // This tells the investigation engine EXACTLY what EDR situation the org has
    const edrConnector = allConnectors.find(c => c.connector_type === 'edr');
    let edrStatus = null;
    if (edrConnector) {
      const vendor = (edrConnector.vendor || '').toLowerCase();
      const isRealEDR = edrConnector.is_enabled && vendor !== 'none' && vendor !== 'pending' && vendor !== '';
      const isExplicitlyNoEDR = !edrConnector.is_enabled || vendor === 'none';
      edrStatus = {
        has_edr: isRealEDR,
        explicitly_no_edr: isExplicitlyNoEDR,
        vendor: edrConnector.vendor || 'Unknown',
        display_name: edrConnector.display_name || edrConnector.vendor || 'EDR',
        is_enabled: edrConnector.is_enabled,
        health_status: edrConnector.health_status || 'unknown',
        // For guardrails: if org explicitly has no EDR, don't penalize for missing EDR telemetry
        skip_edr_telemetry_gap: isExplicitlyNoEDR
      };
    } else {
      // No EDR connector record at all — unknown situation, don't assume either way
      edrStatus = {
        has_edr: false,
        explicitly_no_edr: false,
        vendor: null,
        display_name: null,
        is_enabled: false,
        health_status: 'not_configured',
        skip_edr_telemetry_gap: false
      };
    }

    console.log(`[Investigate] Org context loaded: orgId=${orgId}, connectors=${enabledConnectors.length}/${allConnectors.length} (enabled/total), logSources=${logSources.length}, indices=${indexPatterns.length}, EDR: ${edrStatus.has_edr ? edrStatus.vendor : (edrStatus.explicitly_no_edr ? 'NONE (explicit)' : 'unknown')}`);
    return { orgId, connectors: enabledConnectors, allConnectors, logSources, indexPatterns, edrStatus };
  } catch (err) {
    console.error('[Investigate] Failed to load org context:', err.message);
    return { orgId: null, connectors: [], logSources: [], indexPatterns: [], edrStatus: null };
  }
}

// Resolve EDR credentials from org_connectors
async function resolveEDRAuth(connector) {
  if (!connector || !connector.credentials_ref) return null;
  const creds = typeof connector.credentials_ref === 'string'
    ? JSON.parse(connector.credentials_ref) : connector.credentials_ref;
  const vendor = (connector.vendor || '').toLowerCase();

  if (vendor.includes('heimdal')) {
    return {
      vendor: 'heimdal',
      baseUrl: connector.api_endpoint || HM_BASE,
      apiKey: creds.api_key || creds.token || creds.client_secret || HM_API_KEY,
      customerId: creds.customer_id || creds.client_id || HM_CUSTOMER_ID
    };
  }
  if (vendor.includes('crowdstrike')) {
    return {
      vendor: 'crowdstrike',
      baseUrl: connector.api_endpoint || CS_BASE_URL,
      clientId: creds.client_id || CS_CLIENT_ID,
      clientSecret: creds.client_secret || CS_CLIENT_SECRET
    };
  }
  if (vendor.includes('microsoft') || vendor.includes('defender') || vendor.includes('mde')) {
    return {
      vendor: 'mde',
      baseUrl: connector.api_endpoint || 'https://api.securitycenter.microsoft.com',
      tenantId: creds.tenant_id || process.env.MDE_TENANT_ID || '',
      clientId: creds.client_id || process.env.MDE_CLIENT_ID || '',
      clientSecret: creds.client_secret || process.env.MDE_CLIENT_SECRET || ''
    };
  }
  if (vendor.includes('trend') || vendor.includes('vision')) {
    return {
      vendor: 'trendmicro',
      baseUrl: connector.api_endpoint || 'https://api.xdr.trendmicro.com',
      apiToken: creds.api_key || creds.token || process.env.TRENDMICRO_API_TOKEN || ''
    };
  }
  return null;
}

// ═══════════════════════════════════════════════
// PHASE 1: INVESTIGATOR SYSTEM PROMPT
// The LLM acts as an unbiased forensic investigator
// ═══════════════════════════════════════════════
const INVESTIGATOR_PROMPT = `You are a senior SOC forensic investigator at DACTA SIEMLess MSSP. You are conducting Phase 1 of a structured investigation on a security alert.

## Your Mandate
- You are an UNBIASED investigator. You have NO agenda — not to prove true positive, not to prove false positive.
- Follow the evidence wherever it leads. Observe, hypothesize, test, refine.
- Use your tools selectively and only when they are relevant to this alert. Do NOT treat every available connector or tool as relevant evidence. Query only the sources that match the alert context, relevant log sources, and permitted tools listed in the alert context. Don't theorize — VERIFY.
- Document every finding as a neutral observation with its source and significance.

## Investigation Methodology
1. **OBSERVE**: Read the alert data. What do you see? What stands out?
2. **HYPOTHESIZE**: What could explain this alert? (Both malicious and benign explanations)
3. **QUERY**: Use tools to test your hypotheses. Search for corroborating or contradicting evidence.
4. **REFINE**: Based on results, update your understanding. Follow new leads.
5. **DOCUMENT**: Record each finding neutrally — what was found, where, and what it means.

## Playbook Guidance (MANDATORY)
- If a Response Playbook is provided in the alert context, you MUST follow it as the authoritative investigation procedure. Do NOT rephrase, reorder, or skip playbook steps.
- Execute each triage step in the exact order listed. Your investigation narrative should directly reference the playbook steps (e.g., "Per playbook step 3: queried FortiGate for...").
- Use the playbook's recommended investigation queries verbatim as your SIEM queries (substituting actual IOC values for template variables like {{src_ip}}).
- Apply the playbook's false positive guidance as-is when evaluating whether activity is benign — do not invent your own FP criteria.
- Use the playbook's escalation criteria to determine your confidence level and whether to recommend escalation.
- The playbook is written by DACTA's detection engineering team and represents the approved triage procedure for this specific rule. Treat it as SOC SOP, not a suggestion.

## Analyst Precedent Learning
- If an "Analyst Precedent" section is provided, it contains closure notes from previous analysts who resolved similar correlated alerts.
- These notes reveal how experienced analysts handled the same detection rule on the same host/IP — pay close attention to their reasoning.
- If multiple prior analysts concluded a similar alert was a false positive (e.g., scheduled scan, expected admin activity), weight your verdict accordingly but still verify the current instance.
- If prior closures indicate this is a known recurring true positive, escalate with higher confidence.
- Reference specific analyst notes in your findings when they are relevant to your verdict (e.g., "Previous analyst [ticket] noted this is a scheduled scan — current activity matches the same pattern").
- Never copy-paste analyst notes as your own findings — synthesize them into your investigation narrative.

## Tool Usage Strategy — Analyst-Aligned Investigation Flow
Think like a senior DACTA analyst. Follow this investigation order:

### Step 1: Learn from the Analyst Corpus (ALWAYS DO THIS FIRST)
- **Immediately** call query_analyst_corpus with the detection rule name from the alert summary.
- This retrieves how DACTA's experienced analysts previously investigated and resolved the SAME type of alert.
- Study their closure reasoning: What did they look for? What queries did they run? What made them conclude TP vs FP?
- Use their investigation patterns as your starting framework — then verify against the CURRENT alert's specifics.
- If the corpus shows this rule is historically 80%+ false positive (e.g., scheduled scans, known admin tools), still verify but calibrate your prior accordingly.
- If the corpus shows mixed results, pay extra attention to the distinguishing factors analysts noted.

### Step 2: Extract and Pivot on IOCs
- Extract IOCs from the alert context (IPs, hashes, domains, hostnames, processes)
- Identify pivot points: What entities connect this alert to broader activity?

### Step 3: SIEM Evidence Gathering
- Query Elastic SIEM using the SPECIFIC INDEX PATTERNS provided in the alert context (never use generic "logs-*")
- **CRITICAL**: Use ONLY the exact field names from the 'ACTUAL Elasticsearch Field Names' section in the alert context. Do NOT guess field names — wrong field names return 0 hits.
- If field mappings are not available, start with a small match_all query (size 1-2) on the target index to discover the actual document structure before constructing targeted queries.
- Use ONLY the relevant index patterns listed in the alert context. If the context says some vendors or log sources are not relevant, do NOT query them
- Follow the pivot chain: alert source IP → what else did it talk to? → were those targets compromised? → timeline correlation

### Step 4: IP Reputation Check (ALWAYS for public IPs)
- For EVERY public IP address in the alert IOCs, use lookup_ip_reputation to check AbuseIPDB reputation
- This provides quantitative data: abuse confidence score (0-100%), number of reports, ISP, country, and top abuse categories
- An IP with score >= 80% is HIGHLY_MALICIOUS — strong inculpatory evidence
- An IP with score 25-79% is SUSPICIOUS/LOW_RISK — moderate inculpatory evidence
- An IP with score 0% and 0 reports is CLEAN — moderate exculpatory evidence
- Private/reserved IPs are automatically detected and skipped
- Do NOT skip this step — IP reputation is one of the strongest quantitative signals available

### Step 5: Corroborate with Threat Intel & EDR
- Use search_edr ONLY when the alert context explicitly says endpoint telemetry is relevant and permitted
- Check DACTA TIP for IOC reputation and MITRE technique context when the alert contains applicable IOCs or techniques
- Look at alert history on the same host or entity only when that entity is relevant to the alert

### Step 6: Quantitative Evidence Gathering
- Use search_siem with aggregations (aggs) to get EVENT COUNTS, not just individual events
- Example: Count how many times a source IP communicated with a destination in the last 24h vs 7d vs 30d
- Example: Aggregate bytes_sent and bytes_received to quantify data transfer volumes
- Example: Count unique destination IPs contacted by a source to detect scanning behavior
- A single firewall deny event means little; 500 deny events from the same source in 1 hour is a port scan
- Always report QUANTITIES in your findings: "47 connection attempts", "3.2MB transferred", "contacted 128 unique IPs"
- If event counts are 0 for a query, that IS meaningful evidence (absence of activity)
- Never say "suspicious activity detected" without quantifying HOW MUCH activity

### Evidence Quality Rules
- If a query is unsuccessful or returns no meaningful data, treat it as inconclusive or suspicious — never as confirmation of a true positive
- IMPORTANT: Use the exact index patterns listed in the alert context. These are org-specific and different per client.

## Confidence Calibration Guide (MANDATORY)
Your confidence score MUST be calibrated against these anchors. Do NOT default to 40-50% — that range is ONLY for alerts where evidence is genuinely balanced.

- **90-100**: Smoking gun evidence. Confirmed C2 beacon, known malware hash, active data exfiltration with evidence trail.
- **75-89**: Strong evidence pointing one direction. Multiple corroborating signals (e.g., malicious IP + suspicious process + lateral movement indicators).
- **60-74**: Moderate evidence with some corroboration. Alert context + 1-2 supporting SIEM findings, but no definitive proof.
- **40-59**: Genuinely ambiguous. Evidence is roughly balanced between malicious and benign explanations. Use this range ONLY when you truly cannot lean either way.
- **25-39**: Leaning benign. Some suspicious elements but significant benign explanations exist (e.g., known admin tool, scheduled task, internal scanning).
- **10-24**: Likely benign. Strong indicators of legitimate activity (known IT automation, documented business process, previously whitelisted).
- **0-9**: Definitively benign. Confirmed false positive with clear documentation.

Priority-based priors (adjust based on evidence):
- P1/Critical alerts: Start at 70 (high severity = high prior) and adjust based on evidence
- P2/High alerts: Start at 60 and adjust
- P3/Medium alerts: Start at 45 and adjust
- P4/Low alerts: Start at 30 and adjust

IMPORTANT: The confidence score should reflect the DIRECTION and STRENGTH of evidence, not just uncertainty. A P1 ransomware alert with corroborating SIEM logs should score 80+. A P4 port scan from an internal scanner should score 15-25.

QUANTITATIVE CALIBRATION:
- AbuseIPDB score >= 80% for an involved IP: +20 confidence toward TP
- AbuseIPDB score == 0% with 0 reports: +15 confidence toward FP
- 100+ blocked firewall events from same source: strong indicator of scanning (usually FP for the target)
- Zero bytes transferred in network events: strong FP indicator (connection never established)
- 5+ correlated Jira tickets with same rule on same host: strong recurring pattern signal

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
  "confidence_rationale": "Brief explanation of why you chose this specific confidence score",
  "open_questions": ["Things that couldn't be answered with available tools"],
  "analyst_corpus_insights": {
    "corpus_queried": true,
    "historical_pattern": "Summary of how analysts historically handled this rule (e.g., '4/5 closed as FP due to scheduled scans')",
    "key_analyst_patterns": ["Pattern 1 from analyst corpus", "Pattern 2"]
  },
  "tools_summary": {
    "total_queries": 0,
    "siem_queries": 0,
    "edr_queries": 0,
    "tip_lookups": 0,
    "corpus_queries": 0,
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
- If a VERDICT GUARDRAIL section is present in the alert context, multiple critical queries failed or lacked telemetry coverage. Clean negative results are excluded from this guardrail. You MUST NOT output TRUE_POSITIVE in this case — use SUSPICIOUS instead and note which queries failed or lacked telemetry.
- If Jira cross-ticket correlation shows related tickets, factor the pattern (recurring rule firings on same host/IP) into your assessment.
- If analyst learning from closed tickets is provided, use it as historical context to refine hypotheses, compare patterns, and identify likely benign workflows or recurring threat behaviors — but do not treat historical analyst comments as stronger evidence than current-ticket SIEM or threat-intel findings.
- If an analyst_corpus section is provided with historical investigation data for the same detection rule, reference the pattern summary (e.g., "4/5 prior instances closed as FP") and key analyst reasoning in your narrative. This is powerful context for calibrating your confidence.

## Confidence Calibration Guide (MANDATORY)
Your confidence score MUST be calibrated against these anchors. Do NOT default to 40-50%.

- **90-100**: Smoking gun evidence. Confirmed C2, known malware hash, active exfiltration.
- **75-89**: Strong directional evidence. Multiple corroborating signals pointing same way.
- **60-74**: Moderate evidence with some corroboration. Leaning one direction but gaps remain.
- **40-59**: Genuinely ambiguous. ONLY use when evidence is truly balanced — this should be RARE.
- **25-39**: Leaning benign. Suspicious elements but strong benign explanations.
- **10-24**: Likely benign. Clear legitimate activity patterns.
- **0-9**: Definitively benign false positive.

Your verdict + confidence must be CONSISTENT:
- TRUE_POSITIVE requires confidence >= 65 (you are asserting this IS malicious)
- FALSE_POSITIVE requires confidence >= 65 (you are asserting this IS benign)
- SUSPICIOUS means you cannot determine direction — confidence should reflect how much additional investigation would help (higher = more data could resolve it, lower = fundamentally ambiguous)

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
  "threat_score": 0-100,
  "key_evidence_count": {"threat": 0, "benign": 0, "inconclusive": 0}
}

The threat_score is INDEPENDENT of your verdict confidence. It represents how THREATENING this alert is on a 0-100 scale: 90+ = critical active threat, 70-89 = high threat likely needs containment, 50-69 = moderate threat needs investigation, 30-49 = low threat likely benign, 0-29 = negligible/false positive. This score helps differentiate alerts even when the verdict is the same.

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
7. Check if Jira cross-ticket correlation reveals a recurring pattern that changes the assessment

## ABSOLUTE RULE — Failed/Empty Query Guardrail
If the alert context contains a VERDICT GUARDRAIL section or notes that critical queries failed or lacked telemetry coverage:
- You MUST NOT conclude TRUE_POSITIVE. The evidence base is incomplete.
- Default to SUSPICIOUS with an explicit list of which queries the analyst needs to verify manually.
- State clearly: "Verdict cannot be confirmed as TRUE POSITIVE because the following queries failed or lacked telemetry: [list]"
- Clean negative results are excluded from this guardrail.
- This rule overrides ALL other reasoning. Even if the remaining evidence looks malicious, incomplete investigation = SUSPICIOUS.

## Confidence Calibration Guide (MANDATORY)
Your final_confidence MUST be calibrated. Do NOT default to 40-50%.

- **90-100**: Smoking gun. Verdict is essentially certain.
- **75-89**: Strong evidence. Verdict is highly likely correct.
- **60-74**: Moderate evidence. Leaning strongly in one direction.
- **40-59**: Genuinely ambiguous. ONLY if evidence is truly balanced. This should be RARE.
- **25-39**: Leaning opposite direction. Some concerning elements but benign explanation is stronger.
- **10-24**: Likely the opposite. Strong evidence it's benign/malicious (opposite of initial assessment).
- **0-9**: Certain the opposite.

Rules:
- TRUE_POSITIVE verdict requires final_confidence >= 65
- FALSE_POSITIVE verdict requires final_confidence >= 65
- If your confidence is below 65 for either TP or FP, you MUST use SUSPICIOUS
- SUSPICIOUS verdict confidence should indicate how THREATENING the alert is: high confidence SUSPICIOUS (65+) = "probably malicious but can't confirm", low confidence SUSPICIOUS (<35) = "probably benign but can't confirm"

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
  "threat_score": 0-100,
  "final_reasoning": "The definitive conclusion after adversarial testing",
  "recommended_actions": [
    {"action": "What to do next", "priority": "HIGH|MEDIUM|LOW", "type": "containment|investigation|documentation|notification"}
  ]
}

The threat_score is INDEPENDENT of verdict confidence. It represents how THREATENING this alert is: 90+ = critical active threat, 70-89 = high threat, 50-69 = moderate, 30-49 = low, 0-29 = negligible. This helps prioritize analyst attention even among SUSPICIOUS verdicts.

CRITICAL: Output ONLY the JSON object. No explanatory text before or after.`;

// ═══════════════════════════════════════════════
// Tool Definitions (shared across phases)
// ═══════════════════════════════════════════════
const INVESTIGATION_TOOLS = [
  {
    name: "search_siem",
    description: "Search Elastic SIEM logs using Elasticsearch query DSL. Query for log events, alerts, network connections, process executions, authentication events. Supports aggregations. ALWAYS use the specific index patterns listed in the alert context — never use generic wildcards like 'logs-*'.",
    input_schema: {
      type: "object",
      properties: {
        index: { type: "string", description: "Elasticsearch index pattern. Use the EXACT index patterns from the 'Available Elasticsearch Indices' section in the alert context. If no specific indices listed, use 'logs-*-{namespace}' (no trailing wildcard)." },
        query: { type: "object", description: "Elasticsearch DSL query. IMPORTANT: Use ONLY the exact field names listed in the 'ACTUAL Elasticsearch Field Names' section of the alert context. Do NOT guess field names — wrong field names will return 0 results." },
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
  },
  {
    name: "search_edr",
    description: "Query the organization's EDR platform (Heimdal/CrowdStrike) for endpoint detections, device info, and security events. Use this to investigate endpoint-level activity beyond SIEM logs.",
    input_schema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["get_detections", "device_search", "query_detections", "get_endpoints"],
          description: "EDR action: 'get_detections' for EDR alerts/detections, 'device_search' for endpoint info by hostname/IP, 'query_detections' for detection search by filter, 'get_endpoints' for endpoint inventory"
        },
        hostname: { type: "string", description: "Filter by hostname" },
        ip: { type: "string", description: "Filter by IP address" },
        start_date: { type: "string", description: "Start date for detection search (ISO format)" },
        end_date: { type: "string", description: "End date for detection search" },
        severity: { type: "string", description: "Severity filter (e.g., 'High', 'Critical')" },
        limit: { type: "integer", description: "Max results (default 10)" }
      },
      required: ["action"]
    }
  },
  {
    name: "query_analyst_corpus",
    description: "Query the analyst investigation corpus — a database of how DACTA's experienced analysts previously investigated and resolved similar alerts. Returns closure reasoning, investigation comments, and resolution patterns from past tickets with the same or similar detection rule. Use this EARLY in your investigation to understand how analysts typically handle this type of alert, what they look for, and what patterns indicate true/false positives.",
    input_schema: {
      type: "object",
      properties: {
        detection_rule: { type: "string", description: "The detection rule name to search for (e.g., 'DACTA Distributed Port Scan Detected', 'DACTA Unusual Host Communication')" },
        org: { type: "string", description: "Organization name to prioritize same-org precedent (optional)" },
        limit: { type: "integer", description: "Max results to return (default 5, max 20)" }
      },
      required: ["detection_rule"]
    }
  },
  {
    name: "lookup_ip_reputation",
    description: "Check an IP address reputation against AbuseIPDB. Returns abuse confidence score (0-100), number of reports, ISP, country, usage type, and top abuse categories. Use this for ANY public IP addresses found in the alert to quickly assess if they are known-malicious, suspicious, or clean. Private/reserved IPs are automatically detected and skipped. CRITICAL: Use this tool early in your investigation for every public IP in the alert IOCs — it provides quantitative reputation data that directly informs your verdict confidence.",
    input_schema: {
      type: "object",
      properties: {
        ip: { type: "string", description: "The IP address to check (IPv4 or IPv6)" },
        max_age_days: { type: "integer", description: "Max age of reports in days (default 90, max 365)" }
      },
      required: ["ip"]
    }
  }
];

function normalizeRelevanceVendor(vendor = '') {
  const value = String(vendor || '').toLowerCase();
  if (value.includes('fortinet') || value.includes('fortigate')) return 'fortinet';
  if (value.includes('palo') || value.includes('panw') || value.includes('pan-os')) return 'paloalto';
  if (value.includes('imperva') || value.includes('incapsula')) return 'imperva';
  if (value.includes('crowdstrike') || value.includes('falcon')) return 'crowdstrike';
  if (value.includes('checkpoint') || value.includes('check point')) return 'checkpoint';
  if (value.includes('sophos')) return 'sophos';
  return value.replace(/[^a-z0-9]/g, '');
}

function inferAlertSourceRelevance(alertContext = {}) {
  const iocs = alertContext.iocs || {};
  const text = [
    alertContext.summary || '',
    alertContext.description || '',
    Array.isArray(alertContext.labels) ? alertContext.labels.join(' ') : (alertContext.labels || ''),
    alertContext.use_case || '',
    (alertContext.techniques || []).map(t => [t.id || '', t.name || '', t.tactic || ''].join(' ')).join(' ')
  ].join(' ').toLowerCase();

  const hasIPs = Array.isArray(iocs.ips) && iocs.ips.length > 0;
  const hasPorts = Array.isArray(iocs.ports) && iocs.ports.length > 0;
  const hasWebIOCs = (Array.isArray(iocs.domains) && iocs.domains.length > 0) || (Array.isArray(iocs.urls) && iocs.urls.length > 0);
  const endpointHints = /(powershell|cmd\.exe|rundll32|wscript|cscript|mshta|regsvr32|schtasks|service|registry|hash|sha256|malware|ransom|trojan|process|command\s*line|child process|parent process|execution|endpoint|crowdstrike|falcon|quarantine|kill_process|logon|signin)/i.test(text);
  const webHints = /(waf|imperva|incapsula|http|https|url|uri|web attack|sqli|sql injection|xss|webshell|application attack|path traversal|owasp|user-agent|referer|cookie)/i.test(text) || hasWebIOCs;
  const networkHints = /(firewall|fortigate|fortinet|palo alto|pan-os|panw|network|traffic|srcip|dstip|source ip|destination ip|internal|outbound|inbound|port\s*\d+|deny|drop|blocked|connection|delivery optimization|vpn)/i.test(text) || hasIPs || hasPorts;

  const vendorMentions = [];
  if (/forti(net|gate)/i.test(text)) vendorMentions.push('fortinet');
  if (/palo alto|pan-os|panw/i.test(text)) vendorMentions.push('paloalto');
  if (/imperva|incapsula/i.test(text)) vendorMentions.push('imperva');
  if (/crowdstrike|falcon/i.test(text)) vendorMentions.push('crowdstrike');

  let mode = 'generic';
  if (webHints && !endpointHints) mode = 'web';
  else if (networkHints && !endpointHints) mode = 'network';
  else if (endpointHints) mode = 'endpoint';

  const preferredFirewallVendors = vendorMentions.filter(v => ['fortinet', 'paloalto', 'imperva', 'checkpoint', 'sophos'].includes(v));
  const allowEDR = endpointHints && mode !== 'web' && !(networkHints && !endpointHints);

  return {
    mode,
    allowEDR,
    vendorMentions,
    preferredFirewallVendors,
    hasIPs,
    hasPorts,
    hasWebIOCs,
    reason: mode === 'web'
      ? 'Web/WAF indicators detected in alert context'
      : mode === 'network'
        ? 'Network/firewall indicators detected in alert context'
        : mode === 'endpoint'
          ? 'Endpoint/process indicators detected in alert context'
          : 'No strong telemetry bias detected from alert context'
  };
}

async function indexHasTicketSignal(indexPattern, alertContext = {}) {
  if (!ELASTIC_URL || !ELASTIC_API_KEY || !indexPattern) return false;
  const iocs = alertContext.iocs || {};
  const should = [];

  (iocs.ips || []).slice(0, 6).forEach(ip => {
    should.push({ term: { 'source.ip': ip } });
    should.push({ term: { 'destination.ip': ip } });
    should.push({ term: { 'related.ip': ip } });
  });
  (iocs.hosts || []).slice(0, 4).forEach(host => {
    should.push({ match_phrase: { 'host.hostname': host } });
    should.push({ match_phrase: { 'host.name': host } });
    should.push({ match_phrase: { 'observer.hostname': host } });
  });
  (iocs.domains || []).slice(0, 4).forEach(domain => {
    should.push({ match_phrase: { 'destination.domain': domain } });
    should.push({ match_phrase: { 'url.domain': domain } });
    should.push({ match_phrase: { 'host.name': domain } });
  });

  if (should.length === 0) return false;

  const body = {
    size: 1,
    query: {
      bool: {
        must: [{ range: { '@timestamp': { gte: 'now-7d' } } }],
        should,
        minimum_should_match: 1
      }
    },
    _source: ['@timestamp']
  };

  try {
    const resp = await fetch(`${ELASTIC_URL}/${indexPattern}/_search`, elasticFetchOptions({
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    }));
    if (!resp.ok) return false;
    const data = await resp.json();
    return (data.hits?.total?.value || 0) > 0;
  } catch (err) {
    return false;
  }
}

async function selectRelevantOrgContext(alertContext = {}, namespace, orgCtx = {}) {
  const base = inferAlertSourceRelevance(alertContext);
  const allLogSources = Array.isArray(orgCtx.logSources) ? orgCtx.logSources.slice() : [];
  const allConnectors = Array.isArray(orgCtx.connectors) ? orgCtx.connectors.slice() : [];
  let filteredLogSources = allLogSources.filter(ls => (ls.status || '').toLowerCase() !== 'disabled');
  let filteredConnectors = allConnectors.slice();

  const isFirewallLike = (item) => {
    const vendor = normalizeRelevanceVendor(item.vendor || item.display_name || '');
    const type = String(item.source_type || item.connector_type || '').toLowerCase();
    return type.includes('firewall') || type.includes('network') || type.includes('waf') || ['fortinet', 'paloalto', 'imperva', 'checkpoint', 'sophos'].includes(vendor);
  };

  if (base.mode === 'web') {
    filteredLogSources = filteredLogSources.filter(ls => normalizeRelevanceVendor(ls.vendor) === 'imperva' || String(ls.source_type || '').toLowerCase().includes('waf'));
    filteredConnectors = filteredConnectors.filter(c => c.connector_type !== 'firewall' || normalizeRelevanceVendor(c.vendor || c.display_name || '') === 'imperva');
  } else if (base.mode === 'network') {
    filteredLogSources = filteredLogSources.filter(ls => isFirewallLike(ls) && normalizeRelevanceVendor(ls.vendor) !== 'imperva');
    filteredConnectors = filteredConnectors.filter(c => c.connector_type !== 'firewall' || normalizeRelevanceVendor(c.vendor || c.display_name || '') !== 'imperva');
  }

  if (base.preferredFirewallVendors.length > 0) {
    filteredLogSources = filteredLogSources.filter(ls => !isFirewallLike(ls) || base.preferredFirewallVendors.includes(normalizeRelevanceVendor(ls.vendor)));
    filteredConnectors = filteredConnectors.filter(c => c.connector_type !== 'firewall' || base.preferredFirewallVendors.includes(normalizeRelevanceVendor(c.vendor || c.display_name || '')));
  }

  if (filteredLogSources.length > 1 && base.hasIPs) {
    const matchedSources = [];
    for (const ls of filteredLogSources.slice(0, 8)) {
      if (ls.index_pattern && await indexHasTicketSignal(ls.index_pattern, alertContext)) {
        matchedSources.push(ls);
      }
    }
    if (matchedSources.length > 0) filteredLogSources = matchedSources;
  }

  if (filteredLogSources.length === 0) filteredLogSources = allLogSources.slice();

  const relevantIndexPatterns = [...new Set(filteredLogSources.map(ls => ls.index_pattern).filter(Boolean))];
  const allowedFirewallVendors = new Set(filteredLogSources.filter(isFirewallLike).map(ls => normalizeRelevanceVendor(ls.vendor)));

  filteredConnectors = filteredConnectors.filter(c => {
    if (c.connector_type === 'edr') return base.allowEDR;
    if (c.connector_type === 'firewall' && allowedFirewallVendors.size > 0) {
      return allowedFirewallVendors.has(normalizeRelevanceVendor(c.vendor || c.display_name || ''));
    }
    return true;
  });

  const suppressedLogSources = allLogSources
    .filter(ls => !filteredLogSources.includes(ls))
    .map(ls => ({ source_name: ls.source_name, vendor: ls.vendor, source_type: ls.source_type }));

  return {
    ...base,
    relevantLogSources: filteredLogSources,
    relevantConnectors: filteredConnectors,
    relevantIndexPatterns
      : relevantIndexPatterns,
    suppressedLogSources
  };
}

function buildRelevantInvestigationToolset(sourceRelevance, edrContext) {
  return INVESTIGATION_TOOLS.filter(tool => {
    if (tool.name !== 'search_edr') return true;
    return !!(sourceRelevance && sourceRelevance.allowEDR && edrContext);
  });
}

// ═══════════════════════════════════════════════
// Elastic Field Mapping Discovery
// Fetches real field names from indices so the LLM
// can generate accurate queries instead of guessing
// ═══════════════════════════════════════════════
async function fetchElasticFieldMappings(indexPatterns) {
  if (!ELASTIC_URL || !ELASTIC_API_KEY || indexPatterns.length === 0) return null;
  try {
    // Use the first few indices (limit to 3 to avoid huge responses)
    const indicesToQuery = indexPatterns.slice(0, 3).join(',');
    const resp = await fetch(`${ELASTIC_URL}/${indicesToQuery}/_mapping`, elasticFetchOptions({
      method: 'GET',
      headers: {
        'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
        'Content-Type': 'application/json'
      }
    }));
    if (!resp.ok) {
      console.log(`[Investigate] Field mapping fetch failed: ${resp.status}`);
      return null;
    }
    const mappings = await resp.json();
    
    // Extract top-level field names from all returned indices, grouped by category
    const fieldsByCategory = {
      network: new Set(),
      host_endpoint: new Set(),
      process: new Set(),
      user_identity: new Set(),
      event_metadata: new Set(),
      file: new Set(),
      timestamp: new Set(),
      other: new Set()
    };

    function categorizeField(fieldPath) {
      const lf = fieldPath.toLowerCase();
      if (lf.includes('timestamp') || lf === '@timestamp' || lf.includes('_time') || lf.includes('date')) return 'timestamp';
      if (lf.startsWith('source.') || lf.startsWith('destination.') || lf.startsWith('network.') || lf.includes('.ip') || lf.includes('.port') || lf.includes('dns.') || lf.includes('url.')) return 'network';
      if (lf.startsWith('host.') || lf.startsWith('agent.') || lf.startsWith('observer.') || lf.startsWith('os.') || lf.includes('hostname')) return 'host_endpoint';
      if (lf.startsWith('process.') || lf.includes('command_line') || lf.includes('executable') || lf.includes('pid')) return 'process';
      if (lf.startsWith('user.') || lf.includes('user_name') || lf.includes('logon') || lf.includes('auth')) return 'user_identity';
      if (lf.startsWith('event.') || lf.startsWith('rule.') || lf.startsWith('data_stream.') || lf.startsWith('ecs.') || lf.includes('message') || lf.includes('tags')) return 'event_metadata';
      if (lf.startsWith('file.') || lf.includes('hash.')) return 'file';
      return 'other';
    }

    // Walk the mappings tree to get dot-notation paths (max depth 3)
    function extractFields(properties, prefix, depth) {
      if (depth > 3 || !properties) return;
      for (const [key, val] of Object.entries(properties)) {
        const fullPath = prefix ? `${prefix}.${key}` : key;
        if (val.properties) {
          extractFields(val.properties, fullPath, depth + 1);
        } else {
          const cat = categorizeField(fullPath);
          fieldsByCategory[cat].add(fullPath);
        }
      }
    }

    for (const indexData of Object.values(mappings)) {
      const props = indexData.mappings?.properties;
      if (props) extractFields(props, '', 0);
    }

    // Build a concise summary (limit fields per category to keep prompt manageable)
    const MAX_PER_CAT = 25;
    const categoryLabels = {
      timestamp: 'Timestamps',
      network: 'Network (IPs, Ports, DNS, URLs)',
      host_endpoint: 'Host / Endpoint / Agent',
      process: 'Process / Command Line',
      user_identity: 'User / Identity',
      event_metadata: 'Event Metadata / Rules / Tags',
      file: 'File / Hash',
      other: 'Other Fields'
    };

    let summary = '';
    let totalFields = 0;
    for (const [cat, fields] of Object.entries(fieldsByCategory)) {
      if (fields.size === 0) continue;
      const sorted = [...fields].sort().slice(0, MAX_PER_CAT);
      totalFields += fields.size;
      summary += `**${categoryLabels[cat]}**: ${sorted.join(', ')}${fields.size > MAX_PER_CAT ? ` ... (+${fields.size - MAX_PER_CAT} more)` : ''}\n`;
    }

    console.log(`[Investigate] Field mappings discovered: ${totalFields} fields across ${Object.keys(mappings).length} indices`);
    return summary || null;
  } catch (err) {
    console.log(`[Investigate] Field mapping discovery error: ${err.message}`);
    return null;
  }
}

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

  // Log the actual query for debugging
  console.log(`[Investigate] SIEM Query → index: ${index}, query: ${JSON.stringify(body.query).substring(0, 500)}`);

  try {
    const resp = await fetch(`${ELASTIC_URL}/${index}/_search`, elasticFetchOptions({
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${ELASTIC_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    }));
    if (!resp.ok) {
      const errText = await resp.text();
      console.log(`[Investigate] SIEM Query FAILED: ${resp.status} — ${errText.substring(0, 300)}`);
      return { error: `Elastic query failed: HTTP ${resp.status}`, connected: false, debug: { index, status: resp.status } };
    }
    const data = await resp.json();
    const total = data.hits?.total?.value || 0;
    console.log(`[Investigate] SIEM Query result: ${total} hits from index ${index}`);
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

// ═══════════════════════════════════════════════
// EDR Tool Execution — Heimdal / CrowdStrike
// Routes to correct vendor based on org connectors
// ═══════════════════════════════════════════════

// CrowdStrike token cache for investigation
let _invCsToken = null;
let _invCsTokenExpiry = 0;

async function getCrowdStrikeToken(auth) {
  const now = Date.now();
  if (_invCsToken && now < _invCsTokenExpiry - 60000) return _invCsToken;
  const resp = await fetch(`${auth.baseUrl}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `client_id=${encodeURIComponent(auth.clientId)}&client_secret=${encodeURIComponent(auth.clientSecret)}`
  });
  if (!resp.ok) throw new Error(`CrowdStrike auth failed: ${resp.status}`);
  const data = await resp.json();
  _invCsToken = data.access_token;
  _invCsTokenExpiry = now + (data.expires_in * 1000);
  return _invCsToken;
}

async function executeSearchEDR(params, edrContext) {
  if (!edrContext || !edrContext.auth) {
    return { error: 'No EDR connector configured for this organization', connected: false };
  }

  const { auth } = edrContext;
  const action = params.action || 'get_detections';

  try {
    if (auth.vendor === 'heimdal') {
      return await executeHeimdalEDR(auth, action, params);
    } else if (auth.vendor === 'crowdstrike') {
      return await executeCrowdStrikeEDR(auth, action, params);
    } else {
      return { error: `Unsupported EDR vendor: ${auth.vendor}`, connected: false };
    }
  } catch (err) {
    return { error: `EDR query failed (${auth.vendor}): ${err.message}`, connected: false };
  }
}

async function executeHeimdalEDR(auth, action, params) {
  const queryParams = { customerId: auth.customerId };
  if (params.hostname) queryParams.machineName = params.hostname;
  if (params.start_date) queryParams.startDate = params.start_date;
  if (params.end_date) queryParams.endDate = params.end_date;
  if (params.severity) queryParams.severity = params.severity;
  queryParams.perPage = Math.min(params.limit || 10, 20);

  let endpoint;
  switch (action) {
    case 'get_detections': endpoint = 'vigilancedetections'; break;
    case 'get_endpoints': endpoint = 'activeclients'; break;
    case 'query_detections': endpoint = 'xtp/getDetections'; break;
    case 'device_search': endpoint = 'activeclients'; break;
    default: endpoint = 'vigilancedetections';
  }

  const qs = new URLSearchParams(queryParams).toString();
  const url = `${auth.baseUrl}/${endpoint}${qs ? '?' + qs : ''}`;
  const resp = await fetch(url, {
    headers: { 'Authorization': `Bearer ${auth.apiKey}`, 'Accept': 'application/json' }
  });

  if (resp.status === 429) {
    return { error: 'Heimdal rate limited (5 req/min). Try again shortly.', connected: true, rate_limited: true };
  }
  if (!resp.ok) {
    const errText = await resp.text();
    return { error: `Heimdal ${action} failed (${resp.status}): ${errText}`, connected: false };
  }

  const data = await resp.json();
  // Normalize to a standard shape
  const items = Array.isArray(data) ? data : (data.data || data.items || data.results || []);
  return {
    connected: true,
    vendor: 'heimdal',
    action,
    total: items.length,
    results: items.slice(0, 20).map(item => ({
      ...item,
      // Truncate long fields
      description: item.description ? (item.description.length > 300 ? item.description.substring(0, 300) + '...' : item.description) : undefined
    }))
  };
}

async function executeCrowdStrikeEDR(auth, action, params) {
  const token = await getCrowdStrikeToken(auth);
  const csHeaders = { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' };

  if (action === 'device_search') {
    let filter = '';
    if (params.hostname) filter = `hostname:'${params.hostname}'`;
    else if (params.ip) filter = `local_ip:'${params.ip}'`;
    if (!filter) return { error: 'device_search requires hostname or ip', connected: true };
    const qs = new URLSearchParams({ filter, limit: Math.min(params.limit || 5, 10) }).toString();
    const idResp = await fetch(`${auth.baseUrl}/devices/queries/devices/v1?${qs}`, { headers: csHeaders });
    if (!idResp.ok) throw new Error(`CS device search: ${idResp.status}`);
    const idData = await idResp.json();
    const deviceIds = idData.resources || [];
    if (!deviceIds.length) return { connected: true, vendor: 'crowdstrike', action, total: 0, results: [] };
    const detResp = await fetch(`${auth.baseUrl}/devices/entities/devices/v2?ids=${deviceIds.join('&ids=')}`, { headers: csHeaders });
    if (!detResp.ok) throw new Error(`CS device details: ${detResp.status}`);
    const detData = await detResp.json();
    return {
      connected: true, vendor: 'crowdstrike', action, total: (detData.resources || []).length,
      results: (detData.resources || []).map(d => ({
        device_id: d.device_id, hostname: d.hostname, local_ip: d.local_ip, external_ip: d.external_ip,
        os_version: d.os_version, platform_name: d.platform_name, last_seen: d.last_seen, status: d.status,
        agent_version: d.agent_version, tags: d.tags || []
      }))
    };
  }

  if (action === 'get_detections' || action === 'query_detections') {
    const parts = [];
    if (params.hostname) parts.push(`device.hostname:'${params.hostname}'`);
    if (params.ip) parts.push(`device.local_ip:'${params.ip}'`);
    if (params.severity) parts.push(`max_severity_displayname:'${params.severity}'`);
    if (params.start_date) parts.push(`created_timestamp:>'${params.start_date}'`);
    const filter = parts.join('+') || '';
    const dParams = new URLSearchParams({
      filter, limit: Math.min(params.limit || 10, 20), sort: 'created_timestamp|desc'
    }).toString();
    const dIdsResp = await fetch(`${auth.baseUrl}/detects/queries/detects/v1?${dParams}`, { headers: csHeaders });
    if (!dIdsResp.ok) throw new Error(`CS detection query: ${dIdsResp.status}`);
    const dIdsData = await dIdsResp.json();
    const dIds = dIdsData.resources || [];
    if (!dIds.length) return { connected: true, vendor: 'crowdstrike', action, total: 0, results: [] };
    const dDetResp = await fetch(`${auth.baseUrl}/detects/entities/summaries/GET/v1`, {
      method: 'POST', headers: { ...csHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: dIds })
    });
    if (!dDetResp.ok) throw new Error(`CS detection details: ${dDetResp.status}`);
    const dDetData = await dDetResp.json();
    return {
      connected: true, vendor: 'crowdstrike', action,
      total: dIdsData.meta?.pagination?.total || dIds.length,
      results: (dDetData.resources || []).slice(0, 20).map(d => ({
        detection_id: d.detection_id, created: d.created_timestamp, status: d.status,
        hostname: d.device?.hostname, local_ip: d.device?.local_ip,
        max_severity: d.max_severity_displayname, confidence: d.max_confidence,
        behaviors: (d.behaviors || []).slice(0, 5).map(b => ({
          tactic: b.tactic, technique: b.technique, technique_id: b.technique_id,
          display_name: b.display_name, severity: b.severity, cmdline: b.cmdline,
          filename: b.filename, user_name: b.user_name, sha256: b.sha256
        }))
      }))
    };
  }

  if (action === 'get_endpoints') {
    // Return summary of managed endpoints
    const resp = await fetch(`${auth.baseUrl}/devices/queries/devices/v1?limit=20&sort=last_seen.desc`, { headers: csHeaders });
    if (!resp.ok) throw new Error(`CS endpoints: ${resp.status}`);
    const data = await resp.json();
    return { connected: true, vendor: 'crowdstrike', action, total: data.meta?.pagination?.total || 0, device_ids: (data.resources || []).slice(0, 10) };
  }

  return { error: `Unknown EDR action: ${action}`, connected: true };
}

// Global EDR context — set per-investigation in handler
let _currentEDRContext = null;

async function executeQueryAnalystCorpus(input) {
  const rule = input.detection_rule || '';
  const org = input.org || '';
  const limit = Math.min(input.limit || 5, 15);
  if (!rule) return { error: 'Missing detection_rule parameter' };

  const baseUrl = process.env.VERCEL_URL
    ? `https://${process.env.VERCEL_URL}`
    : 'https://dacta-siemless.vercel.app';
  const params = new URLSearchParams({ action: 'corpus_by_rule', rule, limit: String(limit) });
  if (org) params.set('org', org);

  // Try SIEMLess DB first (fast, cached), fallback to live Jira
  let corpusData = null;
  let source = 'siemless_db';
  try {
    const resp = await fetch(`${baseUrl}/api/jira?${params.toString()}`);
    if (resp.ok) {
      corpusData = await resp.json();
      // If DB returned empty or errored (table doesn't exist), try live Jira
      if (!corpusData.corpus || corpusData.corpus.length === 0) {
        corpusData = null;
      }
    }
  } catch (e) {
    console.warn('[query_analyst_corpus] DB query failed, trying live Jira:', e.message);
  }

  if (!corpusData) {
    // Fallback: query Jira directly for closed tickets matching this rule
    source = 'jira_live';
    try {
      const liveParams = new URLSearchParams({ action: 'corpus_by_rule_live', rule, limit: String(limit) });
      if (org) liveParams.set('org', org);
      const resp = await fetch(`${baseUrl}/api/jira?${liveParams.toString()}`);
      if (resp.ok) {
        corpusData = await resp.json();
      }
    } catch (e) {
      console.warn('[query_analyst_corpus] Live Jira fallback also failed:', e.message);
      return { error: `Failed to query analyst corpus: ${e.message}`, matches: 0, corpus: [] };
    }
  }

  if (!corpusData || !corpusData.corpus || corpusData.corpus.length === 0) {
    return {
      rule,
      matches: 0,
      corpus: [],
      source,
      summary: `No prior analyst investigations found for rule "${rule}". This may be a new/rare detection rule — proceed with standard investigation methodology.`
    };
  }

  // Summarize the corpus for the LLM: extract key patterns
  const corpus = corpusData.corpus;
  const resolutions = corpus.map(c => c.resolution).filter(Boolean);
  const fpCount = resolutions.filter(r => /false.?pos|benign|whitel|suppress|duplicate|won.*t.*do/i.test(r)).length;
  const tpCount = resolutions.filter(r => /done|reported|escalat|true.?pos|confirm/i.test(r)).length;

  return {
    rule,
    matches: corpus.length,
    source,
    pattern_summary: {
      total_historical_tickets: corpus.length,
      likely_false_positive_closures: fpCount,
      likely_true_positive_closures: tpCount,
      other_closures: corpus.length - fpCount - tpCount
    },
    analyst_investigations: corpus.map(c => ({
      ticket: c.ticket_key,
      org: c.org || 'unknown',
      resolution: c.resolution || 'unknown',
      closure_reasoning: c.closure_reasoning || 'No closure reasoning recorded',
      key_comments: (c.comment_timeline || []).slice(0, 3).map(ct => ({
        analyst: ct.author,
        note: ct.text
      }))
    }))
  };
}

// ── AbuseIPDB IP Reputation Lookup ──
async function executeLookupIPReputation(input) {
  const ip = input.ip || input.ipAddress;
  if (!ip) return { error: 'ip is required' };

  try {
    // Call our AbuseIPDB serverless proxy
    const resp = await fetch(`https://dacta-siemless.vercel.app/api/abuseipdb`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'check_ip', ip, maxAgeInDays: input.max_age_days || 90 })
    });

    if (!resp.ok) {
      const errText = await resp.text();
      // If AbuseIPDB is not configured, return graceful degradation
      if (resp.status === 503) {
        return {
          ip,
          assessment: 'UNAVAILABLE',
          note: 'AbuseIPDB API key not configured. IP reputation check skipped.',
          summary: `${ip} — AbuseIPDB not configured. Treat IP reputation as UNKNOWN.`
        };
      }
      return { error: `AbuseIPDB lookup failed (${resp.status}): ${errText}` };
    }

    const result = await resp.json();
    console.log(`[AbuseIPDB] ${ip}: score=${result.abuseConfidenceScore}, reports=${result.totalReports}, assessment=${result.assessment}`);
    return result;
  } catch (err) {
    console.warn('[AbuseIPDB] Lookup failed for', ip, ':', err.message);
    return {
      ip,
      assessment: 'ERROR',
      error: err.message,
      summary: `${ip} — AbuseIPDB lookup failed: ${err.message}. Treat IP reputation as UNKNOWN.`
    };
  }
}

async function executeTool(name, input) {
  switch (name) {
    case 'search_siem': return await executeSearchSIEM(input);
    case 'lookup_threat_intel': return await executeLookupThreatIntel(input);
    case 'lookup_mitre': return await executeLookupMITRE(input);
    case 'search_edr': return await executeSearchEDR(input, _currentEDRContext);
    case 'query_analyst_corpus': return await executeQueryAnalystCorpus(input);
    case 'lookup_ip_reputation': return await executeLookupIPReputation(input);
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

async function callClaude(body, retries = 3) {
  if (!ANTHROPIC_API_KEY) throw new Error('Anthropic API key not configured');
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
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
        const waitSec = 10 + (attempt * 10);
        console.log(`[Investigate] Claude rate limited, waiting ${waitSec}s (attempt ${attempt + 1}/${retries})`);
        await new Promise(r => setTimeout(r, waitSec * 1000));
        continue;
      }
      if (resp.status === 529 && attempt < retries) {
        const waitSec = 15 + (attempt * 10);
        console.log(`[Investigate] Claude overloaded (529), waiting ${waitSec}s (attempt ${attempt + 1}/${retries})`);
        await new Promise(r => setTimeout(r, waitSec * 1000));
        continue;
      }
      if (!resp.ok) {
        const errText = await resp.text();
        console.error('[Investigate] Claude API error:', resp.status, errText);
        throw new Error(`Claude API error: ${resp.status}`);
      }
      return await resp.json();
    } catch (fetchErr) {
      if (fetchErr.message.includes('Claude API error')) throw fetchErr;
      // Network error — retry
      if (attempt < retries) {
        console.warn(`[Investigate] Claude fetch error (attempt ${attempt + 1}/${retries}):`, fetchErr.message);
        await new Promise(r => setTimeout(r, 5000));
        continue;
      }
      throw fetchErr;
    }
  }
}

async function callOpenAI(body, retries = 3) {
  if (!OPENAI_API_KEY) throw new Error('OpenAI API key not configured');
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const resp = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
      });
      if (resp.status === 429 && attempt < retries) {
        const waitSec = 10 + (attempt * 10);
        console.log(`[Investigate] OpenAI rate limited, waiting ${waitSec}s (attempt ${attempt + 1}/${retries})`);
        await new Promise(r => setTimeout(r, waitSec * 1000));
        continue;
      }
      if (!resp.ok) {
        const errText = await resp.text();
        console.error('[Investigate] OpenAI API error:', resp.status, errText);
        throw new Error(`OpenAI API error: ${resp.status}`);
      }
      return await resp.json();
    } catch (fetchErr) {
      if (fetchErr.message.includes('OpenAI API error')) throw fetchErr;
      if (attempt < retries) {
        console.warn(`[Investigate] OpenAI fetch error (attempt ${attempt + 1}/${retries}):`, fetchErr.message);
        await new Promise(r => setTimeout(r, 5000));
        continue;
      }
      throw fetchErr;
    }
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
async function runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds = 6, provider = 'claude', toolDefs = INVESTIGATION_TOOLS) {
  // Dual-model strategy: Haiku for tool-use rounds (fast, cheap), Sonnet for final synthesis (quality)
  const CLAUDE_TOOL_MODEL = 'claude-haiku-4-5-20251001';
  const CLAUDE_SYNTH_MODEL = 'claude-sonnet-4-20250514';
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
        model: isLast ? CLAUDE_SYNTH_MODEL : CLAUDE_TOOL_MODEL,
        max_tokens: isLast ? 4096 : 2048,
        system: isLast
          ? systemPrompt + '\n\n[FINAL] All tool calls done. Produce your complete JSON response NOW.'
          : systemPrompt,
        messages
      };
      if (!isLast) callBody.tools = toolDefs;
      result = await callClaude(callBody);
    } else {
      // OpenAI path
      const oaiBody = {
        model: OPENAI_MODEL,
        max_tokens: isLast ? 4096 : 2048,
        messages
      };
      if (!isLast) oaiBody.tools = claudeToolsToOpenAI(toolDefs);
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
        // Build enhanced tool log entry with query details for SIEM searches
        const logEntry = {
          tool: tb.name,
          input: tb.input,  // Full input for drill-down
          input_summary: JSON.stringify(tb.input).substring(0, 200),
          result_summary: toolResult.error || `${toolResult.total !== undefined ? toolResult.total + ' hits' : (toolResult.found ? 'FOUND' : 'not found')}`,
          connected: toolResult.connected !== false
        };
        // For SIEM queries, include the index and query for debugging
        if (tb.name === 'search_siem' && realInput) {
          logEntry.siem_index = realInput.index || 'logs-*';
          logEntry.siem_query = JSON.stringify(realInput.query || {}).substring(0, 500);
        }
        toolLog.push(logEntry);
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
async function runPhaseWithFallback(phase, systemPrompt, userMessage, vault, maxToolRounds, toolDefs = INVESTIGATION_TOOLS) {
  const routing = MODEL_ROUTING[phase] || { primary: 'claude', fallback: 'openai' };
  let provider = routing.primary;
  let fallbackUsed = false;

  try {
    const result = await runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds, provider, toolDefs);
    return { ...result, model: provider === 'claude' ? 'claude-haiku/sonnet-4' : 'gpt-4o', fallback_used: false };
  } catch (primaryErr) {
    console.warn(`[Investigate] ${phase} primary (${provider}) failed: ${primaryErr.message}. Falling back to ${routing.fallback}`);
    provider = routing.fallback;
    fallbackUsed = true;
    try {
      const result = await runAgenticPhase(systemPrompt, userMessage, vault, maxToolRounds, provider, toolDefs);
      return { ...result, model: provider === 'claude' ? 'claude-haiku/sonnet-4' : 'gpt-4o', fallback_used: true };
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
  maxDuration: 300
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

    // ── Load Organization Context (connectors + log sources from DB) ──
    const orgName = alert_context.organization || '';
    const orgCtx = await loadOrgContext(orgName, namespace);

    // Set up EDR context for tool execution
    const edrConnector = orgCtx.connectors.find(c => c.connector_type === 'edr');
    let edrAuth = null;
    if (edrConnector) {
      edrAuth = await resolveEDRAuth(edrConnector);
      if (edrAuth) {
        console.log(`[Investigate] EDR auth resolved from org connector: vendor=${edrAuth.vendor}`);
      } else {
        console.log(`[Investigate] EDR connector found (${edrConnector.vendor}) but credentials could not be resolved`);
      }
    }
    // Only fall back to env var defaults if NO EDR connector exists in org_connectors
    // (Don't override an org's configured vendor with a different one from env vars)
    if (!edrAuth && !edrConnector) {
      if (CS_CLIENT_ID && CS_CLIENT_SECRET) {
        edrAuth = { vendor: 'crowdstrike', baseUrl: CS_BASE_URL, clientId: CS_CLIENT_ID, clientSecret: CS_CLIENT_SECRET };
        console.log('[Investigate] EDR fallback to CrowdStrike env vars (no org EDR connector)');
      } else if (HM_API_KEY && HM_CUSTOMER_ID) {
        edrAuth = { vendor: 'heimdal', baseUrl: HM_BASE, apiKey: HM_API_KEY, customerId: HM_CUSTOMER_ID };
        console.log('[Investigate] EDR fallback to Heimdal env vars (no org EDR connector)');
      }
    }
    const sourceRelevance = await selectRelevantOrgContext(alert_context, namespace, orgCtx);
    _currentEDRContext = (sourceRelevance.allowEDR && edrAuth) ? { auth: edrAuth, vendor: edrAuth.vendor } : null;

    // ── Discover actual Elastic field mappings for accurate queries ──
    const effectivePatterns = sourceRelevance.relevantIndexPatterns.length > 0 ? sourceRelevance.relevantIndexPatterns
      : (orgCtx.indexPatterns.length > 0 ? orgCtx.indexPatterns : (namespace ? [`logs-*-${namespace}`] : []));
    const fieldMappings = await fetchElasticFieldMappings(effectivePatterns);

    // ── Build index pattern context for LLM ──
    let indexContext = '';
    if (orgCtx.indexPatterns.length > 0) {
      // Use actual indices from client_log_sources
      const indexList = orgCtx.indexPatterns.map(idx => `  - ${idx}`).join('\n');
      indexContext = `### Available Elasticsearch Indices for This Organization\nUse ONLY these specific index patterns when querying SIEM. Do NOT use generic wildcard patterns like "logs-*":\n${indexList}\n\nFor a broad search across all log sources, use a comma-separated list of these indices or the first matching index for the relevant log type.`;
    } else if (namespace) {
      // Fallback: construct patterns from namespace (less precise)
      indexContext = `### Client Namespace for SIEM queries: ${namespace}\nNo specific index patterns configured. Try these patterns:\n  - logs-*-${namespace} (primary — note: NO trailing wildcard after namespace)\n  - .ds-logs-*-${namespace}-* (data streams)\nIMPORTANT: Scope ALL Elastic queries to this namespace.`;
    }

    // ── Build field mapping context for LLM ──
    let fieldMappingContext = '';
    if (fieldMappings) {
      fieldMappingContext = `\n### ACTUAL Elasticsearch Field Names (from index mappings)\nThese are the REAL field names that exist in the indices. You MUST use ONLY these exact field names in your Elasticsearch queries. Do NOT invent or guess field names.\n${fieldMappings}\nCRITICAL: If a field you want to query is not listed above, try using a match_all query with a small size first to see the actual document structure, or use a wildcard aggregation to discover values.`;
    }

    // ── Build log source summary ──
    const contextLogSources = (sourceRelevance.relevantLogSources && sourceRelevance.relevantLogSources.length > 0) ? sourceRelevance.relevantLogSources : orgCtx.logSources;
    let logSourceSummary = '';
    if (contextLogSources.length > 0) {
      logSourceSummary = '\n### Relevant Log Sources for This Alert\n' + contextLogSources.map(ls =>
        `- **${ls.source_name}** (${ls.vendor}, type: ${ls.source_type}, status: ${ls.status})${ls.index_pattern ? ' — indices: ' + ls.index_pattern : ''}`
      ).join('\n');
    }

    // ── Build connector/tools summary (EDR-aware) ──
    let connectorSummary = '';
    const scopedConnectors = (sourceRelevance.relevantConnectors && sourceRelevance.relevantConnectors.length > 0) ? sourceRelevance.relevantConnectors : orgCtx.connectors;
    const activeConnectors = scopedConnectors.filter(c => c.health_status === 'healthy' || c.health_status === 'degraded');
    if (activeConnectors.length > 0) {
      connectorSummary = '\n### Available Security Tools for This Organization\n' + activeConnectors.map(c =>
        `- **${c.vendor || c.display_name}** (${c.connector_type}) — status: ${c.health_status}`
      ).join('\n');
      if (_currentEDRContext) {
        connectorSummary += `\n\n**EDR Available For This Alert**: ${_currentEDRContext.vendor}. Use the search_edr tool only for endpoint-relevant hypotheses.`;
      }
    }

    // ── Build org-level EDR status context for LLM ──
    // This is CRITICAL: tells the LLM whether missing EDR data is expected or a gap
    const edrStatus = orgCtx.edrStatus;
    let edrStatusSummary = '';
    if (edrStatus) {
      if (edrStatus.has_edr) {
        edrStatusSummary = `\n### Organization EDR Status\nThis organization has **${edrStatus.vendor}** (${edrStatus.display_name}) deployed as their EDR/XDR solution (status: ${edrStatus.health_status}).\nEndpoint telemetry IS available. If endpoint queries return no data, this may indicate a real gap worth investigating.`;
      } else if (edrStatus.explicitly_no_edr) {
        edrStatusSummary = `\n### Organization EDR Status\n**This organization has NO EDR deployed.** This is a known configuration — the client does not use endpoint detection.\nDo NOT count missing endpoint/EDR telemetry as a failure or telemetry gap. Base your verdict entirely on available log sources (SIEM, firewall, threat intel).\nA firewall-only investigation CAN reach FALSE_POSITIVE if the available evidence is sufficiently clear (clean TIP, blocked traffic, known scanner IPs, zero-byte transfers).`;
      } else {
        edrStatusSummary = `\n### Organization EDR Status\nEDR status for this organization is **unknown** (not configured in the connector database).\nTreat missing endpoint data as inconclusive — neither confirm nor deny based on absent EDR telemetry.`;
      }
    }

    const relevanceSummary = `\n### Source Relevance Guardrails\n- Primary telemetry focus: ${sourceRelevance.mode}\n- Endpoint telemetry allowed: ${sourceRelevance.allowEDR ? 'YES' : 'NO'}\n- Reason: ${sourceRelevance.reason}\n${sourceRelevance.suppressedLogSources && sourceRelevance.suppressedLogSources.length > 0 ? '- Suppress these non-relevant sources unless new evidence makes them relevant: ' + sourceRelevance.suppressedLogSources.map(ls => `${ls.vendor || 'Unknown'} (${ls.source_type || 'unknown'})`).join(', ') : '- No source suppressions identified'}\n- IMPORTANT: Do not count failed or empty irrelevant queries as evidence. Treat unanswered questions as inconclusive and escalate to the analyst for confirmation.`;

    const relevantToolset = buildRelevantInvestigationToolset(sourceRelevance, _currentEDRContext);

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
- Devices: ${(alert_context.iocs?.devices || []).join(', ') || 'None'}
- MAC Addresses: ${(alert_context.iocs?.macs || []).join(', ') || 'None'}

### Detected MITRE Techniques
${(alert_context.techniques || []).map(t => `- ${t.id}: ${t.name} [${t.tactic}]`).join('\n') || 'None detected'}

${(() => {
  const di = alert_context.deep_investigation;
  if (!di) return '';
  let sections = [];
  if (di.investigation_mode === 'firewall_only') {
    sections.push('### Investigation Mode: FIREWALL-ONLY (No EDR endpoint agent)');
    sections.push('IMPORTANT: This org has NO EDR telemetry. Rely on firewall logs, geo-location, bytes transferred, temporal patterns, and TIP lookups. Do NOT assert TRUE POSITIVE without SIEM-confirmed evidence. Default to SUSPICIOUS when evidence is insufficient.');
  } else if (di.investigation_mode === 'edr_full' && di.edr_vendor) {
    sections.push('### Investigation Mode: EDR FULL (' + di.edr_vendor + ')');
    sections.push('This org has ' + di.edr_vendor + ' EDR/XDR deployed. Endpoint telemetry is available via direct API. Use search_edr tool when endpoint context is relevant.');
  }
  if (di.dest_geo && di.dest_geo.length > 0) {
    sections.push('### Destination Geo-Location Analysis');
    di.dest_geo.forEach(g => {
      sections.push(`- IP ${g.ip}: ${g.geoBreakdown.map(gb => gb.location + ' (' + gb.count + ' events)').join(', ')} (${g.totalEvents} total)`);
    });
  }
  if (di.bytes_analysis && di.bytes_analysis.length > 0) {
    sections.push('### Bytes Transferred Analysis');
    di.bytes_analysis.forEach(b => {
      sections.push(`- IP ${b.ip}: Total=${b.totalNetworkBytes}B, Src=${b.totalSourceBytes}B, Dst=${b.totalDestBytes}B, Avg=${b.avgBytesPerEvent}B/event, Assessment=${b.assessment}`);
    });
  }
  if (di.temporal_analysis && di.temporal_analysis.length > 0) {
    sections.push('### Temporal Traffic Pattern Analysis');
    di.temporal_analysis.forEach(t => {
      const peakStr = t.peakHours.map(h => h.hour + ':00 UTC (' + h.count + ' events)').join(', ');
      const portStr = t.portBreakdown.map(p => 'port ' + p.port + ' (' + p.count + 'x)').join(', ');
      sections.push(`- IP ${t.ip}: Pattern=${t.assessment}, Peak hours=${peakStr}, Ports=${portStr}`);
    });
  }
  if (di.dest_tip_results && di.dest_tip_results.length > 0) {
    sections.push('### DACTA TIP Lookup Results (Destination IP Pivot)');
    di.dest_tip_results.forEach(t => {
      sections.push(`- ${t.value}: ${t.found ? 'FOUND — Labels: ' + t.labels.join(', ') + ' (Source: ' + t.source + ')' : 'NOT FOUND in TIP — no abuse reports'}`);
    });
  }
  if (di.ip_reputation && di.ip_reputation.length > 0) {
    sections.push('### AbuseIPDB IP Reputation Results');
    di.ip_reputation.forEach(r => {
      sections.push(`- ${r.summary || r.ip + ': ' + r.assessment}`);
    });
  }
  if (di.device_names && di.device_names.length > 0) {
    sections.push(`### Identified Device Names: ${di.device_names.join(', ')}`);
  }
  if (di.mac_addresses && di.mac_addresses.length > 0) {
    sections.push(`### Identified MAC Addresses: ${di.mac_addresses.join(', ')}`);
  }
  return sections.join('\n');
})()}

${(() => {
  const jc = alert_context.jira_correlation;
  if (!jc || jc.length === 0) return '';
  let lines = ['### Jira Cross-Ticket Correlation (' + jc.length + ' related tickets found)'];
  lines.push('These tickets share the same detection rule and host/IP entities within this organization:');
  jc.slice(0, 10).forEach(t => {
    lines.push(`- **${t.key}**: ${t.summary} [Status: ${t.status}, Priority: ${t.priority}, Created: ${t.created}, Assignee: ${t.assignee}]`);
  });
  if (jc.length > 1) {
    lines.push('\nIMPORTANT: Multiple related tickets from the same rule on the same host/IP suggest a RECURRING pattern. Consider whether this represents a persistent threat, a noisy detection rule, or an ongoing campaign.');
  }
  return lines.join('\n');
})()}

${(() => {
  const vg = alert_context.verdict_guardrail;
  if (!vg || !vg.active) return '';
  return `### ⚠️ VERDICT GUARDRAIL ACTIVE
${vg.instruction}
Failed/Empty queries: ${[...(vg.failed_queries || []), ...(vg.empty_queries || [])].join(', ')}
You MUST label your verdict as SUSPICIOUS and list which queries the analyst needs to re-run manually.`;
})()}

${(() => {
  const pb = alert_context.playbook;
  if (!pb) return '';
  let lines = ['### Response Playbook: ' + pb.name + ' (match: ' + pb.match_type + ')'];
  lines.push('MANDATORY: Follow this playbook EXACTLY as written. Execute each triage step in order. Use investigation queries verbatim. Do NOT rephrase or skip steps.');
  if (pb.triage_steps && pb.triage_steps.length > 0) {
    lines.push('\n**Triage Steps:**');
    pb.triage_steps.forEach((s, i) => lines.push((i+1) + '. ' + (typeof s === 'string' ? s : JSON.stringify(s))));
  }
  if (pb.investigation_queries && pb.investigation_queries.length > 0) {
    lines.push('\n**Recommended Investigation Queries:**');
    pb.investigation_queries.forEach(q => {
      if (typeof q === 'object') {
        lines.push('- [' + (q.platform || 'elastic') + '] ' + q.query + (q.description ? ' — ' + q.description : ''));
      } else {
        lines.push('- ' + q);
      }
    });
  }
  if (pb.false_positive_guidance) {
    lines.push('\n**False Positive Guidance:** ' + pb.false_positive_guidance);
  }
  if (pb.escalation_criteria) {
    lines.push('\n**Escalation Criteria:** ' + (typeof pb.escalation_criteria === 'string' ? pb.escalation_criteria : JSON.stringify(pb.escalation_criteria)));
  }
  if (pb.containment_steps && pb.containment_steps.length > 0) {
    lines.push('\n**Containment Steps (if confirmed threat):**');
    pb.containment_steps.forEach((s, i) => lines.push((i+1) + '. ' + (typeof s === 'string' ? s : JSON.stringify(s))));
  }
  return lines.join('\n');
})()}

${(() => {
  const ap = alert_context.analyst_precedent;
  if (!ap || !ap.notes || ap.notes.length === 0) return '';
  let lines = ['### Analyst Precedent (from ' + ap.count + ' resolved correlated ticket(s))'];
  lines.push('Previous analysts have resolved similar alerts. Use their closure notes as context — they may reveal known false positives, expected behavior, or established remediation patterns:');
  ap.notes.forEach((n, i) => {
    lines.push('');
    lines.push('**[' + n.ticket + ']** (analyst: ' + n.analyst + ')');
    lines.push(n.note);
  });
  lines.push('');
  lines.push('IMPORTANT: Analyst precedent is informational context. If prior analysts closed similar alerts as false positives, strongly consider whether the current alert matches the same pattern. However, do NOT blindly follow precedent — always verify against current evidence.');
  return lines.join('\n');
})()}

${indexContext}
${fieldMappingContext}
${logSourceSummary}
${connectorSummary}
${edrStatusSummary}
${relevanceSummary}`;

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
        6, // Allow up to 6 tool rounds for thorough investigation
        relevantToolset
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
        4, // Fewer tool rounds — focused challenge
        relevantToolset
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
