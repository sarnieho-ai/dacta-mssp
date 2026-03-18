// Vercel Serverless Function — AbuseIPDB IP Reputation Proxy
// Checks IP addresses against AbuseIPDB for abuse reports, confidence scores, and ISP info.
// Used by the investigation engine as a key tool for IP reputation assessment.
//
// Required Vercel env vars:
//   ABUSEIPDB_API_KEY — Free tier API key (1,000 checks/day)
//
// Supported actions:
//   check_ip       — Check a single IP address for abuse reports
//   check_batch    — Check multiple IPs (sequential, respects rate limits)
//   ping           — Health check
//
// Rate limit: 1,000 checks/day (free tier). Returns 429 on limit.

const { setCors, requireAuth } = require('./lib/auth');
const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';
const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY || '';

// ── HTTP helper with rate limit handling ──
async function abuseipdbGet(endpoint, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = `${ABUSEIPDB_BASE}/${endpoint}${qs ? '?' + qs : ''}`;

  const resp = await fetch(url, {
    headers: {
      'Key': ABUSEIPDB_KEY,
      'Accept': 'application/json'
    }
  });

  if (resp.status === 429) {
    const retryAfter = resp.headers.get('Retry-After') || '3600';
    const remaining = resp.headers.get('X-RateLimit-Remaining') || '0';
    throw new Error(`AbuseIPDB rate limited (${remaining} remaining). Retry after ${retryAfter}s.`);
  }

  if (resp.status === 422) {
    const err = await resp.json().catch(() => ({}));
    throw new Error(`AbuseIPDB validation error: ${JSON.stringify(err.errors || err)}`);
  }

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`AbuseIPDB ${endpoint} failed (${resp.status}): ${err}`);
  }

  return resp.json();
}

// ── Check single IP ──
async function checkIP(ipAddress, maxAgeInDays = 90) {
  if (!ipAddress) throw new Error('ipAddress is required');

  // Skip private/reserved IPs
  if (/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.|fe80:|::1|fc00:|fd00:)/i.test(ipAddress)) {
    return {
      ipAddress,
      isPublic: false,
      abuseConfidenceScore: 0,
      totalReports: 0,
      isp: 'Private/Reserved',
      domain: 'local',
      countryCode: null,
      usageType: 'Private',
      isWhitelisted: false,
      assessment: 'PRIVATE_IP',
      note: 'Private/reserved IP — not checked against AbuseIPDB'
    };
  }

  const result = await abuseipdbGet('check', {
    ipAddress,
    maxAgeInDays: String(maxAgeInDays),
    verbose: ''
  });

  const data = result.data || {};

  // Build assessment
  let assessment = 'CLEAN';
  const score = data.abuseConfidenceScore || 0;
  const reports = data.totalReports || 0;

  if (score >= 80) assessment = 'HIGHLY_MALICIOUS';
  else if (score >= 50) assessment = 'SUSPICIOUS';
  else if (score >= 25) assessment = 'LOW_RISK';
  else if (reports > 0) assessment = 'REPORTED_BUT_LOW_CONFIDENCE';
  else assessment = 'CLEAN';

  // Extract recent report categories
  const reportCategories = {};
  if (data.reports && Array.isArray(data.reports)) {
    data.reports.forEach(r => {
      (r.categories || []).forEach(cat => {
        reportCategories[cat] = (reportCategories[cat] || 0) + 1;
      });
    });
  }

  // Map category IDs to human-readable names
  const CATEGORY_MAP = {
    1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
    5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
    13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
    17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
    21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
  };

  const topCategories = Object.entries(reportCategories)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([catId, count]) => ({
      id: Number(catId),
      name: CATEGORY_MAP[Number(catId)] || `Category ${catId}`,
      count
    }));

  return {
    ipAddress: data.ipAddress || ipAddress,
    isPublic: data.isPublic !== false,
    abuseConfidenceScore: score,
    totalReports: reports,
    numDistinctUsers: data.numDistinctUsers || 0,
    lastReportedAt: data.lastReportedAt || null,
    isp: data.isp || 'Unknown',
    domain: data.domain || 'Unknown',
    countryCode: data.countryCode || null,
    countryName: data.countryName || null,
    usageType: data.usageType || 'Unknown',
    isWhitelisted: data.isWhitelisted || false,
    isTor: data.isTor || false,
    assessment,
    topCategories,
    // Summary for LLM consumption
    summary: score === 0 && reports === 0
      ? `${ipAddress} — CLEAN. No abuse reports in AbuseIPDB (${data.isp || 'Unknown ISP'}, ${data.countryCode || '??'}).`
      : `${ipAddress} — ${assessment} (confidence: ${score}%, ${reports} reports from ${data.numDistinctUsers || 0} users). ISP: ${data.isp || 'Unknown'}, Country: ${data.countryCode || '??'}. Top abuse categories: ${topCategories.map(c => c.name).join(', ') || 'N/A'}.`
  };
}

// ── Check batch of IPs ──
async function checkBatch(ips, maxAgeInDays = 90) {
  if (!Array.isArray(ips) || ips.length === 0) throw new Error('ips array is required');

  // Limit to 10 IPs per batch to stay within rate limits
  const limitedIPs = ips.slice(0, 10);
  const results = [];

  for (const ip of limitedIPs) {
    try {
      const result = await checkIP(ip, maxAgeInDays);
      results.push(result);
    } catch (err) {
      results.push({
        ipAddress: ip,
        error: err.message,
        assessment: 'ERROR'
      });
      // If rate limited, stop batch
      if (err.message.includes('rate limited')) break;
    }
  }

  // Build batch summary
  const clean = results.filter(r => r.assessment === 'CLEAN' || r.assessment === 'PRIVATE_IP').length;
  const suspicious = results.filter(r => r.assessment === 'SUSPICIOUS' || r.assessment === 'LOW_RISK' || r.assessment === 'REPORTED_BUT_LOW_CONFIDENCE').length;
  const malicious = results.filter(r => r.assessment === 'HIGHLY_MALICIOUS').length;

  return {
    total: results.length,
    clean,
    suspicious,
    malicious,
    results,
    batchSummary: `Checked ${results.length} IPs: ${clean} clean, ${suspicious} suspicious, ${malicious} malicious.`
  };
}

// ── Main handler ──
export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // SECURITY: Require authenticated session
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent


  const body = req.method === 'POST'
    ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body) || {}
    : {};
  const action = req.query.action || body.action;

  if (!action) {
    return res.status(400).json({ error: 'Missing action parameter' });
  }

  if (!ABUSEIPDB_KEY) {
    return res.status(503).json({
      error: 'AbuseIPDB API key not configured',
      configured: false,
      hint: 'Set ABUSEIPDB_API_KEY in Vercel environment variables. Free tier: https://www.abuseipdb.com/account/api'
    });
  }

  try {
    let result;

    switch (action) {
      case 'check_ip':
        result = await checkIP(body.ip || body.ipAddress, body.maxAgeInDays || 90);
        break;

      case 'check_batch':
        result = await checkBatch(body.ips || [], body.maxAgeInDays || 90);
        break;

      case 'ping': {
        try {
          // Check a well-known IP to test connectivity
          const pingResult = await checkIP('8.8.8.8', 1);
          result = {
            status: 'ok',
            authenticated: true,
            testIP: '8.8.8.8',
            testScore: pingResult.abuseConfidenceScore
          };
        } catch (e) {
          result = { status: 'error', authenticated: false, error: e.message };
        }
        break;
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }

    return res.status(200).json(result);

  } catch (err) {
    console.error('[AbuseIPDB]', action, err.message);
    return res.status(err.message.includes('rate limited') ? 429 : 500).json({
      error: err.message,
      action
    });
  }
}
