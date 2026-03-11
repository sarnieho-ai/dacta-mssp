// Vercel Serverless Function — Multi-Scanner IOC Enrichment Aggregator
// Queries multiple threat intelligence sources in parallel and provides
// a consensus-based verdict for each IOC.
//
// Supported scanners:
//   1. VirusTotal   — Multi-vendor AV/URL analysis (IP, domain, hash, URL)
//   2. AbuseIPDB    — IP abuse reputation (IP only)
//   3. CrowdStrike  — Falcon Intel threat intelligence (IP, domain, hash, URL)
//
// Required Vercel env vars:
//   VIRUSTOTAL_API_KEY         — VT API key (free tier: 500/day, 4/min)
//   ABUSEIPDB_API_KEY          — AbuseIPDB API key (free tier: 1000/day)
//   CROWDSTRIKE_CLIENT_ID      — CS OAuth2 client ID (existing)
//   CROWDSTRIKE_CLIENT_SECRET  — CS OAuth2 client secret (existing)
//   CROWDSTRIKE_BASE_URL       — CS base URL (existing)
//
// POST body: { indicators: ["1.2.3.4", "evil.com", "abc123..."] }
// Returns:   { results: { "1.2.3.4": { verdict, confidence, scanners: {...} }, ... }, meta: {...} }

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || '';
const CS_BASE = process.env.CROWDSTRIKE_BASE_URL || 'https://api.us-2.crowdstrike.com';
const CS_CLIENT_ID = process.env.CROWDSTRIKE_CLIENT_ID || '';
const CS_CLIENT_SECRET = process.env.CROWDSTRIKE_CLIENT_SECRET || '';

// ── CrowdStrike token cache ──
let _csToken = null;
let _csTokenExpiry = 0;

async function getCsToken() {
  const now = Date.now();
  if (_csToken && now < _csTokenExpiry - 60000) return _csToken;
  if (!CS_CLIENT_ID || !CS_CLIENT_SECRET) return null;
  try {
    const resp = await fetch(`${CS_BASE}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `client_id=${encodeURIComponent(CS_CLIENT_ID)}&client_secret=${encodeURIComponent(CS_CLIENT_SECRET)}`
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    _csToken = data.access_token;
    _csTokenExpiry = now + (data.expires_in * 1000);
    return _csToken;
  } catch { return null; }
}

// ── IOC type detection ──
function classifyIOC(indicator) {
  const s = (indicator || '').trim();
  if (!s) return 'unknown';
  // IPv4
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) return 'ip';
  // IPv6 (simplified)
  if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) return 'ip';
  // Hash — MD5 (32), SHA1 (40), SHA256 (64)
  if (/^[0-9a-fA-F]{32}$/.test(s)) return 'hash';
  if (/^[0-9a-fA-F]{40}$/.test(s)) return 'hash';
  if (/^[0-9a-fA-F]{64}$/.test(s)) return 'hash';
  // URL
  if (s.startsWith('http://') || s.startsWith('https://')) return 'url';
  // Domain
  if (/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(s)) return 'domain';
  return 'unknown';
}

// ── VirusTotal lookup ──
async function queryVirusTotal(indicator, iocType) {
  if (!VT_API_KEY) return { scanner: 'VirusTotal', available: false, error: 'No API key configured' };
  try {
    let endpoint;
    if (iocType === 'ip') {
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`;
    } else if (iocType === 'domain') {
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`;
    } else if (iocType === 'hash') {
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`;
    } else if (iocType === 'url') {
      // VT URL lookup requires base64 encoding
      const urlId = Buffer.from(indicator).toString('base64').replace(/=+$/, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    } else {
      return { scanner: 'VirusTotal', available: false, error: 'Unsupported IOC type' };
    }

    const resp = await fetch(endpoint, {
      headers: { 'x-apikey': VT_API_KEY, 'Accept': 'application/json' }
    });

    if (resp.status === 429) return { scanner: 'VirusTotal', available: false, error: 'Rate limited' };
    if (resp.status === 404) return { scanner: 'VirusTotal', available: true, verdict: 'clean', confidence: 'low', details: { malicious: 0, suspicious: 0, total: 0, note: 'Not found in VirusTotal' } };
    if (!resp.ok) return { scanner: 'VirusTotal', available: false, error: `HTTP ${resp.status}` };

    const data = await resp.json();
    const attrs = data.data && data.data.attributes ? data.data.attributes : {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    // Extract vendor details for the malicious/suspicious ones
    const vendorResults = attrs.last_analysis_results || {};
    const flaggedVendors = [];
    Object.entries(vendorResults).forEach(([vendor, result]) => {
      if (result.category === 'malicious' || result.category === 'suspicious') {
        flaggedVendors.push({ vendor, category: result.category, result: result.result || result.category });
      }
    });

    // Determine verdict
    let verdict = 'clean';
    let confidence = 'high';
    if (malicious >= 5) { verdict = 'malicious'; confidence = 'high'; }
    else if (malicious >= 2) { verdict = 'malicious'; confidence = 'medium'; }
    else if (malicious >= 1 || suspicious >= 2) { verdict = 'suspicious'; confidence = 'medium'; }
    else if (suspicious >= 1) { verdict = 'suspicious'; confidence = 'low'; }

    // Additional context for IPs
    const extra = {};
    if (iocType === 'ip') {
      if (attrs.as_owner) extra.as_owner = attrs.as_owner;
      if (attrs.asn) extra.asn = attrs.asn;
      if (attrs.country) extra.country = attrs.country;
      if (attrs.reputation !== undefined) extra.reputation_score = attrs.reputation;
    }

    return {
      scanner: 'VirusTotal',
      available: true,
      verdict,
      confidence,
      details: {
        malicious,
        suspicious,
        harmless,
        undetected,
        total,
        flagged_vendors: flaggedVendors.slice(0, 10),
        ...extra
      }
    };
  } catch (e) {
    return { scanner: 'VirusTotal', available: false, error: e.message };
  }
}

// ── AbuseIPDB lookup (IP only) ──
async function queryAbuseIPDB(indicator, iocType) {
  if (!ABUSEIPDB_API_KEY) return { scanner: 'AbuseIPDB', available: false, error: 'No API key configured' };
  if (iocType !== 'ip') return { scanner: 'AbuseIPDB', available: false, error: 'IP only scanner' };

  try {
    const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(indicator)}&maxAgeInDays=90&verbose`, {
      headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' }
    });

    if (resp.status === 429) return { scanner: 'AbuseIPDB', available: false, error: 'Rate limited' };
    if (!resp.ok) return { scanner: 'AbuseIPDB', available: false, error: `HTTP ${resp.status}` };

    const data = await resp.json();
    const d = data.data || {};
    const abuseScore = d.abuseConfidenceScore || 0;
    const totalReports = d.totalReports || 0;

    let verdict = 'clean';
    let confidence = 'high';
    if (abuseScore >= 80) { verdict = 'malicious'; confidence = 'high'; }
    else if (abuseScore >= 50) { verdict = 'malicious'; confidence = 'medium'; }
    else if (abuseScore >= 25) { verdict = 'suspicious'; confidence = 'medium'; }
    else if (abuseScore >= 10 || totalReports >= 5) { verdict = 'suspicious'; confidence = 'low'; }

    // Extract recent report categories
    const reports = d.reports || [];
    const categoryCounts = {};
    reports.slice(0, 50).forEach(r => {
      (r.categories || []).forEach(c => {
        const catName = ABUSE_CATEGORIES[c] || `Category ${c}`;
        categoryCounts[catName] = (categoryCounts[catName] || 0) + 1;
      });
    });
    const topCategories = Object.entries(categoryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ category: name, count }));

    return {
      scanner: 'AbuseIPDB',
      available: true,
      verdict,
      confidence,
      details: {
        abuse_confidence: abuseScore,
        total_reports: totalReports,
        num_distinct_users: d.numDistinctUsers || 0,
        is_tor: d.isTor || false,
        is_whitelisted: d.isWhitelisted || false,
        isp: d.isp || '',
        domain: d.domain || '',
        country_code: d.countryCode || '',
        usage_type: d.usageType || '',
        last_reported_at: d.lastReportedAt || null,
        top_categories: topCategories
      }
    };
  } catch (e) {
    return { scanner: 'AbuseIPDB', available: false, error: e.message };
  }
}

// AbuseIPDB category map
const ABUSE_CATEGORIES = {
  1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
  5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
  9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
  13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'
};

// ── CrowdStrike Falcon Intel lookup ──
async function queryCrowdStrike(indicator, iocType) {
  const token = await getCsToken();
  if (!token) return { scanner: 'CrowdStrike', available: false, error: 'No credentials or auth failed' };

  try {
    // Map IOC type to CS type string
    const typeMap = { ip: 'ip_address', domain: 'domain', hash: 'hash_md5', url: 'url' };
    // For SHA256, use hash_sha256; for SHA1, use hash_sha1
    let csType = typeMap[iocType] || iocType;
    if (iocType === 'hash') {
      if (indicator.length === 64) csType = 'hash_sha256';
      else if (indicator.length === 40) csType = 'hash_sha1';
      else csType = 'hash_md5';
    }

    const filterQ = `indicator:'${indicator}'+type:'${csType}'`;
    const resp = await fetch(`${CS_BASE}/intel/indicators/entities/GET/v1`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({ filter: filterQ, limit: 10 })
    });

    if (resp.status === 429) return { scanner: 'CrowdStrike', available: false, error: 'Rate limited' };
    if (!resp.ok) {
      // Try the v2 combined search as fallback
      const searchResp = await fetch(`${CS_BASE}/intel/combined/indicators/v1?filter=${encodeURIComponent(filterQ)}&limit=10`, {
        headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json' }
      });
      if (!searchResp.ok) return { scanner: 'CrowdStrike', available: false, error: `HTTP ${resp.status}` };
      const searchData = await searchResp.json();
      return processCsResults(searchData);
    }

    const data = await resp.json();
    return processCsResults(data);
  } catch (e) {
    return { scanner: 'CrowdStrike', available: false, error: e.message };
  }
}

function processCsResults(data) {
  const resources = data.resources || [];
  if (resources.length === 0) {
    return {
      scanner: 'CrowdStrike',
      available: true,
      verdict: 'clean',
      confidence: 'medium',
      details: { matched: false, note: 'Not found in CrowdStrike Falcon Intel' }
    };
  }

  // Take the highest confidence result
  const confRank = { high: 3, medium: 2, low: 1, unverified: 0 };
  resources.sort((a, b) => (confRank[b.malicious_confidence] || 0) - (confRank[a.malicious_confidence] || 0));
  const top = resources[0];
  const malConf = (top.malicious_confidence || 'unverified').toLowerCase();

  const actors = [];
  const malwareFamilies = [];
  const labels = [];
  resources.forEach(r => {
    (r.actors || []).forEach(a => { if (!actors.includes(a)) actors.push(a); });
    (r.malware_families || []).forEach(m => { if (!malwareFamilies.includes(m)) malwareFamilies.push(m); });
    (r.labels || []).forEach(l => { if (!labels.includes(l.name || l)) labels.push(l.name || l); });
  });

  let verdict = 'clean';
  let confidence = 'medium';
  if (malConf === 'high') { verdict = 'malicious'; confidence = 'high'; }
  else if (malConf === 'medium') { verdict = 'suspicious'; confidence = 'medium'; }
  else if (malConf === 'low') { verdict = 'suspicious'; confidence = 'low'; }

  return {
    scanner: 'CrowdStrike',
    available: true,
    verdict,
    confidence,
    details: {
      matched: true,
      malicious_confidence: malConf,
      total_indicators: resources.length,
      actors: actors.slice(0, 5),
      malware_families: malwareFamilies.slice(0, 5),
      labels: labels.slice(0, 10),
      kill_chains: (top.kill_chain_phases || []).map(k => k.phase_name || k).slice(0, 5),
      last_updated: top.last_updated || top.published_date || null
    }
  };
}

// ── Consensus verdict aggregator ──
function aggregateVerdict(scannerResults) {
  const verdictWeight = { malicious: 3, suspicious: 2, clean: 1 };
  const confWeight = { high: 3, medium: 2, low: 1 };

  let totalScore = 0;
  let totalWeight = 0;
  let maxVerdict = 'clean';
  let scannerCount = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  let cleanCount = 0;

  Object.values(scannerResults).forEach(result => {
    if (!result.available) return;
    scannerCount++;

    const vScore = verdictWeight[result.verdict] || 1;
    const cScore = confWeight[result.confidence] || 1;
    const weight = vScore * cScore;
    totalScore += weight;
    totalWeight += confWeight[result.confidence] || 1;

    if (result.verdict === 'malicious') maliciousCount++;
    else if (result.verdict === 'suspicious') suspiciousCount++;
    else cleanCount++;

    if ((verdictWeight[result.verdict] || 0) > (verdictWeight[maxVerdict] || 0)) {
      maxVerdict = result.verdict;
    }
  });

  if (scannerCount === 0) return { verdict: 'unknown', confidence: 0, reason: 'No scanners available' };

  // Consensus logic:
  // - If 2+ scanners say malicious → MALICIOUS
  // - If 1 scanner says malicious with high confidence → MALICIOUS
  // - If any scanner says malicious + others suspicious → MALICIOUS
  // - If 2+ scanners say suspicious → SUSPICIOUS
  // - If 1 scanner says suspicious → SUSPICIOUS (low confidence)
  // - Otherwise → CLEAN
  let consensus = 'clean';
  let confidence = 0;
  let reason = '';

  if (maliciousCount >= 2) {
    consensus = 'malicious';
    confidence = Math.min(95, 70 + maliciousCount * 10);
    reason = `${maliciousCount}/${scannerCount} scanners flagged as malicious`;
  } else if (maliciousCount === 1) {
    // Check if the malicious scanner has high confidence
    const malScanner = Object.values(scannerResults).find(r => r.available && r.verdict === 'malicious');
    if (malScanner && malScanner.confidence === 'high') {
      consensus = 'malicious';
      confidence = 75;
      reason = `${malScanner.scanner} flagged with high confidence`;
    } else if (suspiciousCount > 0) {
      consensus = 'malicious';
      confidence = 70;
      reason = `${maliciousCount} malicious + ${suspiciousCount} suspicious across scanners`;
    } else {
      consensus = 'suspicious';
      confidence = 60;
      reason = `1/${scannerCount} scanner flagged as malicious — inconclusive`;
    }
  } else if (suspiciousCount >= 2) {
    consensus = 'suspicious';
    confidence = 55 + suspiciousCount * 5;
    reason = `${suspiciousCount}/${scannerCount} scanners flagged as suspicious`;
  } else if (suspiciousCount === 1) {
    consensus = 'suspicious';
    confidence = 40;
    reason = `1/${scannerCount} scanner flagged as suspicious`;
  } else {
    consensus = 'clean';
    confidence = Math.min(95, 60 + cleanCount * 10);
    reason = `All ${scannerCount} scanners report clean`;
  }

  return {
    verdict: consensus,
    confidence,
    reason,
    scanner_count: scannerCount,
    malicious_count: maliciousCount,
    suspicious_count: suspiciousCount,
    clean_count: cleanCount
  };
}

// ── Main handler ──
module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const { indicators } = req.body || {};
  if (!indicators || !Array.isArray(indicators) || indicators.length === 0) {
    return res.status(400).json({ error: 'indicators[] required' });
  }

  // Limit to prevent abuse
  const iocs = [...new Set(indicators.map(i => (i || '').trim()).filter(Boolean))].slice(0, 50);

  const results = {};
  const meta = {
    scanners: {
      virustotal: { configured: !!VT_API_KEY },
      abuseipdb: { configured: !!ABUSEIPDB_API_KEY },
      crowdstrike: { configured: !!(CS_CLIENT_ID && CS_CLIENT_SECRET) }
    },
    total_iocs: iocs.length,
    timestamp: new Date().toISOString()
  };

  // Process each IOC in parallel (with concurrency limit for VT rate limiting)
  const BATCH_SIZE = 4; // VT allows 4/min
  for (let i = 0; i < iocs.length; i += BATCH_SIZE) {
    const batch = iocs.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(async (indicator) => {
      const iocType = classifyIOC(indicator);

      // Query all available scanners in parallel
      const [vtResult, abuseResult, csResult] = await Promise.all([
        VT_API_KEY ? queryVirusTotal(indicator, iocType) : { scanner: 'VirusTotal', available: false, error: 'Not configured' },
        ABUSEIPDB_API_KEY ? queryAbuseIPDB(indicator, iocType) : { scanner: 'AbuseIPDB', available: false, error: 'Not configured' },
        (CS_CLIENT_ID && CS_CLIENT_SECRET) ? queryCrowdStrike(indicator, iocType) : { scanner: 'CrowdStrike', available: false, error: 'Not configured' }
      ]);

      const scanners = {
        virustotal: vtResult,
        abuseipdb: abuseResult,
        crowdstrike: csResult
      };

      const consensus = aggregateVerdict(scanners);

      return {
        indicator,
        type: iocType,
        scanners,
        consensus
      };
    }));

    batchResults.forEach(r => { results[r.indicator] = r; });

    // Small delay between batches to respect VT rate limits
    if (i + BATCH_SIZE < iocs.length) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }

  return res.status(200).json({ results, meta });
};
