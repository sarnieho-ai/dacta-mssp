// Vercel Serverless Function — Novelty Catcher Fleet Management API
// Handles catcher registration, heartbeat, config distribution, and alert ingestion
//
// Supported actions:
//   heartbeat     — Catcher reports its status (POST)
//   alert         — Catcher pushes a novelty alert (POST)
//   config        — Catcher pulls its latest config (GET)
//   fleet         — UI fetches fleet status for all catchers (GET)
//   alerts_feed   — UI fetches recent novelty alerts (GET)
//   register      — Register a new catcher for a client (POST)
//   update_config — Update a catcher's config from UI (POST)
//   ack_alert     — Acknowledge a novelty alert (POST)
//   deploy_config — Generate deployment config YAML for a catcher (POST)

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://qiqrizggitcqwkwshmfy.supabase.co';
function _d(b) { return Buffer.from(b, 'base64').toString('utf-8'); }
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || _d('c2Jfc2VjcmV0X2txOUJtVVhJd01ndEJDa2lDQXpMX2dfTk1ORDdKVmY=');

async function supabaseRequest(method, path, body, headers = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  const opts = {
    method,
    headers: {
      'apikey': SUPABASE_SERVICE_KEY,
      'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...headers
    }
  };
  if (body && method !== 'GET') opts.body = JSON.stringify(body);
  const resp = await fetch(url, opts);
  const text = await resp.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: resp.status, data, ok: resp.ok };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const action = req.query.action || (req.body && req.body.action);
  if (!action) return res.status(400).json({ error: 'Missing action parameter' });

  try {
    switch (action) {

      // ── Catcher → SIEMLess: Heartbeat ──
      case 'heartbeat': {
        const { catcher_id, hostname, version, mode, events_processed, alerts_24h, stats } = req.body;
        if (!catcher_id) return res.status(400).json({ error: 'Missing catcher_id' });

        const hbPayload = {
          status: mode === 'learn' ? 'learning' : 'online',
          version: version || '2.0.0',
          mode: mode || 'monitor',
          events_processed: events_processed || 0,
          alerts_24h: alerts_24h || 0,
          last_heartbeat: new Date().toISOString(),
          stats: stats || {},
          updated_at: new Date().toISOString(),
        };
        if (hostname) hbPayload.hostname = hostname;

        // Try matching by UUID first, then fall back to hostname
        let result = await supabaseRequest('PATCH',
          `novelty_catchers?id=eq.${catcher_id}`, hbPayload,
          { 'Prefer': 'return=representation' }
        );
        // If no rows matched by id (agent sends name, not UUID), try hostname
        if (!result.data || (Array.isArray(result.data) && result.data.length === 0)) {
          if (hostname) {
            result = await supabaseRequest('PATCH',
              `novelty_catchers?hostname=eq.${hostname}`, hbPayload,
              { 'Prefer': 'return=representation' }
            );
          }
        }
        const matched = Array.isArray(result.data) ? result.data.length : 0;
        return res.status(200).json({ ok: true, matched, message: 'Heartbeat received' });
      }

      // ── Catcher → SIEMLess: Push Alert ──
      case 'alert': {
        const { catcher_id, org_id, alert_type, severity, source_key, detail, alert_data } = req.body;
        if (!catcher_id || !alert_type) return res.status(400).json({ error: 'Missing required fields' });

        const result = await supabaseRequest('POST', 'novelty_alerts', {
          catcher_id,
          org_id: org_id || null,
          alert_type,
          severity: severity || 'medium',
          source_key: source_key || '',
          detail: detail || '',
          alert_data: alert_data || {},
        });
        return res.status(201).json({ ok: true, alert_id: result.data?.[0]?.id });
      }

      // ── Catcher → SIEMLess: Pull Config ──
      case 'config': {
        const catcher_id = req.query.catcher_id;
        const cfgHostname = req.query.hostname;
        if (!catcher_id && !cfgHostname) return res.status(400).json({ error: 'Missing catcher_id or hostname' });

        // Try by UUID first, then by hostname
        let result = await supabaseRequest('GET',
          `novelty_catchers?id=eq.${catcher_id}&select=id,config,mode,org_id`
        );
        if (!result.data?.[0] && cfgHostname) {
          result = await supabaseRequest('GET',
            `novelty_catchers?hostname=eq.${cfgHostname}&select=id,config,mode,org_id&limit=1`
          );
        }
        // Also try matching catcher_id against hostname
        if (!result.data?.[0] && catcher_id) {
          result = await supabaseRequest('GET',
            `novelty_catchers?hostname=eq.${catcher_id}&select=id,config,mode,org_id&limit=1`
          );
        }
        if (!result.ok || !result.data?.[0]) return res.status(404).json({ error: 'Catcher not found' });
        return res.status(200).json(result.data[0]);
      }

      // ── UI → SIEMLess: Get Orgs List ──
      case 'orgs': {
        const orgResult = await supabaseRequest('GET', 'organizations?select=id,name,short_name&order=name');
        return res.status(200).json({ orgs: orgResult.data || [] });
      }

      // ── UI → SIEMLess: Get Log Sources for an Org ──
      case 'log_sources': {
        const lsOrgId = req.query.org_id;
        let lsPath = 'client_log_sources?select=id,org_id,source_name,vendor,source_type,status,events_per_day,last_event_at,onboarded_at,index_pattern&order=source_name';
        if (lsOrgId) lsPath += `&org_id=eq.${lsOrgId}`;
        const lsResult = await supabaseRequest('GET', lsPath);
        return res.status(200).json({ log_sources: lsResult.data || [] });
      }

      // ── UI → SIEMLess: Get Fleet Status ──
      case 'fleet': {
        const org_id = req.query.org_id;
        let path = 'novelty_catchers?select=*,organizations(name,short_name)&order=created_at.desc';
        if (org_id) path += `&org_id=eq.${org_id}`;

        const result = await supabaseRequest('GET', path);
        // Mark offline catchers (no heartbeat in 5 min)
        const catchers = Array.isArray(result.data) ? result.data.map(c => {
          if (c.last_heartbeat) {
            const diff = Date.now() - new Date(c.last_heartbeat).getTime();
            if (diff > 5 * 60 * 1000 && c.status !== 'pending') {
              c.status = 'offline';
            }
          }
          return c;
        }) : [];
        return res.status(200).json({ catchers });
      }

      // ── UI → SIEMLess: Get Alert Feed ──
      case 'alerts_feed': {
        const org_id = req.query.org_id;
        const limit = parseInt(req.query.limit) || 50;
        let path = `novelty_alerts?select=*,novelty_catchers(hostname,organizations(name,short_name))&order=created_at.desc&limit=${limit}`;
        if (org_id) path += `&org_id=eq.${org_id}`;

        const result = await supabaseRequest('GET', path);
        return res.status(200).json({ alerts: result.data || [] });
      }

      // ── UI → SIEMLess: Register New Catcher ──
      case 'register': {
        const { org_id, hostname, config, platform, indices } = req.body;
        if (!org_id || !hostname) return res.status(400).json({ error: 'Missing org_id or hostname' });

        // Upsert: check if catcher with same org_id + hostname already exists
        const existing = await supabaseRequest('GET',
          `novelty_catchers?org_id=eq.${org_id}&hostname=eq.${encodeURIComponent(hostname)}&select=id`);
        if (existing.data && existing.data.length > 0) {
          // Update existing record, reset to pending
          const existingId = existing.data[0].id;
          await supabaseRequest('PATCH', `novelty_catchers?id=eq.${existingId}`, {
            version: '2.0.0',
            mode: 'learn',
            status: 'pending',
            platform: platform || 'linux',
            config: config || {},
            indices: indices || [],
            updated_at: new Date().toISOString(),
          });
          return res.status(200).json({ ok: true, catcher: { id: existingId, org_id, hostname, platform: platform || 'linux' } });
        }

        const result = await supabaseRequest('POST', 'novelty_catchers', {
          org_id,
          hostname,
          version: '2.0.0',
          mode: 'learn',
          status: 'pending',
          platform: platform || 'linux',
          config: config || {},
          indices: indices || [],
        });
        return res.status(201).json({ ok: true, catcher: result.data?.[0] });
      }

      // ── UI → SIEMLess: Update Catcher Config ──
      case 'update_config': {
        const { catcher_id, config, mode, indices } = req.body;
        if (!catcher_id) return res.status(400).json({ error: 'Missing catcher_id' });

        const updates = { updated_at: new Date().toISOString() };
        if (config) updates.config = config;
        if (mode) {
          updates.mode = mode;
          updates.status = mode === 'learn' ? 'learning' : 'online';
        }
        if (indices) updates.indices = indices;

        await supabaseRequest('PATCH', `novelty_catchers?id=eq.${catcher_id}`, updates);
        return res.status(200).json({ ok: true });
      }

      // ── UI → SIEMLess: Acknowledge Alert ──
      case 'ack_alert': {
        const { alert_id } = req.body;
        if (!alert_id) return res.status(400).json({ error: 'Missing alert_id' });

        await supabaseRequest('PATCH', `novelty_alerts?id=eq.${alert_id}`, {
          acknowledged: true,
        });
        return res.status(200).json({ ok: true });
      }

      // ── UI → SIEMLess: Delete Catcher ──
      case 'delete_catcher': {
        const { catcher_id: delId } = req.body;
        if (!delId) return res.status(400).json({ error: 'Missing catcher_id' });

        // Delete associated alerts first
        await supabaseRequest('DELETE', `novelty_alerts?catcher_id=eq.${delId}`);
        // Delete the catcher
        const delResult = await supabaseRequest('DELETE', `novelty_catchers?id=eq.${delId}`);
        return res.status(200).json({ ok: delResult.ok });
      }

      // ── UI → SIEMLess: Generate Deploy Config ──
      case 'deploy_config': {
        const { org_id, hostname, syslog_port, elastic_indices, learning_hours } = req.body;

        // Fetch org info for config naming
        let orgName = 'client';
        if (org_id) {
          const orgResult = await supabaseRequest('GET', `organizations?id=eq.${org_id}&select=name,short_name`);
          if (orgResult.data?.[0]) orgName = orgResult.data[0].short_name || orgResult.data[0].name;
        }

        const config = generateConfigYaml({
          orgName,
          hostname: hostname || 'collector-01',
          syslogPort: syslog_port || 5514,
          indices: elastic_indices || [],
          learningHours: learning_hours || 168,
        });

        return res.status(200).json({ config, install_commands: generateInstallCommands(hostname) });
      }

      // ── Catcher → SIEMLess: Pull Feature Schema for Auto-Discovery ──
      case 'feature_schema': {
        const fsOrgId = req.query.org_id;
        if (!fsOrgId) return res.status(400).json({ error: 'Missing org_id' });

        // Pull the org's log sources from client_log_sources
        const lsResult = await supabaseRequest('GET',
          `client_log_sources?org_id=eq.${fsOrgId}&select=id,source_name,vendor,source_type,index_pattern,field_mappings,status`
        );
        // Pull the org's connectors for SIEM/EDR discovery
        const connResult = await supabaseRequest('GET',
          `client_connectors?org_id=eq.${fsOrgId}&select=id,connector_type,connector_name,config,status`
        );

        // Build feature schema dynamically from log sources
        const logSources = Array.isArray(lsResult.data) ? lsResult.data : [];
        const connectors = Array.isArray(connResult.data) ? connResult.data : [];

        // Collect indices to monitor
        const indices = logSources
          .filter(ls => ls.status === 'active' && ls.index_pattern)
          .map(ls => ls.index_pattern);

        // Build per-source feature extraction config
        const features = {};
        for (const ls of logSources) {
          if (ls.field_mappings && typeof ls.field_mappings === 'object') {
            features[ls.source_name.toLowerCase().replace(/\s+/g, '_')] = ls.field_mappings;
          }
        }

        return res.status(200).json({
          org_id: fsOrgId,
          indices,
          features,
          connectors: connectors.map(c => ({
            type: c.connector_type,
            name: c.connector_name,
            status: c.status
          })),
          generated_at: new Date().toISOString()
        });
      }

      default:
        return res.status(400).json({ error: `Unknown action: ${action}` });
    }
  } catch (err) {
    console.error('[novelty-catcher API]', err);
    return res.status(500).json({ error: err.message });
  }
}

function generateConfigYaml({ orgName, hostname, syslogPort, indices, learningHours }) {
  // If user specified indices, include them as overrides; otherwise leave empty for auto-discovery
  let indicesBlock;
  if (indices.length > 0) {
    indicesBlock = '    # Override: specific indices set during deployment\n'
      + '    indices:\n'
      + indices.map(i => `      - "${i}"`).join('\n');
  } else {
    indicesBlock = '    # Auto-discovered from SIEMLess DB (client_log_sources + client_connectors)\n'
      + '    # Set specific indices here only to override auto-discovery\n'
      + '    indices: []';
  }

  return `# ============================================================
# DACTA Novelty Catcher -- ${orgName}
# Auto-generated by SIEMLess - ${new Date().toISOString().split('T')[0]}
# ============================================================

agent:
  name: "novelty-catcher-${orgName.toLowerCase().replace(/\s+/g, '-')}"
  version: "2.0.0"
  log_level: "INFO"
  log_file: "logs/novelty-catcher.log"
  state_dir: "./state"

inputs:
  syslog:
    enabled: true
    protocol: "udp"
    host: "0.0.0.0"
    port: ${syslogPort}
    buffer_size: 65536
    forward_to:
      enabled: true
      host: "127.0.0.1"
      port: 514

  file:
    enabled: true
    paths:
      - "/var/log/elastic-agent/data/*.ndjson"
      - "/var/log/novelty-catcher/input/*.log"
    poll_interval_ms: 500

  elastic:
    enabled: true
    url: "\${ELASTIC_URL}"
    api_key: "\${ELASTIC_API_KEY}"
${indicesBlock}
    poll_interval_seconds: 60
    lookback_minutes: 5
    batch_size: 1000

detection:
  baseline:
    learning_period_hours: ${learningHours}
    rolling_window_hours: 24
    min_samples: 50
  scoring:
    novelty_threshold: 0.75
    high_confidence_threshold: 0.90
    cooldown_minutes: 5

  # Feature schemas are auto-discovered from SIEMLess DB on startup.
  # The catcher pulls field mappings for this org's log sources via
  # /api/novelty-catcher?action=feature_schema&org_id=...
  features:
    auto_discover: true
    sync_interval_minutes: 60
    fallback:
      categorical: ["event.action", "event.category", "event.module", "event.dataset", "log.level"]
      ip_fields: ["source.ip", "destination.ip"]

  source_detection:
    enabled: true
    alert_on_new_source: true
    auto_learn_new_sources: true

outputs:
  elastic:
    enabled: true
    url: "\${ELASTIC_URL}"
    api_key: "\${ELASTIC_API_KEY}"
    index: "novelty-alerts-${orgName.toLowerCase().replace(/\s+/g, '-')}"

  siemless:
    enabled: true
    url: "https://dacta-siemless.vercel.app"
    endpoint: "/api/novelty-catcher"
    # Catcher authenticates via its catcher_id assigned at registration

  file:
    enabled: true
    path: "outputs/novelty_alerts.ndjson"
    rotate_size_mb: 50

performance:
  workers: 2
  queue_size: 10000
  batch_process_size: 100
  memory_limit_mb: 512
`;
}

function generateInstallCommands(hostname) {
  return `# ── Deploy to ${hostname || 'collector'} ──

# 1. Upload the package
scp novelty-catcher-v2.0.0-linux-x64.tar.gz root@${hostname || 'collector'}:/tmp/

# 2. SSH in and install
ssh root@${hostname || 'collector'}
cd /tmp && tar xzf novelty-catcher-v2.0.0-linux-x64.tar.gz
cd novelty-catcher-dist
sudo bash install.sh

# 3. Configure credentials
sudo nano /etc/novelty-catcher/env
# Set ELASTIC_URL and ELASTIC_API_KEY

# 4. Copy the generated config
sudo cp config.yaml /etc/novelty-catcher/config.yaml

# 5. Bootstrap learning (7 days from Elastic history)
novelty-catcher -c /etc/novelty-catcher/config.yaml -m learn-from-elastic --learn-hours 168

# 6. Start the service
sudo systemctl start novelty-catcher
sudo systemctl enable novelty-catcher

# 7. Verify
sudo systemctl status novelty-catcher
journalctl -u novelty-catcher -f`;
}
