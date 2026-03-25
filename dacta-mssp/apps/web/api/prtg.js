/**
 * PRTG Network Monitor API Proxy
 * Proxies requests to a customer's PRTG instance for network telemetry.
 * 
 * Supported actions:
 *   - status:      GET /api/status.json (overall PRTG server status)
 *   - devices:     GET /api/table.json?content=devices (list all devices)
 *   - sensors:     GET /api/table.json?content=sensors (list all sensors)
 *   - sensor_data: GET /api/historicdata.json?id=X (time-series for a sensor)
 *   - channels:    GET /api/table.json?content=channels&id=X (sensor channels)
 *   - ping:        Simple connectivity test to PRTG server
 * 
 * Auth: PRTG uses apitoken OR username+passhash in query params.
 * Credentials are passed per-request from frontend (stored in org_connectors).
 */

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();

  // SECURITY: Require authenticated session
  const authUser = await requireAuth(req, res);
  if (!authUser) return; // 401 already sent

  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    var body = req.body || {};
    var action = body.action;
    var prtgUrl = (body.prtg_url || '').replace(/\/+$/, '');
    var apiToken = body.api_token || '';
    var username = body.username || '';
    var passhash = body.passhash || '';

    if (!prtgUrl) return res.status(400).json({ error: 'prtg_url is required' });

    var authParams = '';
    if (apiToken) {
      authParams = 'apitoken=' + encodeURIComponent(apiToken);
    } else if (username && passhash) {
      authParams = 'username=' + encodeURIComponent(username) + '&passhash=' + encodeURIComponent(passhash);
    } else {
      return res.status(400).json({ error: 'api_token or username+passhash required' });
    }

    var targetUrl = '';

    switch (action) {
      case 'ping':
      case 'status':
        targetUrl = prtgUrl + '/api/status.json?' + authParams;
        break;
      case 'devices':
        targetUrl = prtgUrl + '/api/table.json?content=devices&columns=objid,device,host,status,message,group,probe,condition&count=' + (body.count || 2500) + '&' + authParams;
        break;
      case 'sensors':
        var sf = '';
        if (body.device_id) sf = '&id=' + body.device_id;
        if (body.filter_type) sf += '&filter_type=' + encodeURIComponent(body.filter_type);
        targetUrl = prtgUrl + '/api/table.json?content=sensors&columns=objid,sensor,status,lastvalue,device,group,type,tags,message&count=' + (body.count || 5000) + sf + '&' + authParams;
        break;
      case 'sensor_data':
        if (!body.sensor_id) return res.status(400).json({ error: 'sensor_id required' });
        var now = new Date();
        var ago = new Date(now.getTime() - 86400000);
        var fmt = function(d) { return d.toISOString().replace('T','-').replace(/:/g,'-').split('.')[0]; };
        targetUrl = prtgUrl + '/api/historicdata.json?id=' + body.sensor_id + '&sdate=' + encodeURIComponent(body.start_date || fmt(ago)) + '&edate=' + encodeURIComponent(body.end_date || fmt(now)) + '&avg=' + (body.avg || 300) + '&' + authParams;
        break;
      case 'channels':
        if (!body.sensor_id) return res.status(400).json({ error: 'sensor_id required' });
        targetUrl = prtgUrl + '/api/table.json?content=channels&id=' + body.sensor_id + '&columns=objid,name,lastvalue&' + authParams;
        break;
      default:
        return res.status(400).json({ error: 'Unknown action: ' + action });
    }

    var fetchOpts = { method: 'GET', headers: { 'Accept': 'application/json', 'User-Agent': 'DACTA-SIEMLess/1.0' } };
    if (targetUrl.startsWith('https://')) {
      var https = require('https');
      fetchOpts.agent = new https.Agent({ rejectUnauthorized: false });
    }

    var response = await fetch(targetUrl, fetchOpts);
    if (!response.ok) {
      var errText = await response.text();
      return res.status(response.status).json({ error: 'PRTG returned ' + response.status, detail: errText.substring(0, 500) });
    }
    return res.status(200).json(await response.json());
  } catch (err) {
    console.error('[PRTG Proxy Error]', err.message);
    return res.status(500).json({ error: err.message });
  }
};

const { setCors, requireAuth } = require('./lib/auth');