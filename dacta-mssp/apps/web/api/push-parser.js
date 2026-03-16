// Vercel Serverless Function — Push Parser to SIEM
// Creates an Elastic ingest pipeline from a generated parser definition
// Also updates the parser status in SIEMLess DB to "Deployed"

const { SUPABASE_URL, sbHeaders, sbFetch } = require('./lib/supabase');
const https = require('https');

function getFetchOptions(baseOpts) {
  if (process.env.ELASTIC_SKIP_SSL_VERIFY === 'true') {
    const agent = new https.Agent({ rejectUnauthorized: false });
    return { ...baseOpts, agent };
  }
  return baseOpts;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  try {
    const { parser_id, org_id } = req.body || {};

    if (!parser_id) {
      return res.status(400).json({ error: 'parser_id is required' });
    }

    // 1. Fetch the parser from SIEMLess DB
    const parserResp = await sbFetch(`generated_parsers?id=eq.${parser_id}&select=*`);
    const parsers = await parserResp.json();
    if (!parsers || parsers.length === 0) {
      return res.status(404).json({ error: 'Parser not found in SIEMLess DB' });
    }
    const parser = parsers[0];

    // 2. Get SIEM connector credentials for the org (or default)
    let connectorQuery = 'org_connectors?connector_type=eq.siem&is_enabled=eq.true';
    if (org_id) {
      connectorQuery += `&org_id=eq.${org_id}`;
    }
    connectorQuery += '&limit=1';
    const connResp = await sbFetch(connectorQuery);
    const connectors = await connResp.json();

    if (!connectors || connectors.length === 0) {
      return res.status(400).json({ error: 'No active SIEM connector found. Please configure a SIEM connector in the Client Connector page.' });
    }

    const connector = connectors[0];
    const elasticUrl = connector.api_endpoint;
    let apiKey = '';

    // Parse credentials
    try {
      const creds = typeof connector.credentials_ref === 'string'
        ? JSON.parse(connector.credentials_ref)
        : connector.credentials_ref;
      apiKey = creds.api_key || '';
    } catch (e) {
      return res.status(400).json({ error: 'Invalid SIEM connector credentials. Please reconfigure the SIEM connector.' });
    }

    if (!elasticUrl || !apiKey) {
      return res.status(400).json({ error: 'SIEM connector missing API endpoint or API key. Please configure it in Client Connectors.' });
    }

    // 3. Build Elastic ingest pipeline from parser fields
    const pipelineName = 'siemless-parser-' + parser.parser_name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const processors = [];

    // Detect if this is a key=value format (Fortinet, Palo Alto, etc.)
    const isKVFormat = (parser.delimiter && (parser.delimiter.includes('=') || parser.delimiter.toLowerCase().includes('key')))
      || (parser.format_type && parser.format_type.toLowerCase().includes('key'))
      || (parser.parsed_sample && Object.keys(parser.parsed_sample).length > 10); // Many fields = likely KV

    if (isKVFormat) {
      // Use KV processor for key=value log formats
      processors.push({
        kv: {
          field: 'message',
          field_split: ' ',
          value_split: '=',
          strip_brackets: true,
          trim_value: '"',
          ignore_failure: true,
          description: 'Parse key=value pairs from ' + parser.parser_name
        }
      });
    } else if (parser.regex_pattern) {
      // Convert Python named groups (?P<name>...) to Oniguruma (?<name>...) for Elastic grok
      let grokPattern = parser.regex_pattern
        .replace(/\(\?P</g, '(?<')  // (?P<name>...) → (?<name>...)
        .replace(/\\\\([dswDSW])/g, '\\$1'); // Unescape double-escaped

      processors.push({
        grok: {
          field: 'message',
          patterns: [grokPattern],
          ignore_failure: true,
          description: 'Parse log using regex from SIEMLess Parser Generator'
        }
      });
    }

    // Add date processor for timestamp fields
    const dateFields = (parser.fields_data || []).filter(f =>
      f.type === 'timestamp' || f.name === 'timestamp' || f.name === 'date' || f.name === 'time'
    );
    dateFields.forEach(f => {
      processors.push({
        date: {
          field: f.name,
          formats: [f.format || 'ISO8601', 'yyyy-MM-dd HH:mm:ss', 'MMM d HH:mm:ss', 'MMM dd HH:mm:ss'],
          ignore_failure: true,
          target_field: f.name === 'timestamp' ? '@timestamp' : f.name + '_parsed'
        }
      });
    });

    // Add convert processors for typed fields
    (parser.fields_data || []).forEach(f => {
      if (f.type === 'integer') {
        processors.push({
          convert: { field: f.name, type: 'integer', ignore_failure: true, ignore_missing: true }
        });
      } else if (f.type === 'float') {
        processors.push({
          convert: { field: f.name, type: 'float', ignore_failure: true, ignore_missing: true }
        });
      } else if (f.type === 'boolean') {
        processors.push({
          convert: { field: f.name, type: 'boolean', ignore_failure: true, ignore_missing: true }
        });
      } else if (f.type === 'ip_address') {
        processors.push({
          convert: { field: f.name, type: 'ip', ignore_failure: true, ignore_missing: true }
        });
      }
    });

    // Add a set processor to tag parsed documents
    processors.push({
      set: {
        field: 'event.dataset',
        value: 'siemless.' + parser.vendor.toLowerCase().replace(/[^a-z0-9]+/g, '_'),
        override: false
      }
    });

    processors.push({
      set: {
        field: 'siemless.parser',
        value: pipelineName,
        override: true
      }
    });

    const pipeline = {
      description: `SIEMLess Parser: ${parser.parser_name} (${parser.vendor}) — ${parser.fields_count} fields, ${parser.confidence || 0}% confidence`,
      processors: processors,
      _meta: {
        parser_id: parser.id,
        parser_name: parser.parser_name,
        vendor: parser.vendor,
        created_by: 'siemless-parser-generator',
        deployed_at: new Date().toISOString()
      }
    };

    // 4. Push pipeline to Elastic
    const elasticPipelineUrl = `${elasticUrl}/_ingest/pipeline/${pipelineName}`;

    const elasticResp = await fetch(elasticPipelineUrl, getFetchOptions({
      method: 'PUT',
      headers: {
        'Authorization': `ApiKey ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(pipeline)
    }));

    const elasticResult = await elasticResp.text();
    let elasticData;
    try { elasticData = JSON.parse(elasticResult); } catch (e) { elasticData = { raw: elasticResult }; }

    if (!elasticResp.ok) {
      return res.status(200).json({
        success: false,
        error: 'Elastic SIEM rejected the pipeline: ' + (elasticData.error?.reason || elasticData.error?.type || elasticResult.substring(0, 300)),
        elastic_status: elasticResp.status,
        pipeline_name: pipelineName,
        pipeline: pipeline
      });
    }

    // 5. Update parser status in SIEMLess DB
    const deploymentMeta = JSON.stringify({
      pipeline_id: pipelineName,
      deployed_at: new Date().toISOString(),
      elastic_url: elasticUrl,
      org_id: org_id || connector.org_id,
      org_name: parser.org_name || '',
      processors_count: processors.length
    });

    await sbFetch(`generated_parsers?id=eq.${parser_id}`, {
      method: 'PATCH',
      body: JSON.stringify({
        status: 'Deployed',
        notes: deploymentMeta
      })
    });

    // Extract short SIEM label from URL (e.g. "dacta-global.es.ap-southeast-1" from full URL)
    let siemLabel = elasticUrl;
    try {
      const u = new URL(elasticUrl);
      siemLabel = u.hostname.replace('.aws.found.io', '').replace('.elastic-cloud.com', '');
    } catch(e) {}

    return res.status(200).json({
      success: true,
      pipeline_name: pipelineName,
      processors_count: processors.length,
      elastic_acknowledged: elasticData.acknowledged || false,
      parser_name: parser.parser_name,
      vendor: parser.vendor,
      siem_url: elasticUrl,
      siem_label: siemLabel,
      message: `Parser "${parser.parser_name}" deployed to ${siemLabel} as pipeline "${pipelineName}"`
    });

  } catch (err) {
    console.error('Push parser error:', err);
    return res.status(500).json({ error: 'Push to SIEM failed: ' + err.message });
  }
};
