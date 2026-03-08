// Vercel Serverless Function — Multi-Vendor API Proxy Router
// Consolidates Trend Micro, Heimdal, Fortinet, Palo Alto, and Imperva into a single function
// This avoids hitting Vercel's serverless function limit (12 per deployment on Hobby plan)
//
// Usage: POST /api/vendor-proxy?vendor=trendmicro&action=search_detections
//        POST /api/vendor-proxy?vendor=heimdal&action=get_detections
//        etc.

import { trendmicroHandler } from './vendors/trendmicro.js';
import { heimdalHandler } from './vendors/heimdal.js';
import { fortinetHandler } from './vendors/fortinet.js';
import { paloaltoHandler } from './vendors/paloalto.js';
import { impervaHandler } from './vendors/imperva.js';

const VENDOR_HANDLERS = {
  trendmicro: trendmicroHandler,
  heimdal: heimdalHandler,
  fortinet: fortinetHandler,
  paloalto: paloaltoHandler,
  imperva: impervaHandler
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  // Determine vendor from query param or POST body
  const vendor = (req.query.vendor || (req.body && req.body.vendor) || '').toLowerCase();

  if (!vendor) {
    return res.status(400).json({
      error: 'Missing vendor parameter. Use ?vendor=trendmicro|heimdal|fortinet|paloalto|imperva',
      available_vendors: Object.keys(VENDOR_HANDLERS)
    });
  }

  const handlerFn = VENDOR_HANDLERS[vendor];
  if (!handlerFn) {
    return res.status(400).json({
      error: 'Unknown vendor: ' + vendor,
      available_vendors: Object.keys(VENDOR_HANDLERS)
    });
  }

  // Delegate to the vendor-specific handler
  return handlerFn(req, res);
}
