// Centralized external service configuration
// Reads from environment variables first, falls back to platform defaults.
// For production: set these in Vercel Dashboard → Settings → Environment Variables

module.exports = {
  // DACTA TIP (OpenCTI)
  OPENCTI_URL: process.env.OPENCTI_URL || process.env.DACTA_TIP_URL || 'http://61.13.214.198:8080',
  OPENCTI_TOKEN: process.env.OPENCTI_TOKEN || process.env.DACTA_TIP_TOKEN || '61896c14-5c49-4446-9e01-a281df53fcd3',

  // AbuseIPDB
  ABUSEIPDB_API_KEY: process.env.ABUSEIPDB_API_KEY || '',

  // VirusTotal
  VIRUSTOTAL_API_KEY: process.env.VIRUSTOTAL_API_KEY || '',

  // Agent auth
  SIEMLESS_API_KEY: process.env.SIEMLESS_API_KEY || '',
};
