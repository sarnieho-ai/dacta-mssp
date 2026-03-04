// ── PII Tokenization Vault ──────────────────────────────────────────────────
// GDPR/PDPA-compliant PII protection layer for all LLM workflows.
// Tokenizes PII before LLM sees it, detokenizes tool call arguments before
// executing real API queries, re-tokenizes tool results, and detokenizes
// the final LLM response before returning to the analyst.
//
// Shared module — used by Copilot, AI Investigation, Rule Generation,
// War Room Copilot, and Log Parser workflows.
// ─────────────────────────────────────────────────────────────────────────────

class PiiVault {
  constructor() {
    // Forward map: real value → token
    this._tokenMap = new Map();
    // Reverse map: token → real value
    this._reverseMap = new Map();
    // Counters per category for unique token generation
    this._counters = {};
    // Regex patterns for PII detection, ordered by specificity
    this._patterns = [
      // Email addresses (must be before domain to avoid partial matches)
      {
        category: 'EMAIL',
        regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
        priority: 10
      },
      // NRIC/FIN (Singapore national ID) — e.g. S1234567A, T0123456J, G1234567X
      {
        category: 'NRIC',
        regex: /\b[STFGM]\d{7}[A-Z]\b/gi,
        priority: 20
      },
      // Phone numbers (international and local formats)
      {
        category: 'PHONE',
        regex: /(?<!\d)(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}(?!\d)/g,
        priority: 30
      },
      // IPv4 addresses — but NOT 0.0.0.0 or 127.0.0.1 or version-like strings
      {
        category: 'IP',
        regex: /\b(?!0\.0\.0\.0\b)(?!127\.0\.0\.1\b)(?!255\.255\.255\.\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
        priority: 40
      },
      // IPv6 addresses (simplified — catches common formats)
      {
        category: 'IPV6',
        regex: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b/g,
        priority: 41
      },
      // Hostnames — patterns like WIN-SRV-DC01, DACTASG-WS-047, etc.
      // Only match uppercase hostnames with hyphens/numbers (avoids false positives)
      {
        category: 'HOST',
        regex: /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,5}\b/g,
        priority: 50
      },
      // Usernames — common patterns like jdoe, john.smith, admin\jdoe
      // Only match when preceded by user-context keywords
      {
        category: 'USER',
        regex: /(?:(?:user(?:name)?|account|logon|login|uid|samaccountname|cn)[=:\s]+)([A-Za-z][A-Za-z0-9._\\-]{2,30})/gi,
        priority: 60,
        captureGroup: 1
      },
      // MAC addresses
      {
        category: 'MAC',
        regex: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g,
        priority: 70
      }
    ];

    // Organization/client names loaded from context (tokenized as CLIENT category)
    this._clientNames = [];
  }

  /**
   * Register known client/organization names for tokenization.
   * Call this at the start of a session with names from client_context.
   */
  registerClientNames(names) {
    if (!Array.isArray(names)) names = [names];
    for (const name of names) {
      if (name && typeof name === 'string' && name.length > 1) {
        this._clientNames.push(name);
      }
    }
  }

  /**
   * Generate a deterministic but opaque token for a category + value.
   * Reuses existing token if the same value was already seen.
   */
  _getToken(category, realValue) {
    const key = `${category}::${realValue}`;
    if (this._tokenMap.has(key)) {
      return this._tokenMap.get(key);
    }
    // Generate new token
    if (!this._counters[category]) this._counters[category] = 0;
    this._counters[category]++;
    const hexId = this._counters[category].toString(16).toUpperCase().padStart(2, '0');
    const token = `[[${category}_0x${hexId}]]`;
    this._tokenMap.set(key, token);
    this._reverseMap.set(token, realValue);
    return token;
  }

  /**
   * Get the real value for a token. Returns null if not found.
   */
  _getRealValue(token) {
    return this._reverseMap.get(token) || null;
  }

  /**
   * Tokenize all PII in a string. Returns the tokenized string.
   */
  tokenize(text) {
    if (!text || typeof text !== 'string') return text;
    let result = text;

    // 1. Tokenize registered client names first (exact match, case-insensitive)
    for (const clientName of this._clientNames) {
      const escaped = clientName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(`\\b${escaped}\\b`, 'gi');
      result = result.replace(re, (match) => {
        return this._getToken('CLIENT', match);
      });
    }

    // 2. Apply regex patterns in priority order
    // Sort by priority (lower number = higher priority = processed first)
    const sorted = [...this._patterns].sort((a, b) => a.priority - b.priority);
    for (const pat of sorted) {
      // Reset regex state
      pat.regex.lastIndex = 0;
      if (pat.captureGroup) {
        // For patterns with capture groups (e.g., username after keyword)
        result = result.replace(pat.regex, (fullMatch, captured) => {
          if (!captured || captured.length < 2) return fullMatch;
          // Don't tokenize values that look like already-tokenized
          if (captured.startsWith('[[') && captured.endsWith(']]')) return fullMatch;
          const token = this._getToken(pat.category, captured);
          return fullMatch.replace(captured, token);
        });
      } else {
        result = result.replace(pat.regex, (match) => {
          // Don't tokenize things that are already tokens
          if (match.startsWith('[[') && match.endsWith(']]')) return match;
          // Don't tokenize very short matches that might be false positives
          if (pat.category === 'HOST' && match.length < 5) return match;
          // Don't tokenize phone-like patterns that are too short or look like ports
          if (pat.category === 'PHONE' && match.replace(/\D/g, '').length < 7) return match;
          return this._getToken(pat.category, match);
        });
      }
    }

    return result;
  }

  /**
   * Detokenize all tokens in a string back to real values.
   */
  detokenize(text) {
    if (!text || typeof text !== 'string') return text;
    // Match all [[CATEGORY_0xHH]] patterns
    return text.replace(/\[\[[A-Z0-9]+_0x[0-9A-F]+\]\]/g, (token) => {
      return this._getRealValue(token) || token;
    });
  }

  /**
   * Deep tokenize an object (recursively walks all string values).
   * Used for tokenizing tool results before returning to LLM.
   */
  tokenizeDeep(obj) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') return this.tokenize(obj);
    if (typeof obj === 'number' || typeof obj === 'boolean') return obj;
    if (Array.isArray(obj)) return obj.map(item => this.tokenizeDeep(item));
    if (typeof obj === 'object') {
      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.tokenizeDeep(value);
      }
      return result;
    }
    return obj;
  }

  /**
   * Deep detokenize an object (recursively walks all string values).
   * Used for detokenizing tool call arguments before executing real API calls.
   */
  detokenizeDeep(obj) {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') return this.detokenize(obj);
    if (typeof obj === 'number' || typeof obj === 'boolean') return obj;
    if (Array.isArray(obj)) return obj.map(item => this.detokenizeDeep(item));
    if (typeof obj === 'object') {
      const result = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.detokenizeDeep(value);
      }
      return result;
    }
    return obj;
  }

  /**
   * Get the current vault state for debugging/audit logging.
   * Returns category counts only — never exposes real values.
   */
  getStats() {
    const stats = { totalTokens: this._tokenMap.size, byCategory: {} };
    for (const key of this._tokenMap.keys()) {
      const cat = key.split('::')[0];
      stats.byCategory[cat] = (stats.byCategory[cat] || 0) + 1;
    }
    return stats;
  }

  /**
   * Tokenize the messages array (user messages + any string content).
   * Preserves message structure for Claude API compatibility.
   */
  tokenizeMessages(messages) {
    if (!messages || !Array.isArray(messages)) return messages;
    return messages.map(msg => {
      if (typeof msg.content === 'string') {
        return { ...msg, content: this.tokenize(msg.content) };
      }
      if (Array.isArray(msg.content)) {
        return {
          ...msg,
          content: msg.content.map(block => {
            if (block.type === 'text' && typeof block.text === 'string') {
              return { ...block, text: this.tokenize(block.text) };
            }
            if (block.type === 'tool_result' && typeof block.content === 'string') {
              return { ...block, content: this.tokenize(block.content) };
            }
            return block;
          })
        };
      }
      return msg;
    });
  }

  /**
   * Tokenize the system prompt (replace any client-specific context).
   */
  tokenizeSystemPrompt(prompt) {
    return this.tokenize(prompt);
  }
}

module.exports = { PiiVault };
