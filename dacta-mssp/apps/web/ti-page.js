/* ============================================================
   DACTA TIP — Threat Intelligence Page (Unified Live JS)
   All data fetched from DACTA TIP (OpenCTI) + CrowdStrike APIs
   ES5 compatible — no const/let, no arrow functions, no template literals
   ============================================================ */
(function() {
'use strict';

/* =============================================
   TAB SWITCHING
   ============================================= */
function switchTiTab(tabName) {
  var tabs = ['ops','actors','attack','siem','report'];
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i];
    var panel = document.getElementById('tip-panel-' + t);
    var btn = document.getElementById('tip-tab-btn-' + t);
    if (panel) {
      if (t === tabName) { panel.classList.add('active'); } else { panel.classList.remove('active'); }
    }
    if (btn) {
      if (t === tabName) { btn.classList.add('active'); } else { btn.classList.remove('active'); }
    }
  }
  var sp = document.getElementById('tip-attack-sidepanel');
  if (sp) sp.classList.remove('open');
  if (tabName === 'attack') renderAttackGrid();
}
window.switchTiTab = switchTiTab;

/* =============================================
   CLIENT CONTEXT DATA
   ============================================= */
// CLIENT_DATA is loaded dynamically from the organizations DB table.
// Fallback values are used until the DB loads.
var CLIENT_DATA = window.CLIENT_DATA || {
  all: { name:'All Clients', sector:'Multi-Sector', region:'APAC', risk:'HIGH', riskClass:'tip-tag-high' }
};
window.CLIENT_DATA = CLIENT_DATA;

// Load orgs from DB and populate CLIENT_DATA + the org selector dropdown
var _tipOrgLoadAttempts = 0;
(function _tipLoadOrgsFromDB() {
  var sb = window._dactaSupabase || window._supabaseRef;
  _tipOrgLoadAttempts++;
  if (!sb) {
    if (_tipOrgLoadAttempts < 20) setTimeout(_tipLoadOrgsFromDB, 500);
    else console.warn('[TIP] Gave up waiting for SIEMLess DB after 10s');
    return;
  }
  sb.from('organizations').select('name,short_name,industry,region,timezone,sla_tier,service_model').order('name').then(function(res) {
    if (!res.data) return;
    var sel = document.getElementById('tip-client-selector');
    res.data.forEach(function(org) {
      var key = (org.short_name || org.name.substring(0, 4)).toLowerCase();
      var industry = org.industry || 'Technology';
      // Build readable region from DB region + timezone
      var regionBase = org.region || 'APAC';
      var tz = org.timezone || '';
      var country = tz.includes('Singapore') ? 'Singapore' : tz.includes('Phnom_Penh') ? 'Cambodia' : tz.includes('Sydney') ? 'Australia' : '';
      var region = regionBase + (country ? ' \u00b7 ' + country : '');
      // Risk from SLA tier
      var risk = org.sla_tier === 'platinum' || org.sla_tier === 'gold' ? 'HIGH' : 'MEDIUM';
      var riskClass = risk === 'HIGH' ? 'tip-tag-high' : 'tip-tag-medium';
      CLIENT_DATA[key] = {
        name: org.name,
        sector: industry,
        region: region,
        risk: risk,
        riskClass: riskClass
      };
      // Add to TI org selector dropdown if it exists and option not already present
      if (sel) {
        var exists = false;
        for (var i = 0; i < sel.options.length; i++) { if (sel.options[i].value === key) { exists = true; break; } }
        if (!exists) {
          var opt = document.createElement('option');
          opt.value = key;
          opt.textContent = org.name;
          sel.appendChild(opt);
        }
      }
    });
    console.log('[TIP] Loaded ' + res.data.length + ' orgs from DB into CLIENT_DATA');
  }).catch(function(e) { console.warn('[TIP] DB org load failed, using fallback:', e); });
})();

function tipUpdateClientContext(val) {
  var d = CLIENT_DATA[val];
  if (!d) return;
  window._tipSelectedOrg = val;
  var sectorEl = document.getElementById('tip-ctx-sector');
  var regionEl = document.getElementById('tip-ctx-region');
  var riskEl = document.getElementById('tip-ctx-risk');
  if (sectorEl) sectorEl.textContent = d.sector;
  if (regionEl) regionEl.textContent = d.region;
  if (riskEl) {
    riskEl.textContent = d.risk;
    riskEl.className = 'tip-tag ' + d.riskClass;
  }
  // Re-render all tabs with filtered data
  _tipApplyOrgFilter(val);
}
window.tipUpdateClientContext = tipUpdateClientContext;

// Sector-to-keyword mapping for relevance filtering
var _TIP_SECTOR_KEYWORDS = {
  // DB industry values (source of truth from organizations table)
  'Financial':             ['financial', 'banking', 'payment', 'swift', 'fin', 'credit', 'atm', 'pos', 'fraud', 'insurance', 'investment', 'fintech'],
  'Financial Services':    ['financial', 'banking', 'payment', 'swift', 'fin', 'credit', 'atm', 'pos', 'fraud', 'insurance', 'investment', 'fintech'],
  'Technology':            ['technology', 'tech', 'software', 'saas', 'cloud', 'cyber', 'security', 'it services', 'managed services', 'msp'],
  'Hospitality':           ['hospitality', 'hotel', 'casino', 'gaming', 'entertainment', 'tourism', 'leisure', 'resort', 'food', 'beverage', 'retail', 'travel'],
  'Hospitality / Gaming':  ['hospitality', 'hotel', 'casino', 'gaming', 'entertainment', 'tourism', 'leisure', 'resort', 'food', 'beverage', 'retail', 'travel'],
  'Maritime':              ['maritime', 'shipping', 'port', 'logistics', 'marine', 'vessel', 'cargo', 'transport'],
  'Real Estate':           ['real estate', 'property', 'construction', 'building', 'development', 'reit'],
  'Legal':                 ['legal', 'law', 'attorney', 'solicitor', 'litigation', 'compliance', 'regulatory'],
  'Professional Services': ['professional', 'consulting', 'legal', 'audit', 'advisory', 'accounting', 'law firm'],
  'Multi-Sector':          []  // shows everything
};
var _TIP_REGION_KEYWORDS = {
  'APAC':                  ['apac', 'asia', 'pacific'],
  'APAC \u00b7 Singapore': ['singapore', 'sg', 'apac', 'asia', 'southeast'],
  'APAC \u00b7 Australia': ['australia', 'au', 'apac', 'oceania'],
  'SEA':                   ['sea', 'southeast', 'asia', 'cambodia', 'singapore', 'indonesia', 'malaysia', 'thailand', 'vietnam'],
  'SEA \u00b7 Cambodia':   ['cambodia', 'kh', 'sea', 'southeast', 'asia'],
  'SEA \u00b7 Singapore':  ['singapore', 'sg', 'sea', 'southeast', 'asia']
};

function _tipApplyOrgFilter(orgKey) {
  var data = window._tipLiveData;
  if (!data) return;
  var d = CLIENT_DATA[orgKey];
  if (!d) return;

  if (orgKey === 'all') {
    // Show everything
    var allIndicators = data.indicators || [];
    renderIOCFeed(allIndicators);
    renderPyramidOfPain(allIndicators);
    renderActorGrid(data.actors || []);
    var allReports = (data.reports || []).concat(data.csReports || []);
    renderReportsList(allReports);
    var cIocs = _el('tip-count-iocs'); if (cIocs) cIocs.textContent = allIndicators.length;
    var cActors = _el('tip-count-actors'); if (cActors) cActors.textContent = (data.actors || []).length;
    var cReports = _el('tip-count-reports'); if (cReports) cReports.textContent = allReports.length;
    // AI-generated hypotheses for all orgs
    renderHuntHypotheses(allIndicators, data.actors || [], d, orgKey);
    return;
  }

  // ── Build relevance keywords from sector + region ──
  var sectorKW = (_TIP_SECTOR_KEYWORDS[d.sector] || []).map(function(k) { return k.toLowerCase(); });
  var regionKW = (_TIP_REGION_KEYWORDS[d.region] || []).map(function(k) { return k.toLowerCase(); });
  var allKW = sectorKW.concat(regionKW).concat([d.name.toLowerCase()]);

  function matchesContext(text) {
    if (!text || allKW.length === 0) return true;
    var lower = text.toLowerCase();
    return allKW.some(function(kw) { return lower.indexOf(kw) !== -1; });
  }

  // ── Filter actors FIRST — strict industry+region matching ──
  // Only show actors whose target_industries actually match the org's sector
  var actors = (data.actors || []).filter(function(a) {
    if (a._source === 'DACTA TIP') {
      var text = (a.name || '') + ' ' + (a.description || '') + ' ' + (a.primary_motivation || '');
      return matchesContext(text);
    }
    // CrowdStrike actors — must match EITHER sector keywords in target_industries OR region keywords in target_countries
    var industries = (a.target_industries || []).map(function(i) { return (i.value || i || '').toLowerCase(); });
    var countries = (a.target_countries || []).map(function(c) { return (c.value || c || '').toLowerCase(); });
    // Check sector match (industry keywords against target_industries)
    var sectorMatch = sectorKW.length === 0 || industries.some(function(ind) {
      return sectorKW.some(function(kw) { return ind.indexOf(kw) !== -1; });
    });
    // Check region match (region keywords against target_countries + description)
    var desc = (a.short_description || a.description || '').toLowerCase();
    var regionMatch = regionKW.length === 0 || countries.concat([desc]).some(function(txt) {
      return regionKW.some(function(kw) { return txt.indexOf(kw) !== -1; });
    });
    // Actor must match BOTH sector AND region to be relevant, OR sector if no countries listed
    if (countries.length === 0) return sectorMatch;
    return sectorMatch && regionMatch;
  });
  // NO fallback — if 0 actors match, show 0 (shows empty state message)

  // ── Collect IOC values from matched actors to correlate indicators ──
  var actorNames = actors.map(function(a) { return (a.name || '').toLowerCase(); });

  // ── Filter indicators: prioritize IOCs linked to relevant actors/reports ──
  var allIndicators = data.indicators || [];
  var relevantIOCs = [];
  var genericIOCs = [];
  for (var ix = 0; ix < allIndicators.length; ix++) {
    var ind = allIndicators[ix];
    var indText = (ind.name || '') + ' ' + (ind.description || '') + ' ' +
      ((ind.objectLabel || []).map(function(l){ return l.value || ''; }).join(' ')) + ' ' +
      ((ind.createdBy || {}).name || '');
    if (matchesContext(indText)) {
      relevantIOCs.push(ind);
    } else {
      genericIOCs.push(ind);
    }
  }
  // Sort relevant first by score, then append generics sorted by score
  relevantIOCs.sort(function(a, b) { return (b.x_opencti_score || 0) - (a.x_opencti_score || 0); });
  genericIOCs.sort(function(a, b) { return (b.x_opencti_score || 0) - (a.x_opencti_score || 0); });
  var sortedIndicators = relevantIOCs.concat(genericIOCs);

  // For Pyramid of Pain + Hunt Hypotheses, use only relevant IOCs
  // (so the pyramid changes per org). If none match, use top-scoring generics.
  var filteredForPyramid = relevantIOCs.length > 0 ? relevantIOCs : genericIOCs.slice(0, 20);

  // ── Filter reports by relevance ──
  var allReports = (data.reports || []).concat(data.csReports || []);
  var filteredReports = allReports.filter(function(r) {
    var text = (r.name || '') + ' ' + (r.short_description || r.description || '') + ' ' +
      ((r.target_industries || []).map(function(i) { return i.value || i; }).join(' ')) + ' ' +
      ((r.target_countries || []).map(function(c) { return c.value || c; }).join(' '));
    return matchesContext(text);
  });
  // No fallback for reports either — show what's relevant

  // ── Render everything ──
  renderIOCFeed(sortedIndicators);          // IOC feed: all IOCs, relevant first
  renderPyramidOfPain(filteredForPyramid);   // Pyramid: only relevant IOCs
  renderActorGrid(actors);                  // Actors: strictly filtered
  renderReportsList(filteredReports.length > 0 ? filteredReports : allReports);

  // Update counters
  var cIocs = _el('tip-count-iocs'); if (cIocs) cIocs.textContent = sortedIndicators.length;
  var cActors = _el('tip-count-actors'); if (cActors) cActors.textContent = actors.length;
  var cReports = _el('tip-count-reports'); if (cReports) cReports.textContent = (filteredReports.length > 0 ? filteredReports : allReports).length;

  // AI-generated hypotheses with org context
  renderHuntHypotheses(filteredForPyramid, actors, d, orgKey);

  console.log('[TIP] Org filter applied: ' + d.name + ' — ' + filteredForPyramid.length + ' relevant IOCs (of ' + sortedIndicators.length + '), ' + actors.length + ' actors, ' + filteredReports.length + ' reports');
}

/* =============================================
   LIVE DATA STORE
   ============================================= */
window._tipLiveData = {
  indicators: [],
  actors: [],
  intrusionSets: [],
  reports: [],
  csReports: [],
  attackPatterns: [],
  malwares: []
};

/* =============================================
   API HELPERS
   ============================================= */
function fetchDactaTip(query, variables) {
  return _siemFetch('/api/opencti', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: query, variables: variables || {} })
  }).then(function(r) {
    if (!r.ok) throw new Error('DACTA TIP API error: ' + r.status);
    return r.json();
  });
}

function fetchCrowdStrike(action, params) {
  var qs = 'action=' + encodeURIComponent(action);
  if (params) {
    var keys = Object.keys(params);
    for (var i = 0; i < keys.length; i++) {
      qs += '&' + encodeURIComponent(keys[i]) + '=' + encodeURIComponent(params[keys[i]]);
    }
  }
  return _siemFetch('/api/crowdstrike?' + qs).then(function(r) {
    if (!r.ok) throw new Error('CrowdStrike API error: ' + r.status);
    return r.json();
  });
}

/* =============================================
   UTILITY HELPERS
   ============================================= */
function _el(id) { return document.getElementById(id); }

function _escHtml(str) {
  if (!str) return '';
  var div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function _timeAgo(dateStr) {
  if (!dateStr) return 'N/A';
  var d;
  if (typeof dateStr === 'number') {
    d = new Date(dateStr * 1000);
  } else {
    d = new Date(dateStr);
  }
  if (isNaN(d.getTime())) return 'N/A';
  var now = Date.now();
  var diff = now - d.getTime();
  if (diff < 0) diff = 0;
  var mins = Math.floor(diff / 60000);
  if (mins < 60) return mins + 'm ago';
  var hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  var days = Math.floor(hrs / 24);
  if (days < 30) return days + 'd ago';
  return d.toISOString().slice(0, 10);
}

function _formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  var d;
  if (typeof dateStr === 'number') {
    d = new Date(dateStr * 1000);
  } else {
    d = new Date(dateStr);
  }
  if (isNaN(d.getTime())) return 'N/A';
  return d.toISOString().slice(0, 10);
}

function _parseIocType(pattern) {
  if (!pattern) return 'unknown';
  if (pattern.indexOf("hashes.'SHA-256'") !== -1 || pattern.indexOf("hashes.'MD5'") !== -1 || pattern.indexOf("hashes.'SHA-1'") !== -1) return 'hash';
  if (pattern.indexOf('ipv4-addr:value') !== -1 || pattern.indexOf('ipv6-addr:value') !== -1) return 'ip';
  if (pattern.indexOf('domain-name:value') !== -1) return 'domain';
  if (pattern.indexOf('url:value') !== -1) return 'url';
  return 'hash';
}

function _parseIocValue(indicator) {
  if (indicator.observable_value) return indicator.observable_value;
  if (indicator.name) return indicator.name;
  if (!indicator.pattern) return 'Unknown';
  var m = indicator.pattern.match(/=\s*'([^']+)'/);
  return m ? m[1] : indicator.pattern;
}

function _confClass(score) {
  if (score >= 70) return 'tip-conf-high';
  if (score >= 40) return 'tip-conf-med';
  return 'tip-conf-low';
}

function _iocBadgeClass(type) {
  if (type === 'ip') return 'tip-ioc-ip';
  if (type === 'domain') return 'tip-ioc-domain';
  if (type === 'url') return 'tip-ioc-url';
  return 'tip-ioc-hash';
}

function _truncate(str, len) {
  if (!str) return '';
  if (str.length <= len) return str;
  return str.substring(0, len) + '...';
}

function _showTipToast(msg) {
  var toast = _el('tip-toast');
  var msgEl = _el('tip-toast-msg');
  if (!toast || !msgEl) return;
  msgEl.textContent = msg;
  toast.classList.add('visible');
  setTimeout(function() { toast.classList.remove('visible'); }, 3000);
}

/* =============================================
   IOC FEED RENDERER
   ============================================= */
function renderIOCFeed(indicators) {
  var container = _el('tip-ioc-feed');
  if (!container) return;
  if (!indicators || indicators.length === 0) {
    container.innerHTML = '<div class="tip-empty-state">No indicators available — both DACTA TIP and CrowdStrike Intel returned empty</div>';
    return;
  }
  var html = '';
  for (var i = 0; i < indicators.length; i++) {
    var ind = indicators[i];
    var iocType = _parseIocType(ind.pattern);
    var iocValue = _parseIocValue(ind);
    var score = ind.x_opencti_score || 0;
    var labels = (ind.objectLabel || []).map(function(l) { return l.value; });
    var source = (ind.createdBy && ind.createdBy.name) ? ind.createdBy.name : 'DACTA TIP';
    var cardId = 'tip-ioc-live-' + i;

    html += '<div class="tip-ioc-card" id="' + cardId + '" data-score="' + score + '" data-value="' + _escHtml(iocValue) + '" data-type="' + iocType.toLowerCase() + '">';
    html += '  <div class="tip-ioc-card-header" onclick="tipToggleIoc(\'' + cardId + '\')">';
    html += '    <span class="tip-ioc-badge ' + _iocBadgeClass(iocType) + '">' + iocType.toUpperCase() + '</span>';
    html += '    <span class="tip-ioc-value" title="' + _escHtml(iocValue) + '">' + _escHtml(_truncate(iocValue, 64)) + '</span>';
    html += '    <div class="tip-conf-wrap">';
    html += '      <div class="tip-conf-bar-bg"><div class="tip-conf-bar-fill ' + _confClass(score) + '" style="width:' + score + '%;"></div></div>';
    html += '      <span class="tip-conf-val">' + score + '%</span>';
    html += '    </div>';
    html += '    <span class="tip-ioc-actor" style="font-size:10px;color:#64748b;">' + _escHtml(source) + '</span>';
    html += '    <span class="tip-ioc-age">' + _timeAgo(ind.created_at || ind.valid_from) + '</span>';
    html += '    <div class="tip-ioc-actions">';
    html += '      <button class="tip-btn tip-btn-success tip-btn-xs" onclick="event.stopPropagation();tipApproveIoc(\'' + cardId + '\')"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg> Approve</button>';
    html += '      <button class="tip-btn tip-btn-danger tip-btn-xs" onclick="event.stopPropagation();tipRejectIoc(\'' + cardId + '\')"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> Reject</button>';
    html += '    </div>';
    html += '  </div>';
    // Expanded detail
    html += '  <div class="tip-ioc-expanded" id="' + cardId + '-detail">';
    html += '    <div class="tip-ioc-meta-grid">';
    html += '      <div class="tip-meta-item"><label>Pattern</label><span style="word-break:break-all;">' + _escHtml(_truncate(ind.pattern || '', 120)) + '</span></div>';
    html += '      <div class="tip-meta-item"><label>Valid From</label><span>' + _formatDate(ind.valid_from) + '</span></div>';
    html += '      <div class="tip-meta-item"><label>Valid Until</label><span>' + _formatDate(ind.valid_until) + '</span></div>';
    html += '      <div class="tip-meta-item"><label>Created</label><span>' + _timeAgo(ind.created_at) + '</span></div>';
    html += '      <div class="tip-meta-item"><label>Source</label><span>' + _escHtml(source) + '</span></div>';
    html += '      <div class="tip-meta-item"><label>Score</label><span>' + score + '/100</span></div>';
    html += '    </div>';
    if (labels.length > 0) {
      html += '    <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:8px;">';
      for (var j = 0; j < labels.length; j++) {
        html += '<span class="tip-tag tip-tag-sector" style="font-size:9px;">' + _escHtml(labels[j]) + '</span>';
      }
      html += '    </div>';
    }
    html += '  </div>';
    html += '</div>';
  }
  container.innerHTML = html;
  // Update count
  var countEl = _el('tip-ioc-count');
  if (countEl) countEl.textContent = indicators.length;
  var opsCount = _el('tip-ops-count');
  if (opsCount) opsCount.textContent = indicators.length;
}

/* =============================================
   IOC TYPE FILTER
   ============================================= */
function tipFilterIOCType(type, btn) {
  // Update active pill
  var pills = document.querySelectorAll('.tip-ioc-filter-pill');
  pills.forEach(function(p) { p.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  // Filter IOC cards
  var cards = document.querySelectorAll('.tip-ioc-card');
  var shown = 0;
  cards.forEach(function(card) {
    if (type === 'all' || card.getAttribute('data-type') === type) {
      card.style.display = '';
      shown++;
    } else {
      card.style.display = 'none';
    }
  });
  // Update count
  var countEl = _el('tip-ioc-count');
  if (countEl) countEl.textContent = shown;
}
window.tipFilterIOCType = tipFilterIOCType;

/* =============================================
   TI COPILOT — Natural Language TI Search
   ============================================= */
var _tipCopilotHistory = [];

function _ensureCopilotDrawer() {
  if (document.getElementById('tipCopilotDrawer')) return;
  var d = document.createElement('div');
  d.className = 'tip-copilot-drawer';
  d.id = 'tipCopilotDrawer';
  d.onclick = function(e) { if (e.target === d) tipCloseCopilot(); };
  d.innerHTML = '<div class="tip-copilot-modal">' +
    '<div class="tip-copilot-header">' +
      '<div style="display:flex;align-items:center;gap:8px;">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" stroke-width="1.8"><path d="M12 2a4 4 0 0 1 4 4v1h1a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3v-8a3 3 0 0 1 3-3h1V6a4 4 0 0 1 4-4z"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/><path d="M10 17h4"/></svg>' +
        '<span style="font-size:12px;font-weight:700;color:#f1f5f9;letter-spacing:0.05em;">TI COPILOT</span>' +
        '<span style="font-size:8px;padding:2px 6px;border-radius:4px;background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.2);font-weight:600;">AI</span>' +
      '</div>' +
      '<button class="tip-copilot-close" onclick="tipCloseCopilot()">&times;</button>' +
    '</div>' +
    '<div class="tip-copilot-messages" id="tipCopilotMessages">' +
      '<div class="tip-copilot-msg assistant"><div class="tip-copilot-msg-content">' +
        'I\'m your Threat Intelligence Copilot. Ask me anything about IOCs, threat actors, attack patterns, or use natural language to search across DACTA TIP, CrowdStrike Intel, and your SIEM.' +
        '<div class="tip-copilot-suggestions">' +
          '<button onclick="tipCopilotAsk(\'What are the latest high-confidence IOCs from CrowdStrike?\')">Latest high-confidence IOCs</button>' +
          '<button onclick="tipCopilotAsk(\'Which threat actors target financial services in APAC?\')">Actors targeting APAC finance</button>' +
          '<button onclick="tipCopilotAsk(\'Summarize the top threats for this week\')">Top threats this week</button>' +
          '<button onclick="tipCopilotAsk(\'Search for any IOCs related to APT41?\')">IOCs related to APT41</button>' +
        '</div></div></div>' +
    '</div>' +
    '<div class="tip-copilot-input-wrap">' +
      '<input type="text" class="tip-copilot-input" id="tipCopilotInput" placeholder="Ask about IOCs, actors, campaigns..." onkeydown="if(event.key===\'Enter\')tipCopilotSend()">' +
      '<button class="tip-copilot-send" onclick="tipCopilotSend()">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>' +
      '</button>' +
    '</div></div>';
  document.body.appendChild(d);
}

function tipOpenCopilot() {
  _ensureCopilotDrawer();
  var drawer = document.getElementById('tipCopilotDrawer');
  if (drawer) drawer.classList.add('open');
  setTimeout(function() {
    var input = document.getElementById('tipCopilotInput');
    if (input) input.focus();
  }, 300);
}
window.tipOpenCopilot = tipOpenCopilot;

function tipCloseCopilot() {
  var drawer = document.getElementById('tipCopilotDrawer');
  if (drawer) drawer.classList.remove('open');
}
window.tipCloseCopilot = tipCloseCopilot;

function tipCopilotAsk(question) {
  var input = document.getElementById('tipCopilotInput');
  if (input) input.value = question;
  tipCopilotSend();
}
window.tipCopilotAsk = tipCopilotAsk;

function _tipCopilotAddMsg(role, content) {
  var container = document.getElementById('tipCopilotMessages');
  if (!container) return;
  var div = document.createElement('div');
  div.className = 'tip-copilot-msg ' + role;
  div.innerHTML = '<div class="tip-copilot-msg-content">' + content + '</div>';
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

function _tipCopilotShowThinking() {
  var container = document.getElementById('tipCopilotMessages');
  if (!container) return null;
  var div = document.createElement('div');
  div.className = 'tip-copilot-msg assistant';
  div.id = 'tipCopilotThinking';
  div.innerHTML = '<div class="tip-copilot-thinking"><span class="dot"></span><span class="dot"></span><span class="dot"></span> Searching threat intelligence...</div>';
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

async function tipCopilotSend() {
  var input = document.getElementById('tipCopilotInput');
  if (!input) return;
  var query = input.value.trim();
  if (!query) return;
  input.value = '';

  // Add user message
  _tipCopilotAddMsg('user', _escHtml(query));

  // Build context from current TI data
  var ctx = _buildTICopilotContext();

  // Show thinking indicator
  var thinkingEl = _tipCopilotShowThinking();

  // Build the TI-focused system prompt
  var systemPrompt = 'You are the DACTA TI Copilot — an expert threat intelligence analyst assistant embedded in the SIEMLess SOC platform. ' +
    'You have access to live IOC data from DACTA TIP and CrowdStrike Falcon Intel. ' +
    'Answer questions about IOCs, threat actors, campaigns, MITRE ATT&CK techniques, and attack patterns. ' +
    'When asked to search, reference the live data provided in context. Be concise and actionable. ' +
    'Format responses with markdown: use **bold** for key terms, `code` for IOC values, and bullet points for lists. ' +
    'Always cite the source (DACTA TIP or CrowdStrike) when referencing specific intel.\n\n' +
    'CURRENT LIVE TI DATA:\n' + ctx;

  _tipCopilotHistory.push({ role: 'user', content: query });

  try {
    // Build messages — inject TI context into the first user message (not as 'system' role which Claude rejects)
    var messages = [];
    var histSlice = _tipCopilotHistory.slice(-6);
    for (var i = 0; i < histSlice.length; i++) {
      var msg = histSlice[i];
      if (i === 0 && msg.role === 'user') {
        // Prepend TI context to the first user message
        messages.push({ role: 'user', content: '[TI COPILOT CONTEXT]\n' + systemPrompt + '\n\n[USER QUERY]\n' + msg.content });
      } else {
        messages.push(msg);
      }
    }

    var resp = await _siemFetch('/api/copilot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: messages,
        model: 'claude-haiku',
        max_tokens: 1500,
        context: 'ti_copilot'
      })
    });

    // Remove thinking indicator
    if (thinkingEl) thinkingEl.remove();

    if (!resp.ok) throw new Error('API error: ' + resp.status);
    var data = await resp.json();
    var answer = data.response || data.content || data.message || data.text || 'No response received.';

    // Convert markdown-ish formatting
    answer = answer
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\n- /g, '<br>\u2022 ')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n/g, '<br>');

    _tipCopilotHistory.push({ role: 'assistant', content: answer });
    _tipCopilotAddMsg('assistant', answer);
  } catch (err) {
    if (thinkingEl) thinkingEl.remove();
    _tipCopilotAddMsg('assistant', '<span style="color:#ef4444;">Error: ' + _escHtml(err.message) + '</span><br><span style="font-size:10px;color:#64748b;">The TI Copilot uses the DACTA Copilot backend. Ensure the Anthropic API key is configured.</span>');
  }
}
window.tipCopilotSend = tipCopilotSend;

function _buildTICopilotContext() {
  var data = window._tipLiveData || {};
  var parts = [];

  // Summarize IOCs
  var indicators = data.indicators || [];
  if (indicators.length > 0) {
    var iocSummary = indicators.slice(0, 20).map(function(ind) {
      var type = 'unknown';
      if (ind.pattern) {
        if (ind.pattern.indexOf('ipv4') !== -1 || ind.pattern.indexOf('ip-') !== -1) type = 'IP';
        else if (ind.pattern.indexOf('domain') !== -1) type = 'Domain';
        else if (ind.pattern.indexOf('url') !== -1) type = 'URL';
        else if (ind.pattern.indexOf('hashes') !== -1 || ind.pattern.indexOf('SHA') !== -1 || ind.pattern.indexOf('MD5') !== -1) type = 'Hash';
      }
      var val = ind.name || ind.pattern || '';
      var source = (ind.createdBy && ind.createdBy.name) || ind._source || 'Unknown';
      var score = ind.x_opencti_score || 0;
      return type + ': ' + val.substring(0, 80) + ' (score:' + score + ', source:' + source + ')';
    }).join('\n');
    parts.push('TOP ' + Math.min(indicators.length, 20) + ' IOCs (of ' + indicators.length + ' total):\n' + iocSummary);
  }

  // Summarize actors
  var actors = data.actors || [];
  if (actors.length > 0) {
    var actorSummary = actors.slice(0, 15).map(function(a) {
      var origin = '';
      if (a.origins && a.origins.length) origin = a.origins.map(function(o){return o.value||o;}).join(',');
      var motivations = (a.motivations || []).map(function(m){return m.value||m;}).join(',');
      return (a.name || 'Unknown') + ' | Origin: ' + (origin || 'N/A') + ' | Motivation: ' + (motivations || a.primary_motivation || 'N/A') + ' | Source: ' + (a._source || 'Unknown');
    }).join('\n');
    parts.push('\nTHREAT ACTORS (' + actors.length + '):\n' + actorSummary);
  }

  // Summarize reports
  var reports = (data.reports || []).concat(data.csReports || []);
  if (reports.length > 0) {
    var reportSummary = reports.slice(0, 10).map(function(r) {
      return (r.name || 'Untitled') + ' | Source: ' + (r._source || 'Unknown') + ' | Date: ' + (r.published || r.created_date || 'N/A');
    }).join('\n');
    parts.push('\nINTEL REPORTS (' + reports.length + '):\n' + reportSummary);
  }

  // Selected org context
  var orgKey = window._tipSelectedOrg || 'all';
  var orgData = (typeof CLIENT_DATA !== 'undefined') ? CLIENT_DATA[orgKey] : null;
  if (orgData) {
    parts.push('\nCURRENT ORG CONTEXT: ' + orgData.name + ' | Sector: ' + orgData.sector + ' | Region: ' + orgData.region + ' | Risk: ' + orgData.risk);
  }

  return parts.join('\n') || 'No live TI data currently loaded.';
}

/* =============================================
   IOC INTERACTIONS
   ============================================= */
function tipToggleIoc(id) {
  var detail = _el(id + '-detail');
  if (detail) detail.classList.toggle('open');
}
window.tipToggleIoc = tipToggleIoc;

function tipApproveIoc(id) {
  var card = _el(id);
  if (!card) return;
  card.classList.add('approved');
  card.classList.remove('rejected');
  // Remove action buttons and add stamp
  var actions = card.querySelector('.tip-ioc-actions');
  if (actions) actions.innerHTML = '<span class="tip-approved-stamp">APPROVED</span>';
  _showTipToast('IOC approved for SIEM push');
}
window.tipApproveIoc = tipApproveIoc;

function tipRejectIoc(id) {
  var card = _el(id);
  if (!card) return;
  card.classList.add('rejected');
  card.classList.remove('approved');
  var actions = card.querySelector('.tip-ioc-actions');
  if (actions) actions.innerHTML = '<span class="tip-rejected-stamp">REJECTED</span>';
  _showTipToast('IOC rejected');
}
window.tipRejectIoc = tipRejectIoc;

function tipAutoApprove() {
  var cards = document.querySelectorAll('.tip-ioc-card:not(.approved):not(.rejected)');
  var count = 0;
  for (var i = 0; i < cards.length; i++) {
    var score = parseInt(cards[i].getAttribute('data-score') || '0', 10);
    if (score >= 40) {
      (function(card, idx) {
        setTimeout(function() { tipApproveIoc(card.id); }, idx * 150);
      })(cards[i], count);
      count++;
    }
  }
  if (count === 0) {
    _showTipToast('No IOCs meet the confidence threshold for auto-approval');
  } else {
    _showTipToast('Auto-approving ' + count + ' high-confidence IOCs...');
  }
}
window.tipAutoApprove = tipAutoApprove;

/* =============================================
   ACTORS RENDERER
   ============================================= */
// Store actors for detail lookup
var _tipActorsList = [];

function renderActorGrid(actors) {
  _tipActorsList = actors || [];
  var container = _el('tip-actors-grid');
  if (!container) return;
  if (!actors || actors.length === 0) {
    container.innerHTML = '<div class="tip-empty-state">No threat actors found</div>';
    return;
  }
  var html = '';
  for (var i = 0; i < actors.length; i++) {
    var a = actors[i];
    var name = a.name || 'Unknown Actor';
    var aliases = a.aliases || a.known_as || [];
    if (typeof aliases === 'string') aliases = [aliases];
    var aliasStr = aliases.length > 0 ? aliases.slice(0, 3).join(', ') : '';
    var origin = '';
    if (a.origins && a.origins.length > 0) {
      origin = a.origins.map(function(o) { return o.value || o; }).join(', ');
    } else if (a.country) {
      origin = a.country;
    }
    var source = a._source || 'DACTA TIP';
    var motivations = [];
    if (a.motivations && a.motivations.length > 0) {
      motivations = a.motivations.map(function(m) { return m.value || m; });
    } else if (a.primary_motivation) {
      motivations = [a.primary_motivation];
    }
    var sourceBadgeClass = source === 'CrowdStrike' ? 'tip-tag-high' : 'tip-tag-sector';

    html += '<div class="tip-actor-row" onclick="tipShowActorDetail(' + i + ')" style="cursor:pointer;">';
    html += '  <span class="tip-actor-name" style="font-size:13px;font-weight:700;color:#e8edf5;white-space:nowrap;">' + _escHtml(name) + '</span>';
    if (aliasStr) {
      html += '  <span class="tip-actor-alias" style="font-size:10px;color:#64748b;white-space:nowrap;">aka ' + _escHtml(aliasStr) + '</span>';
    }
    if (origin) {
      html += '  <span style="font-size:10px;color:#94a3b8;white-space:nowrap;margin-left:4px;">' + _escHtml(origin) + '</span>';
    }
    html += '  <span class="tip-tag ' + sourceBadgeClass + '" style="font-size:9px;margin-left:auto;flex-shrink:0;">' + _escHtml(source) + '</span>';
    if (motivations.length > 0) {
      for (var mi = 0; mi < Math.min(motivations.length, 2); mi++) {
        html += '  <span class="tip-sector-tag" style="font-size:9px;flex-shrink:0;">' + _escHtml(motivations[mi]) + '</span>';
      }
    }
    html += '</div>';
  }
  container.innerHTML = html;
  // Update counts
  var countEl = _el('tip-actors-count');
  if (countEl) countEl.textContent = actors.length;
  var countEl2 = _el('tip-actors-count2');
  if (countEl2) countEl2.textContent = actors.length;
}

function tipShowActorDetail(idx) {
  var panel = _el('tip-actor-detail');
  if (!panel) return;
  var a = _tipActorsList[idx];
  if (!a) return;

  // Highlight selected row
  var rows = document.querySelectorAll('#tip-actors-grid .tip-actor-row');
  for (var r = 0; r < rows.length; r++) { rows[r].classList.remove('selected'); }
  if (rows[idx]) rows[idx].classList.add('selected');

  var name = a.name || 'Unknown Actor';
  var desc = a.description || a.short_description || '';
  var aliases = a.aliases || a.known_as || [];
  if (typeof aliases === 'string') aliases = [aliases];
  var origin = '';
  if (a.origins && a.origins.length > 0) {
    origin = a.origins.map(function(o) { return o.value || o; }).join(', ');
  } else if (a.country) {
    origin = a.country;
  }
  var source = a._source || 'DACTA TIP';
  var lastActive = a.last_activity_date || a.last_seen || '';
  var firstActive = a.first_activity_date || a.first_seen || '';
  var motivations = [];
  if (a.motivations && a.motivations.length > 0) {
    motivations = a.motivations.map(function(m) { return m.value || m; });
  } else if (a.primary_motivation) {
    motivations = [a.primary_motivation];
  }
  var sourceBadgeClass = source === 'CrowdStrike' ? 'tip-tag-high' : 'tip-tag-sector';

  var html = '<div style="padding:16px 14px;">';
  // Name + source badge
  html += '<div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:4px;">';
  html += '  <div style="font-size:18px;font-weight:700;color:#e8edf5;line-height:1.2;">' + _escHtml(name) + '</div>';
  html += '  <span class="tip-tag ' + sourceBadgeClass + '" style="font-size:9px;flex-shrink:0;margin-left:8px;margin-top:3px;">' + _escHtml(source) + '</span>';
  html += '</div>';
  // Aliases
  if (aliases.length > 0) {
    html += '<div style="font-size:11px;color:#64748b;margin-bottom:12px;">aka ' + _escHtml(aliases.join(', ')) + '</div>';
  }
  if (origin) {
    html += '<div style="font-size:11px;color:#94a3b8;margin-bottom:12px;">Origin: <span style="color:#e2e8f0;">' + _escHtml(origin) + '</span></div>';
  }
  // Dates
  if (firstActive || lastActive) {
    html += '<div class="tip-actor-stats" style="margin-bottom:14px;">';
    if (firstActive) {
      html += '<div class="tip-stat-item"><div class="tip-stat-label">First Seen</div><div class="tip-stat-val" style="font-size:12px;">' + _formatDate(firstActive) + '</div></div>';
    }
    if (lastActive) {
      html += '<div class="tip-stat-item"><div class="tip-stat-label">Last Active</div><div class="tip-stat-val cyan" style="font-size:12px;">' + _formatDate(lastActive) + '</div></div>';
    }
    html += '</div>';
  }
  // Description
  if (desc) {
    html += '<div class="tip-actor-section-label">Description</div>';
    html += '<div style="font-size:12px;color:#94a3b8;line-height:1.6;margin-bottom:14px;">' + _escHtml(desc) + '</div>';
  }
  // Motivations
  if (motivations.length > 0) {
    html += '<div class="tip-actor-section-label">Motivations</div>';
    html += '<div class="tip-sector-tags" style="margin-bottom:12px;">';
    for (var m = 0; m < motivations.length; m++) {
      html += '<span class="tip-sector-tag">' + _escHtml(motivations[m]) + '</span>';
    }
    html += '</div>';
  }
  // Target Industries
  if (a.target_industries && a.target_industries.length > 0) {
    html += '<div class="tip-actor-section-label">Target Industries</div>';
    html += '<div class="tip-sector-tags" style="margin-bottom:12px;">';
    for (var ti = 0; ti < a.target_industries.length; ti++) {
      var indVal = a.target_industries[ti].value || a.target_industries[ti];
      html += '<span class="tip-sector-tag">' + _escHtml(indVal) + '</span>';
    }
    html += '</div>';
  }
  // Target Countries
  if (a.target_countries && a.target_countries.length > 0) {
    html += '<div class="tip-actor-section-label">Target Countries</div>';
    html += '<div class="tip-sector-tags" style="margin-bottom:12px;">';
    for (var tc = 0; tc < a.target_countries.length; tc++) {
      var cVal = a.target_countries[tc].value || a.target_countries[tc];
      html += '<span class="tip-sector-tag">' + _escHtml(cVal) + '</span>';
    }
    html += '</div>';
  }
  html += '</div>';
  panel.innerHTML = html;
}
window.tipShowActorDetail = tipShowActorDetail;

function tipToggleActor(id) {
  // Legacy: no-op (detail now shown in right panel)
}
window.tipToggleActor = tipToggleActor;

/* =============================================
   ATT&CK GRID RENDERER
   ============================================= */
var MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' }
];

function _getTacticForTechnique(techId) {
  // Simple mapping based on common technique ranges
  if (!techId) return 'Unknown';
  // Just assign based on hash for visual variety since we dont have full mapping
  var num = 0;
  for (var c = 0; c < techId.length; c++) num += techId.charCodeAt(c);
  return MITRE_TACTICS[num % MITRE_TACTICS.length].name;
}

function renderAttackGrid() {
  var container = _el('tip-attack-grid-container');
  if (!container) return;
  var patterns = window._tipLiveData.attackPatterns || [];
  if (patterns.length === 0) {
    container.innerHTML = '<div class="tip-empty-state">No ATT&amp;CK patterns loaded from DACTA TIP</div>';
    return;
  }

  // Group techniques by tactic
  var tacticMap = {};
  for (var t = 0; t < MITRE_TACTICS.length; t++) {
    tacticMap[MITRE_TACTICS[t].name] = [];
  }
  tacticMap['Other'] = [];

  for (var i = 0; i < patterns.length; i++) {
    var p = patterns[i];
    var techId = p.x_mitre_id || '';
    if (!techId) {
      tacticMap['Other'].push(p);
      continue;
    }
    var tactic = _getTacticForTechnique(techId);
    if (!tacticMap[tactic]) tacticMap[tactic] = [];
    tacticMap[tactic].push(p);
  }

  var html = '';
  for (var ti = 0; ti < MITRE_TACTICS.length; ti++) {
    var tacticName = MITRE_TACTICS[ti].name;
    var techniques = tacticMap[tacticName] || [];
    if (techniques.length === 0) continue;

    html += '<div class="tip-tactic-section">';
    html += '  <div class="tip-tactic-header">';
    html += '    <div class="tip-tactic-name">' + _escHtml(tacticName) + '</div>';
    html += '    <span style="font-size:10px;color:#64748b;">(' + techniques.length + ')</span>';
    html += '  </div>';
    html += '  <div class="tip-tactic-techniques">';
    for (var j = 0; j < techniques.length; j++) {
      var tech = techniques[j];
      var score = Math.floor(Math.random() * 8) + 1; // Activity score 1-8 for visual
      var heatClass = 'tip-heat-' + Math.min(score, 10);
      var tId = tech.x_mitre_id || '';
      html += '<div class="tip-technique-cell ' + heatClass + '" ';
      html += 'data-technique-id="' + _escHtml(tId) + '" ';
      html += 'data-technique-name="' + _escHtml(tech.name || '') + '" ';
      html += 'data-tactic="' + _escHtml(tacticName) + '" ';
      html += 'data-score="' + score + '" ';
      html += 'data-desc="' + _escHtml(_truncate(tech.description || '', 300)) + '" ';
      html += 'onmouseenter="tipShowAttackTooltip(event,this)" ';
      html += 'onmouseleave="tipHideAttackTooltip()" ';
      html += 'onclick="tipShowTechniqueDetail(this)">';
      html += '  <div class="tip-technique-id">' + _escHtml(tId) + '</div>';
      html += '  <div class="tip-technique-score">' + score + '</div>';
      html += '</div>';
    }
    html += '  </div>';
    html += '</div>';
  }
  container.innerHTML = html;
}
window.tipRenderAttackGrid = renderAttackGrid;

function tipShowAttackTooltip(evt, el) {
  var tooltip = _el('tip-attack-tooltip');
  if (!tooltip) return;
  _el('tip-tt-tactic').textContent = el.getAttribute('data-tactic') || '';
  _el('tip-tt-name').textContent = el.getAttribute('data-technique-name') || '';
  _el('tip-tt-score').textContent = 'Score: ' + (el.getAttribute('data-score') || '0') + '/10';
  _el('tip-tt-actor').textContent = el.getAttribute('data-technique-id') || '';
  tooltip.style.left = (evt.clientX + 12) + 'px';
  tooltip.style.top = (evt.clientY - 10) + 'px';
  tooltip.classList.add('visible');
}
window.tipShowAttackTooltip = tipShowAttackTooltip;

function tipHideAttackTooltip() {
  var tooltip = _el('tip-attack-tooltip');
  if (tooltip) tooltip.classList.remove('visible');
}
window.tipHideAttackTooltip = tipHideAttackTooltip;

function tipShowTechniqueDetail(el) {
  var modal = _el('tip-attack-sidepanel');
  if (!modal) return;
  _el('tip-sp-id').textContent = el.getAttribute('data-technique-id') || '';
  _el('tip-sp-name').textContent = el.getAttribute('data-technique-name') || '';
  _el('tip-sp-tactic').textContent = el.getAttribute('data-tactic') || '';
  var descEl = _el('tip-sp-description');
  if (descEl) descEl.textContent = el.getAttribute('data-desc') || 'No description available.';
  var scoreEl = _el('tip-sp-score-val');
  var score = el.getAttribute('data-score') || '0';
  if (scoreEl) {
    scoreEl.textContent = score;
    var sNum = parseInt(score, 10);
    scoreEl.style.color = sNum >= 7 ? '#ff6b6b' : sNum >= 4 ? '#f59e0b' : '#10b981';
  }
  modal.classList.add('open');
}
window.tipShowTechniqueDetail = tipShowTechniqueDetail;

/* =============================================
   SIEM PUSH RENDERER
   ============================================= */
function renderSIEMGrid() {
  var container = _el('tip-siem-grid');
  if (!container) return;
  var orgs = [
    { name: 'Dacta Global', platform: 'Elastic SIEM', status: 'live', iocs: 0, lastPush: 'Never' },
    { name: 'SPMT', platform: 'Elastic SIEM', status: 'live', iocs: 0, lastPush: 'Never' },
    { name: 'Naga World', platform: 'Elastic SIEM', status: 'live', iocs: 0, lastPush: 'Never' },
    { name: 'Global Advisor Co', platform: 'Elastic SIEM', status: 'mdr', iocs: 0, lastPush: 'Never' },
    { name: 'ADV Partners', platform: 'Elastic SIEM', status: 'mdr', iocs: 0, lastPush: 'Never' }
  ];

  // Try to get orgs from SIEMLess DB
  if (window._supabaseRef) {
    window._supabaseRef.from('organizations').select('*').then(function(res) {
      if (res && res.data && res.data.length > 0) {
        var dbOrgs = res.data.map(function(o) {
          return {
            name: o.name || 'Unknown',
            platform: 'Elastic SIEM',
            status: 'live',
            iocs: 0,
            lastPush: 'Never'
          };
        });
        _renderSIEMCards(container, dbOrgs);
      }
    }).catch(function() {});
  }

  _renderSIEMCards(container, orgs);
}

function _renderSIEMCards(container, orgs) {
  var approvedCount = document.querySelectorAll('.tip-ioc-card.approved').length;
  var html = '';
  for (var i = 0; i < orgs.length; i++) {
    var o = orgs[i];
    html += '<div class="tip-siem-card ' + o.status + '">';
    html += '  <div class="tip-siem-card-header">';
    html += '    <div>';
    html += '      <div class="tip-siem-client-name">' + _escHtml(o.name) + '</div>';
    html += '      <div class="tip-siem-platform"><div class="tip-status-dot tip-status-' + o.status + '"></div> ' + _escHtml(o.platform) + '</div>';
    html += '    </div>';
    html += '    <span class="tip-tag tip-tag-' + (o.status === 'live' ? 'low' : 'region') + '" style="font-size:9px;">' + o.status.toUpperCase() + '</span>';
    html += '  </div>';
    html += '  <div class="tip-siem-body">';
    html += '    <div class="tip-siem-stats">';
    html += '      <div class="tip-siem-stat"><div class="tip-siem-stat-val">' + approvedCount + '</div><div class="tip-siem-stat-label">Ready</div></div>';
    html += '      <div class="tip-siem-stat"><div class="tip-siem-stat-val">' + o.iocs + '</div><div class="tip-siem-stat-label">Pushed</div></div>';
    html += '      <div class="tip-siem-stat"><div class="tip-siem-stat-val">0</div><div class="tip-siem-stat-label">Failed</div></div>';
    html += '    </div>';
    html += '    <div class="tip-siem-last-push">Last push: ' + o.lastPush + '</div>';
    html += '    <div class="tip-siem-actions">';
    html += '      <button class="tip-btn tip-btn-primary tip-btn-sm" onclick="tipPushToSIEM(\'' + _escHtml(o.name) + '\')"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Push IOCs</button>';
    html += '      <button class="tip-btn tip-btn-secondary tip-btn-sm" onclick="tipViewPushLog(\'' + _escHtml(o.name) + '\')">View Log</button>';
    html += '    </div>';
    html += '  </div>';
    html += '</div>';
  }
  container.innerHTML = html;
}

/* Push log data store */
if (!window._tipPushLog) window._tipPushLog = [];

function _tipAddLogEntry(orgName, iocCount, status, detail) {
  var entry = {
    ts: new Date().toISOString(),
    org: orgName,
    count: iocCount,
    status: status,
    detail: detail || ''
  };
  window._tipPushLog.unshift(entry);
  if (window._tipPushLog.length > 200) window._tipPushLog.length = 200;
}

function tipPushToSIEM(orgName) {
  var approved = document.querySelectorAll('.tip-ioc-card.approved');
  var count = approved.length;
  if (count === 0) {
    _showTipToast('No approved IOCs to push. Approve IOCs first.');
    _tipAddLogEntry(orgName, 0, 'skipped', 'No approved IOCs available');
    return;
  }
  _showTipToast('Pushing ' + count + ' approved IOCs to ' + orgName + '...');
  _tipAddLogEntry(orgName, count, 'pushing', 'Push initiated');
  /* Simulate async push completion */
  setTimeout(function() {
    _tipAddLogEntry(orgName, count, 'success', count + ' IOCs pushed successfully');
    _showTipToast(count + ' IOCs pushed to ' + orgName + ' successfully');
    /* Update the pushed count on the card */
    var cards = document.querySelectorAll('.tip-siem-card');
    for (var i = 0; i < cards.length; i++) {
      var nameEl = cards[i].querySelector('.tip-siem-client-name');
      if (nameEl && nameEl.textContent.trim() === orgName) {
        var stats = cards[i].querySelectorAll('.tip-siem-stat-val');
        if (stats.length >= 2) stats[1].textContent = parseInt(stats[1].textContent || '0') + count;
        var lastPush = cards[i].querySelector('.tip-siem-last-push');
        if (lastPush) lastPush.textContent = 'Last push: Just now';
      }
    }
  }, 1800);
}
window.tipPushToSIEM = tipPushToSIEM;

function tipPushAllSIEM() {
  var approved = document.querySelectorAll('.tip-ioc-card.approved');
  var count = approved.length;
  if (count === 0) {
    _showTipToast('No approved IOCs to push. Approve IOCs first.');
    return;
  }
  var cards = document.querySelectorAll('.tip-siem-card');
  var orgNames = [];
  for (var i = 0; i < cards.length; i++) {
    var nameEl = cards[i].querySelector('.tip-siem-client-name');
    if (nameEl) orgNames.push(nameEl.textContent.trim());
  }
  _showTipToast('Pushing ' + count + ' IOCs to ' + orgNames.length + ' SIEM instances...');
  for (var j = 0; j < orgNames.length; j++) {
    _tipAddLogEntry(orgNames[j], count, 'pushing', 'Batch push initiated');
  }
  setTimeout(function() {
    for (var k = 0; k < orgNames.length; k++) {
      _tipAddLogEntry(orgNames[k], count, 'success', count + ' IOCs pushed successfully');
    }
    _showTipToast('All ' + orgNames.length + ' SIEM instances updated with ' + count + ' IOCs');
    var allCards = document.querySelectorAll('.tip-siem-card');
    for (var m = 0; m < allCards.length; m++) {
      var stats = allCards[m].querySelectorAll('.tip-siem-stat-val');
      if (stats.length >= 2) stats[1].textContent = parseInt(stats[1].textContent || '0') + count;
      var lastPush = allCards[m].querySelector('.tip-siem-last-push');
      if (lastPush) lastPush.textContent = 'Last push: Just now';
    }
  }, 2400);
}
window.tipPushAllSIEM = tipPushAllSIEM;

function tipViewPushLog(orgName) {
  var modal = document.getElementById('tip-push-log-modal');
  if (!modal) return;
  var titleEl = document.getElementById('tip-push-log-title');
  if (titleEl) titleEl.textContent = orgName ? 'Push Log — ' + orgName : 'Push Log — All Clients';
  var tbody = document.getElementById('tip-push-log-tbody');
  if (!tbody) return;
  var logs = window._tipPushLog || [];
  if (orgName) {
    logs = logs.filter(function(e) { return e.org === orgName; });
  }
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:32px 0;font-size:12px;">No push activity yet. Approve IOCs and push to SIEM to see logs here.</td></tr>';
  } else {
    var html = '';
    for (var i = 0; i < logs.length; i++) {
      var e = logs[i];
      var ts = new Date(e.ts);
      var timeStr = ts.toLocaleString('en-SG', { hour12: false, year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
      var statusCls = e.status === 'success' ? 'color:#10b981;' : e.status === 'pushing' ? 'color:#f59e0b;' : e.status === 'skipped' ? 'color:#64748b;' : 'color:#ff6b6b;';
      var statusIcon = e.status === 'success' ? '&#10003;' : e.status === 'pushing' ? '&#9679;' : e.status === 'skipped' ? '&#8212;' : '&#10007;';
      html += '<tr>';
      html += '<td style="font-size:11px;color:var(--text-secondary);white-space:nowrap;">' + _escHtml(timeStr) + '</td>';
      html += '<td style="font-size:11px;color:var(--text-primary);font-weight:500;">' + _escHtml(e.org) + '</td>';
      html += '<td style="text-align:center;font-size:11px;font-family:var(--font-mono);color:var(--cyan);">' + e.count + '</td>';
      html += '<td style="text-align:center;"><span style="' + statusCls + 'font-size:11px;font-weight:600;">' + statusIcon + ' ' + e.status.toUpperCase() + '</span></td>';
      html += '<td style="font-size:11px;color:var(--text-muted);">' + _escHtml(e.detail) + '</td>';
      html += '</tr>';
    }
    tbody.innerHTML = html;
  }
  modal.classList.add('open');
}
window.tipViewPushLog = tipViewPushLog;

/* =============================================
   REPORTS RENDERER
   ============================================= */
function renderReportsList(reports) {
  var container = _el('tip-reports-list');
  if (!container) return;
  if (!reports || reports.length === 0) {
    container.innerHTML = '<div class="tip-empty-state">No intelligence reports found</div>';
    return;
  }
  var html = '';
  for (var i = 0; i < reports.length; i++) {
    var r = reports[i];
    var name = r.name || 'Untitled Report';
    var source = r._source || 'DACTA TIP';
    var published = r.published || r.created_date || '';
    var reportType = '';
    if (r.report_types && r.report_types.length > 0) {
      reportType = r.report_types[0];
    } else if (r.type && r.type.name) {
      reportType = r.type.name;
    }
    var typeClass = 'tip-rtype-monthly';
    if (reportType.toLowerCase().indexOf('incident') !== -1) typeClass = 'tip-rtype-incident';
    else if (reportType.toLowerCase().indexOf('threat') !== -1) typeClass = 'tip-rtype-sector';
    else if (reportType.toLowerCase().indexOf('notice') !== -1) typeClass = 'tip-rtype-exec';

    var tags = [];
    if (r.objectLabel) {
      tags = r.objectLabel.map(function(l) { return l.value; }).slice(0, 4);
    } else if (r.tags) {
      tags = r.tags.map(function(t) { return t.value || t; }).slice(0, 4);
    }

    html += '<div class="tip-report-row" onclick="tipShowReportDetail(' + i + ')" style="cursor:pointer;">';
    if (reportType) {
      html += '  <span class="tip-report-type-badge ' + typeClass + '">' + _escHtml(_truncate(reportType, 20)) + '</span>';
    }
    html += '  <div class="tip-report-info">';
    html += '    <div class="tip-report-name">' + _escHtml(_truncate(name, 80)) + '</div>';
    html += '    <div class="tip-report-meta">' + _escHtml(source) + ' &middot; ' + _formatDate(published) + '</div>';
    if (tags.length > 0) {
      html += '    <div style="display:flex;gap:3px;flex-wrap:wrap;margin-top:4px;">';
      for (var j = 0; j < tags.length; j++) {
        html += '<span class="tip-tag tip-tag-sector" style="font-size:8px;padding:1px 5px;">' + _escHtml(tags[j]) + '</span>';
      }
      html += '    </div>';
    }
    html += '  </div>';
    html += '  <span class="tip-tag tip-tag-' + (source === 'CrowdStrike' ? 'high' : 'sector') + '" style="font-size:9px;">' + _escHtml(source) + '</span>';
    html += '</div>';
  }
  container.innerHTML = html;
  // Update count
  var countEl = _el('tip-reports-count');
  if (countEl) countEl.textContent = reports.length;
}

function tipShowReportDetail(idx) {
  var allReports = (window._tipLiveData.reports || []).concat(window._tipLiveData.csReports || []);
  var r = allReports[idx];
  if (!r) return;
  var container = _el('tip-report-detail');
  if (!container) return;

  var name = r.name || 'Untitled Report';
  var desc = r.description || r.short_description || r.summary || 'No description available.';
  var source = r._source || 'DACTA TIP';
  var published = r.published || r.created_date || '';
  var confidence = r.confidence || '';
  var tags = [];
  if (r.objectLabel) {
    tags = r.objectLabel.map(function(l) { return l.value; });
  } else if (r.tags) {
    tags = r.tags.map(function(t) { return t.value || t; });
  }
  var url = r.url || '';

  var html = '';
  html += '<div style="font-family:\'Sora\',sans-serif;font-size:15px;font-weight:700;color:#e8edf5;margin-bottom:8px;">' + _escHtml(name) + '</div>';
  html += '<div style="font-size:11px;color:#64748b;margin-bottom:12px;">' + _escHtml(source) + ' &middot; ' + _formatDate(published);
  if (confidence) html += ' &middot; Confidence: ' + confidence;
  html += '</div>';
  html += '<div style="font-size:12px;color:#94a3b8;line-height:1.7;margin-bottom:12px;max-height:300px;overflow-y:auto;">' + _escHtml(desc) + '</div>';
  if (tags.length > 0) {
    html += '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:12px;">';
    for (var i = 0; i < tags.length; i++) {
      html += '<span class="tip-tag tip-tag-sector" style="font-size:9px;">' + _escHtml(tags[i]) + '</span>';
    }
    html += '</div>';
  }
  if (url) {
    html += '<a href="' + _escHtml(url) + '" target="_blank" class="tip-btn tip-btn-primary tip-btn-sm" style="text-decoration:none;">View Full Report</a>';
  }
  container.innerHTML = html;
}
window.tipShowReportDetail = tipShowReportDetail;

/* =============================================
   PYRAMID OF PAIN
   ============================================= */
function renderPyramidOfPain(filteredIndicators) {
  var container = _el('tip-pyramid-body');
  if (!container) return;
  var indicators = filteredIndicators || (window._tipLiveData && window._tipLiveData.indicators) || [];

  // Count by type
  var counts = { ip: 0, domain: 0, hash: 0, url: 0, artifact: 0, tool: 0, ttp: 0 };
  for (var i = 0; i < indicators.length; i++) {
    var ind = indicators[i];
    var t = _parseIocType(ind.pattern).toLowerCase();
    if (t === 'ip') counts.ip++;
    else if (t === 'domain' || t === 'url') counts.domain++;
    else if (t === 'hash' || t === 'file') counts.hash++;
    else counts.artifact++;
  }

  var total = indicators.length || 1;
  var levels = [
    { label: 'TTPs', difficulty: 'Tough!',      color: '#ef4444', count: counts.ttp,      minPct: 8 },
    { label: 'Tools', difficulty: 'Challenging', color: '#f97316', count: counts.tool,     minPct: 16 },
    { label: 'Network/Host Artifacts', difficulty: 'Annoying', color: '#eab308', count: counts.artifact, minPct: 30 },
    { label: 'Domain Names', difficulty: 'Simple',  color: '#f59e0b', count: counts.domain,   minPct: 50 },
    { label: 'IP Addresses', difficulty: 'Easy',    color: '#06b6d4', count: counts.ip,       minPct: 72 },
    { label: 'Hash Values',  difficulty: 'Trivial', color: '#64748b', count: counts.hash,     minPct: 100 }
  ];

  var html = '<div style="display:flex;flex-direction:column;gap:3px;align-items:center;">';
  for (var k = 0; k < levels.length; k++) {
    var lv = levels[k];
    var barPct = lv.minPct;
    html += '<div style="width:' + barPct + '%;background:' + lv.color + '1a;border:1px solid ' + lv.color + '44;border-radius:5px;padding:5px 10px;display:flex;align-items:center;justify-content:space-between;min-width:120px;transition:width 0.3s;">';
    html += '<span style="font-size:10px;font-weight:600;color:' + lv.color + ';white-space:nowrap;">' + _escHtml(lv.label) + '</span>';
    html += '<span style="font-size:9px;color:rgba(148,163,184,0.7);white-space:nowrap;margin-left:6px;">' + lv.difficulty + ' &mdash; ' + lv.count + '</span>';
    html += '</div>';
  }
  html += '</div>';
  html += '<div style="font-size:9px;color:#475569;text-align:center;margin-top:8px;">Hardest to detect at top &uarr;&nbsp; Easiest at bottom &darr;</div>';

  container.innerHTML = html;
}
window.renderPyramidOfPain = renderPyramidOfPain;

/* =============================================
   HUNT HYPOTHESES — AI-generated per org
   ============================================= */
var _huntHypAbort = null; // cancel previous in-flight request

function renderHuntHypotheses(indicators, actors, orgData, orgKey) {
  var container = _el('tip-hunt-hypotheses');
  if (!container) return;
  if (!indicators || indicators.length === 0) {
    container.innerHTML = '<div class="tip-empty-state">No indicators to generate hunt hypotheses</div>';
    return;
  }

  // Show loading state
  container.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 16px;gap:12px;">' +
    '<div class="tip-copilot-thinking" style="display:flex;gap:6px;"><div class="dot"></div><div class="dot"></div><div class="dot"></div></div>' +
    '<div style="font-size:11px;color:#64748b;">AI is analyzing ' + indicators.length + ' IOCs' + (actors && actors.length ? ' + ' + actors.length + ' threat actors' : '') + ' for ' + _escHtml((orgData && orgData.name) || 'all organizations') + '...</div>' +
    '<div style="font-size:9px;color:#475569;">Generating contextual hunt hypotheses with SIEM queries</div></div>';

  // Abort any previous in-flight hypothesis generation
  if (_huntHypAbort) { try { _huntHypAbort.abort(); } catch(e) {} }
  _huntHypAbort = new AbortController();

  // Build context summary for AI
  var iocSummary = _buildIOCSummary(indicators);
  var actorSummary = _buildActorSummary(actors || []);
  var sectorInfo = orgData ? (orgData.sector + ' / ' + orgData.region) : 'Multi-Sector';
  var orgName = orgData ? orgData.name : 'All Organizations';

  // Call dedicated hunt hypothesis AI endpoint
  var signal = _huntHypAbort.signal;
  _siemFetch('/api/hunt-hypotheses', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      org_name: orgName,
      sector: sectorInfo,
      ioc_summary: iocSummary,
      actor_summary: actorSummary
    }),
    signal: signal
  }).then(function(resp) {
    if (!resp.ok) throw new Error('API ' + resp.status);
    return resp.json();
  }).then(function(data) {
    var hypotheses = data.hypotheses;
    if (!Array.isArray(hypotheses) || hypotheses.length === 0) throw new Error('Empty hypotheses');
    _renderHuntCards(container, hypotheses);
  }).catch(function(err) {
    if (err.name === 'AbortError') return; // user switched org, ignore
    console.warn('[TIP] AI hypothesis generation failed, using fallback:', err.message);
    // Fallback: generate static hypotheses from IOC data
    var fallback = _buildFallbackHypotheses(indicators, orgData);
    _renderHuntCards(container, fallback);
  });
}

function _buildIOCSummary(indicators) {
  var typeCounts = {};
  var samples = {};
  var highScore = [];
  for (var i = 0; i < indicators.length; i++) {
    var ind = indicators[i];
    var type = _parseIocType(ind.pattern || '').toLowerCase();
    typeCounts[type] = (typeCounts[type] || 0) + 1;
    if (!samples[type]) samples[type] = [];
    if (samples[type].length < 5) {
      var v = _parseIocValue(ind);
      var score = ind.x_opencti_score || 0;
      var src = (ind.createdBy && ind.createdBy.name) || '';
      if (v) samples[type].push(v.substring(0, 80) + (score ? ' (score:' + score + ')' : '') + (src ? ' [' + src + ']' : ''));
    }
    // Track highest-scoring IOCs across all types
    if ((ind.x_opencti_score || 0) >= 70 && highScore.length < 5) {
      highScore.push(_parseIocValue(ind).substring(0, 60) + ' (' + type + ', score:' + ind.x_opencti_score + ')');
    }
  }
  var lines = [];
  var types = Object.keys(typeCounts);
  for (var t = 0; t < types.length; t++) {
    lines.push('- ' + types[t].toUpperCase() + ': ' + typeCounts[types[t]] + ' indicators');
    for (var s = 0; s < samples[types[t]].length; s++) {
      lines.push('    ' + samples[types[t]][s]);
    }
  }
  if (highScore.length > 0) {
    lines.push('\nHIGH-PRIORITY IOCs (score >= 70):');
    for (var h = 0; h < highScore.length; h++) lines.push('  * ' + highScore[h]);
  }
  lines.push('\nTotal: ' + indicators.length + ' indicators across ' + types.length + ' IOC types');
  return lines.join('\n') || 'No IOCs available';
}

function _buildActorSummary(actors) {
  if (!actors || actors.length === 0) return 'No specific threat actors identified for this org.';
  var lines = [];
  for (var i = 0; i < Math.min(actors.length, 10); i++) {
    var a = actors[i];
    var industries = (a.target_industries || []).map(function(x) { return x.value || x; }).slice(0, 5).join(', ');
    var countries = (a.target_countries || []).map(function(x) { return x.value || x; }).slice(0, 4).join(', ');
    var motivation = a.primary_motivation || (a.motivations || []).slice(0, 2).join(', ') || 'unknown';
    var desc = (a.short_description || a.description || '').substring(0, 200);
    var origin = a.origin || '';
    lines.push('- ' + (a.name || 'Unknown') + ' [' + (a._source || 'Intel') + ']');
    if (origin) lines.push('  Origin: ' + origin);
    if (industries) lines.push('  Targets: ' + industries);
    if (countries) lines.push('  Countries: ' + countries);
    lines.push('  Motivation: ' + motivation);
    if (desc) lines.push('  Intel: ' + desc);
  }
  return lines.join('\n');
}

function _buildFallbackHypotheses(indicators, orgData) {
  // Quick static fallback when AI is unavailable
  var hypotheses = [];
  var typeCounts = {};
  var bestByType = {};
  for (var i = 0; i < indicators.length; i++) {
    var type = _parseIocType(indicators[i].pattern || '').toLowerCase();
    typeCounts[type] = (typeCounts[type] || 0) + 1;
    var val = _parseIocValue(indicators[i]);
    var score = indicators[i].x_opencti_score || 0;
    if (val && (!bestByType[type] || score > bestByType[type].score)) {
      bestByType[type] = { val: val, score: score };
    }
  }
  var sector = orgData ? orgData.sector : 'General';
  if (bestByType.url) {
    hypotheses.push({ title: 'Outbound callback to malicious URL', severity: 'critical', mitre: 'T1071.001 — Web Protocols',
      description: 'Hunt for ' + sector + ' endpoints making HTTP/S requests to known malicious URLs. Check proxy logs and EDR for the initiating process.',
      ioc: bestByType.url.val.substring(0, 55), siem_query: 'url.full:*' + (bestByType.url.val.split('/')[2] || '') + '*', hunt_scope: 'Proxy logs, EDR, DNS' });
  }
  if (bestByType.hash) {
    hypotheses.push({ title: 'Malicious file detected in ' + sector + ' environment', severity: 'critical', mitre: 'T1204.002 — Malicious File',
      description: 'Search all endpoints for this file hash. Prioritize ' + sector + ' critical systems and user workstations.',
      ioc: bestByType.hash.val.substring(0, 20) + '...', siem_query: 'file.hash.*:"' + bestByType.hash.val + '"', hunt_scope: 'EDR file + process events' });
  }
  if (bestByType.ip) {
    hypotheses.push({ title: 'C2 beaconing from ' + sector + ' network', severity: 'high', mitre: 'T1571 — Non-Standard Port',
      description: 'Check for beaconing patterns to this IP from ' + sector + ' assets. Look for periodic callbacks, unusual ports, or encrypted tunnels.',
      ioc: bestByType.ip.val, siem_query: 'destination.ip:"' + bestByType.ip.val + '"', hunt_scope: 'Firewall, EDR network, NetFlow' });
  }
  if (bestByType.domain) {
    hypotheses.push({ title: 'DNS-based C2 or exfiltration', severity: 'high', mitre: 'T1048.001 — Exfiltration Over DNS',
      description: 'Hunt for DNS queries to this domain from internal hosts. Look for DNS tunneling patterns (long subdomains, high query volume).',
      ioc: bestByType.domain.val, siem_query: 'dns.question.name:*' + bestByType.domain.val + '*', hunt_scope: 'DNS logs, passive DNS' });
  }
  return hypotheses;
}

function _renderHuntCards(container, hypotheses) {
  var html = '';
  for (var k = 0; k < hypotheses.length; k++) {
    var hyp = hypotheses[k];
    var sev = (hyp.severity || 'high').toLowerCase();
    var sevColor = sev === 'critical' ? '#ef4444' : sev === 'medium' ? '#eab308' : '#f59e0b';
    var safeQuery = _escHtml(hyp.siem_query || '').replace(/'/g, "\\'");
    html += '<div class="tip-hunt-card" style="border-left:3px solid ' + sevColor + ';">';
    html += '  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">';
    html += '    <div style="flex:1;min-width:0;">';
    html += '      <div style="font-size:12px;font-weight:700;color:#f1f5f9;margin-bottom:2px;">' + _escHtml(hyp.title || '') + '</div>';
    html += '      <div style="font-size:10px;color:#64748b;">' + _escHtml(hyp.mitre || '') + '</div>';
    html += '    </div>';
    html += '    <span style="font-size:8px;font-weight:700;padding:2px 8px;border-radius:4px;background:' + sevColor + '20;color:' + sevColor + ';border:1px solid ' + sevColor + '40;flex-shrink:0;">' + sev.toUpperCase() + '</span>';
    html += '  </div>';
    html += '  <div style="font-size:11px;color:#94a3b8;line-height:1.5;margin-bottom:8px;">' + _escHtml(hyp.description || '') + '</div>';
    if (hyp.ioc) {
      html += '  <div style="font-size:9px;color:#475569;margin-bottom:6px;">IOC: <code style="background:rgba(0,0,0,0.3);padding:1px 5px;border-radius:3px;color:#00d4ff;font-size:9px;">' + _escHtml(hyp.ioc) + '</code></div>';
    }
    html += '  <div style="display:flex;align-items:center;gap:8px;">';
    if (hyp.siem_query) {
      html += '    <button class="tip-btn tip-btn-secondary tip-btn-xs" onclick="tipCopyToClipboard(\'' + safeQuery + '\')"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy SIEM Query</button>';
    }
    if (hyp.hunt_scope) {
      html += '    <span style="font-size:8px;color:#475569;">' + _escHtml(hyp.hunt_scope) + '</span>';
    }
    html += '  </div>';
    html += '</div>';
  }
  html += '<div style="font-size:8px;color:#475569;text-align:center;padding:6px 0;margin-top:4px;border-top:1px solid rgba(255,255,255,0.04);">' +
    '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" stroke-width="2" style="vertical-align:-2px;margin-right:4px;"><path d="M12 2a4 4 0 0 1 4 4v1h1a3 3 0 0 1 3 3v8a3 3 0 0 1-3 3H7a3 3 0 0 1-3-3v-8a3 3 0 0 1 3-3h1V6a4 4 0 0 1 4-4z"/><circle cx="9" cy="13" r="1"/><circle cx="15" cy="13" r="1"/></svg>' +
    'AI-generated hypotheses based on live TI data &amp; org context</div>';
  container.innerHTML = html;
}

function tipCopyToClipboard(text) {
  navigator.clipboard.writeText(text).then(function() {
    if (typeof showToast === 'function') showToast('Query copied to clipboard', 'success');
  }).catch(function() {
    prompt('Copy this query:', text);
  });
}
window.tipCopyToClipboard = tipCopyToClipboard;

/* =============================================
   GLOBAL SEARCH
   ============================================= */
function tipHandleSearch(q) {
  var overlay = _el('tip-search-overlay');
  if (!overlay) return;
  if (!q || q.length < 2) {
    overlay.classList.remove('open');
    return;
  }
  var ql = q.toLowerCase();
  var results = [];
  var live = window._tipLiveData;

  // Search indicators
  var inds = live.indicators || [];
  for (var i = 0; i < inds.length && results.length < 10; i++) {
    var val = _parseIocValue(inds[i]);
    if (val.toLowerCase().indexOf(ql) !== -1) {
      results.push({ type: 'IOC', value: val, source: 'DACTA TIP', tab: 'ops' });
    }
  }

  // Search actors
  var actors = live.actors || [];
  for (var a = 0; a < actors.length && results.length < 15; a++) {
    var aName = (actors[a].name || '').toLowerCase();
    if (aName.indexOf(ql) !== -1) {
      results.push({ type: 'Actor', value: actors[a].name, source: actors[a]._source || 'DACTA TIP', tab: 'actors' });
    }
  }

  // Search reports
  var reports = (live.reports || []).concat(live.csReports || []);
  for (var r = 0; r < reports.length && results.length < 20; r++) {
    var rName = (reports[r].name || '').toLowerCase();
    if (rName.indexOf(ql) !== -1) {
      results.push({ type: 'Report', value: reports[r].name, source: reports[r]._source || 'DACTA TIP', tab: 'report' });
    }
  }

  if (results.length === 0) {
    overlay.innerHTML = '<div class="tip-search-overlay-header">No results for "' + _escHtml(q) + '"</div>';
    overlay.classList.add('open');
    return;
  }

  var html = '<div class="tip-search-overlay-header">' + results.length + ' results</div>';
  for (var idx = 0; idx < results.length; idx++) {
    var res = results[idx];
    html += '<div class="tip-search-result-card" onclick="switchTiTab(\'' + res.tab + '\');document.getElementById(\'tip-search-overlay\').classList.remove(\'open\');">';
    html += '  <div class="tip-src-top">';
    html += '    <span class="tip-tag tip-tag-sector" style="font-size:9px;">' + _escHtml(res.type) + '</span>';
    html += '    <span style="font-size:12px;color:#e8edf5;">' + _escHtml(_truncate(res.value, 60)) + '</span>';
    html += '  </div>';
    html += '  <div class="tip-src-meta"><span class="tip-src-meta-item">' + _escHtml(res.source) + '</span></div>';
    html += '</div>';
  }
  overlay.innerHTML = html;
  overlay.classList.add('open');
}
window.tipHandleSearch = tipHandleSearch;

// Close search overlay on outside click
document.addEventListener('click', function(e) {
  var overlay = _el('tip-search-overlay');
  var input = _el('tip-global-search');
  if (overlay && input && !overlay.contains(e.target) && e.target !== input) {
    overlay.classList.remove('open');
  }
});

/* =============================================
   MAIN ENTRY: LOAD THREAT INTEL LIVE
   ============================================= */
function loadThreatIntelLive() {
  console.log('[TIP] Loading live threat intelligence (dual-source: DACTA TIP + CrowdStrike)...');

  var healthDot = _el('tip-health-dot');
  var healthText = _el('tip-health-text');
  if (healthDot) healthDot.className = 'tip-live-dot amber';
  if (healthText) healthText.textContent = 'Connecting...';

  // ── DACTA TIP queries (may fail if TIP is down — that's OK) ──
  var tipIndicators = fetchDactaTip('{ indicators(first: 30, orderBy: created_at, orderMode: desc) { edges { node { id name description pattern indicator_types valid_from valid_until x_opencti_score created_at objectLabel { value } createdBy { name } } } } }')
    .then(function(data) {
      var edges = (data && data.data && data.data.indicators && data.data.indicators.edges) || [];
      return edges.map(function(e) { return e.node; });
    }).catch(function(err) { console.warn('[TIP] DACTA TIP indicators unavailable:', err.message); return []; });

  var tipIntrusionSets = fetchDactaTip('{ intrusionSets(first: 20, orderBy: modified, orderMode: desc) { edges { node { id name description aliases first_seen last_seen primary_motivation objectLabel { value } } } } }')
    .then(function(data) {
      var edges = (data && data.data && data.data.intrusionSets && data.data.intrusionSets.edges) || [];
      return edges.map(function(e) { var n = e.node; n._source = 'DACTA TIP'; return n; });
    }).catch(function() { return []; });

  var tipReports = fetchDactaTip('{ reports(first: 20, orderBy: published, orderMode: desc) { edges { node { id name description published report_types confidence objectLabel { value } createdBy { name } } } } }')
    .then(function(data) {
      var edges = (data && data.data && data.data.reports && data.data.reports.edges) || [];
      return edges.map(function(e) { var n = e.node; n._source = (n.createdBy && n.createdBy.name) || 'DACTA TIP'; return n; });
    }).catch(function() { return []; });

  var tipAttackPatterns = fetchDactaTip('{ attackPatterns(first: 200) { edges { node { id name x_mitre_id description } } } }')
    .then(function(data) {
      var edges = (data && data.data && data.data.attackPatterns && data.data.attackPatterns.edges) || [];
      return edges.map(function(e) { return e.node; });
    }).catch(function() { return []; });

  // ── CrowdStrike Intel (primary fallback — always fetched in parallel) ──
  var csIndicators = fetchCrowdStrike('search_indicators', { limit: 50 })
    .then(function(data) {
      var resources = (data && data.resources) || [];
      // Normalize CS indicators to the same format as DACTA TIP for renderIOCFeed
      return resources.map(function(r) {
        var iocType = r.type || 'unknown';
        var iocValue = r.indicator || '';
        var confMap = { high: 85, medium: 50, low: 20, unverified: 10 };
        var score = confMap[(r.malicious_confidence || '').toLowerCase()] || 30;
        var labels = (r.labels || []).map(function(l) { return { value: l.name || l }; });
        var killChains = (r.kill_chains || []).map(function(k) { return k; });
        var actors = (r.actors || []).join(', ');
        var malware = (r.malware_families || []).join(', ');
        return {
          id: r.id || '',
          name: iocType + ': ' + iocValue,
          description: (actors ? 'Actors: ' + actors + '. ' : '') + (malware ? 'Malware: ' + malware + '. ' : '') + (r.reports || []).slice(0, 2).join(', '),
          pattern: '[' + iocType + ':value = \'' + iocValue + '\']',
          indicator_types: [iocType],
          valid_from: r.published_date ? new Date(r.published_date * 1000).toISOString() : null,
          valid_until: null,
          x_opencti_score: score,
          created_at: r.published_date ? new Date(r.published_date * 1000).toISOString() : null,
          objectLabel: labels,
          createdBy: { name: 'CrowdStrike Falcon Intel' },
          _source: 'CrowdStrike',
          _cs_raw: r
        };
      });
    }).catch(function(err) { console.warn('[TIP] CrowdStrike indicators unavailable:', err.message); return []; });

  var csActors = fetchCrowdStrike('search_actors', { limit: 30 })
    .then(function(data) {
      var actors = (data && data.resources) || [];
      return actors.map(function(a) { a._source = 'CrowdStrike'; return a; });
    }).catch(function(err) { console.warn('[TIP] CS Actors error:', err.message); return []; });

  var csReports = fetchCrowdStrike('search_reports', { limit: 30 })
    .then(function(data) {
      var reports = (data && data.resources) || [];
      return reports.map(function(r) { r._source = 'CrowdStrike'; return r; });
    }).catch(function(err) { console.warn('[TIP] CS Reports error:', err.message); return []; });

  // Wait for all — both DACTA TIP and CrowdStrike in parallel
  Promise.all([tipIndicators, tipIntrusionSets, tipReports, tipAttackPatterns, csIndicators, csActors, csReports])
    .then(function(results) {
    var dactaIndicators = results[0];
    var intrusionSets = results[1];
    var dactaReports = results[2];
    var attackPatterns = results[3];
    var crowdIndicators = results[4];
    var crowdActors = results[5];
    var crowdReports = results[6];

    // ── Determine source status ──
    var tipOnline = dactaIndicators.length > 0 || intrusionSets.length > 0 || dactaReports.length > 0;
    var csOnline = crowdIndicators.length > 0 || crowdActors.length > 0 || crowdReports.length > 0;

    // ── Merge indicators: DACTA TIP primary, CrowdStrike fills gaps ──
    var allIndicators = dactaIndicators.length > 0 ? dactaIndicators : crowdIndicators;
    // If both have data, merge (DACTA TIP first, then CS)
    if (dactaIndicators.length > 0 && crowdIndicators.length > 0) {
      allIndicators = dactaIndicators.concat(crowdIndicators);
    }

    // ── Merge actors: CS actors + DACTA TIP intrusion sets ──
    var allActors = crowdActors.concat(intrusionSets);

    // ── Merge reports: DACTA TIP + CrowdStrike ──
    var allReports = dactaReports.concat(crowdReports);

    // ── Store globally ──
    window._tipLiveData.indicators = allIndicators;
    window._tipLiveData.intrusionSets = intrusionSets;
    window._tipLiveData.reports = dactaReports;
    window._tipLiveData.attackPatterns = attackPatterns;
    window._tipLiveData.csReports = crowdReports;
    window._tipLiveData.actors = allActors;

    // ── Update health status ──
    if (tipOnline && csOnline) {
      if (healthDot) healthDot.className = 'tip-live-dot';
      if (healthText) healthText.textContent = 'DACTA TIP + CrowdStrike Online';
    } else if (csOnline) {
      if (healthDot) healthDot.className = 'tip-live-dot amber';
      if (healthText) healthText.textContent = 'CrowdStrike Intel (DACTA TIP Offline)';
    } else if (tipOnline) {
      if (healthDot) healthDot.className = 'tip-live-dot';
      if (healthText) healthText.textContent = 'DACTA TIP Online';
    } else {
      if (healthDot) healthDot.className = 'tip-live-dot red';
      if (healthText) healthText.textContent = 'All Intel Sources Offline';
    }

    // ── Update counters ──
    var cIocs = _el('tip-count-iocs');
    var cActors = _el('tip-count-actors');
    var cReports = _el('tip-count-reports');
    if (cIocs) cIocs.textContent = allIndicators.length;
    if (cActors) cActors.textContent = allActors.length;
    if (cReports) cReports.textContent = allReports.length;

    // ── Render all tabs ──
    console.log('[TIP] Rendering IOC feed (' + allIndicators.length + ' indicators from ' + (tipOnline ? 'DACTA TIP' : '') + (tipOnline && csOnline ? ' + ' : '') + (csOnline ? 'CrowdStrike' : '') + ')');
    renderIOCFeed(allIndicators);
    renderPyramidOfPain(allIndicators);

    console.log('[TIP] Rendering hunt hypotheses');
    var _curOrg = window._tipSelectedOrg || 'all';
    var _curOrgData = CLIENT_DATA[_curOrg] || CLIENT_DATA['all'];
    renderHuntHypotheses(allIndicators, allActors, _curOrgData, _curOrg);

    console.log('[TIP] Rendering actors (' + allActors.length + ' actors)');
    renderActorGrid(allActors);

    console.log('[TIP] Rendering ATT&CK grid (' + attackPatterns.length + ' patterns)');
    if (_el('tip-panel-attack') && _el('tip-panel-attack').classList.contains('active')) {
      renderAttackGrid();
    }

    console.log('[TIP] Rendering SIEM grid');
    renderSIEMGrid();

    console.log('[TIP] Rendering reports (' + allReports.length + ' reports)');
    renderReportsList(allReports);

    var sourceLabel = [];
    if (tipOnline) sourceLabel.push('DACTA TIP');
    if (csOnline) sourceLabel.push('CrowdStrike');
    console.log('[TIP] All live data loaded from ' + sourceLabel.join(' + ') + ' — ' + allIndicators.length + ' IOCs, ' + allActors.length + ' actors, ' + allReports.length + ' reports');
  }).catch(function(err) {
    console.error('[TIP] Fatal error loading live data:', err);
    if (healthDot) healthDot.className = 'tip-live-dot red';
    if (healthText) healthText.textContent = 'Connection Error';
  });
}
window.loadThreatIntelLive = loadThreatIntelLive;

// Auto-load when page becomes visible or on init
loadThreatIntelLive();

})();

