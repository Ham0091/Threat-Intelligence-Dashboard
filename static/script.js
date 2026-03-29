// THREAT INTELLIGENCE DASHBOARD

const queryInput = document.getElementById('query-input');
const lookupForm = document.getElementById('lookup-form');
const resultsGrid = document.getElementById('results-grid');
const searchStatus = document.getElementById('search-status');
const defangBtn = document.getElementById('defang-btn');
const clearBtn = document.getElementById('clear-btn');
const exportBtn = document.getElementById('export-btn');
const timeDisplay = document.getElementById('time-display');
const analyzeBtn = lookupForm ? lookupForm.querySelector('button[type="submit"]') : null;

let results_cache = {};
let health_status = {};
let scan_start_time = null;
let is_loading = false;
let toast_timer = null;

// ===== PER-SOURCE STATUS HELPERS =====
const SOURCE_TO_HEALTH_KEY = {
    'vt': 'virustotal', 'abuse': 'abuseipdb', 'greynoise': 'greynoise',
    'crowdsec': 'crowdsec', 'urlhaus': 'urlhaus', 'whois': 'whois',
    'dns': 'dns', 'ssl': 'ssl', 'crtsh': 'crtsh',
    'ipinfo': 'ipinfo', 'secheaders': 'secheaders'
};

const CARD_DEFS = [
    ['virustotal', 'VirusTotal',       'shield',        'vt'],
    ['abuseipdb',  'AbuseIPDB',        'skull',         'abuse'],
    ['greynoise',  'GreyNoise',        'radar',         'greynoise'],
    ['crowdsec',   'CrowdSec CTI',     'shield-alert',  'crowdsec'],
    ['urlhaus',    'URLhaus',          'link',          'urlhaus'],
    ['whois',      'WHOIS Registry',   'file-search',   'whois'],
    ['dns',        'DNS Records',      'server',        'dns'],
    ['ssl',        'SSL Certificate',  'lock',          'ssl'],
    ['crtsh',      'Subdomain Enum',   'git-branch',    'crtsh'],
    ['ipinfo',     'IP Intelligence',  'map-pin',       'ipinfo'],
    ['secheaders', 'Security Headers', 'shield-check',  'secheaders'],
];

function get_health_dot(source) {
    const key = SOURCE_TO_HEALTH_KEY[source];
    const h = health_status[key];
    if (!h) return '';
    const colors = { up: '#06b6d4', slow: '#eab308', down: '#ef4444', unconfigured: '#555' };
    const color = colors[h.status] || '#555';
    const tip = h.status === 'unconfigured' ? 'API key not configured'
        : h.status + (h.duration_ms ? ' (' + h.duration_ms + 'ms)' : '');
    return '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:' + color + ';margin-left:6px;vertical-align:middle;flex-shrink:0;" title="' + tip + '"></span>';
}

function get_duration_text(data) {
    if (!data || data.duration_ms == null) return '';
    var s = (data.duration_ms / 1000).toFixed(1);
    return '<span style="font-size:0.75em;color:#888;margin-left:auto;padding-left:6px;white-space:nowrap;">' + s + 's</span>';
}

async function load_health_status() {
    try {
        var resp = await fetch('/api/health-check');
        if (resp.ok) health_status = await resp.json();
    } catch (e) {
        console.warn('Health check failed:', e);
    }
}

function threat_color(score) {
    if (score >= 91) return '#ef4444';
    if (score >= 76) return '#f97316';
    if (score >= 51) return '#eab308';
    if (score >= 26) return '#22c55e';
    return '#06b6d4';
}

function threat_label(score) {
    if (score >= 91) return 'Critical';
    if (score >= 76) return 'High';
    if (score >= 51) return 'Medium';
    if (score >= 26) return 'Low';
    return 'Clean';
}

// ===== TIME DISPLAY =====
function update_time() {
    if (!timeDisplay) return;
    var now = new Date();
    timeDisplay.textContent = now.toLocaleTimeString('en-US', {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: true
    });
}
setInterval(update_time, 1000);
update_time();

// ===== KEYBOARD SHORTCUT: Ctrl+K focuses search =====
document.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        if (queryInput) queryInput.focus();
    }
});

// ===== LOOKUP =====
if (lookupForm) {
    lookupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        var query = queryInput.value.trim();
        if (!query) {
            show_status('Please enter an IP, domain, or URL', 'error');
            return;
        }
        await perform_lookup(query);
    });
}

// ===== LOADING STATE =====
function set_loading(loading) {
    is_loading = loading;
    if (analyzeBtn) {
        analyzeBtn.disabled = loading;
        analyzeBtn.textContent = loading ? 'Analyzing...' : 'Analyze';
    }
    if (loading) {
        show_skeleton_cards();
    }
}

function show_skeleton_cards() {
    resultsGrid.innerHTML = '';
    for (var i = 0; i < CARD_DEFS.length; i++) {
        var def = CARD_DEFS[i];
        var card = document.createElement('div');
        card.className = 'result-card skeleton-card';
        card.setAttribute('data-source', def[3]);
        card.innerHTML =
            '<div class="result-header skeleton-shimmer" style="height:48px;"></div>' +
            '<div class="result-body">' +
            '<div class="skeleton-line skeleton-shimmer" style="width:70%;"></div>' +
            '<div class="skeleton-line skeleton-shimmer" style="width:50%;"></div>' +
            '<div class="skeleton-line skeleton-shimmer" style="width:85%;"></div>' +
            '</div>';
        resultsGrid.appendChild(card);
    }
}

// ===== PERFORM LOOKUP =====
async function perform_lookup(query) {
    if (is_loading) return;
    scan_start_time = Date.now();
    show_status('Analyzing threat intelligence...', 'loading');
    show_results_sections(false);
    set_loading(true);

    var all_results = {};
    var timeout_handle;

    function finish_loading() {
        clearTimeout(timeout_handle);
        if (is_loading) set_loading(false);
    }

    timeout_handle = setTimeout(function() {
        show_toast('Lookup timed out', 'error');
        show_status('', '');
        finish_loading();
    }, 30000);

    try {
        var response = await fetch('/api/lookup/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: query })
        });

        if (!response.ok) {
            var ct = response.headers.get('content-type') || '';
            var err = 'Lookup failed';
            if (ct.includes('application/json')) {
                var errData = await response.json();
                err = errData.error || err;
            }
            show_toast(err, 'error');
            show_status('', '');
            finish_loading();
            return;
        }

        var reader = response.body.getReader();
        var decoder = new TextDecoder();
        var buffer = '';
        var pending_event = '';

        while (true) {
            var chunk = await reader.read();
            if (chunk.done) break;
            buffer += decoder.decode(chunk.value, { stream: true });
            var lines = buffer.split('\n');
            buffer = lines.pop();
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i];
                if (line.startsWith('event:')) {
                    pending_event = line.slice(6).trim();
                } else if (line.startsWith('data:')) {
                    var raw = line.slice(5).trim();
                    try {
                        var parsed = JSON.parse(raw);
                        if (pending_event === '__complete__') {
                            var elapsed = ((Date.now() - scan_start_time) / 1000).toFixed(1);
                            var valid_count = Object.values(all_results).filter(function(r) { return r && r.valid; }).length;
                            results_cache = { results: all_results, query: parsed.query, query_type: parsed.query_type, threat_score: parsed.threat_score };
                            update_summary(parsed, all_results, elapsed);
                            show_toast('Analysis complete -- ' + valid_count + ' sources responded', 'success');
                            show_status('', '');
                            finish_loading();
                        } else {
                            var src = parsed.source;
                            var src_data = parsed.data;
                            if (src && src_data !== undefined) {
                                all_results[src] = src_data;
                                resolve_card(src, src_data);
                            }
                        }
                    } catch (e) {
                        console.warn('Failed to parse SSE data:', raw, e);
                    }
                    pending_event = '';
                } else if (line.trim() === '') {
                    pending_event = '';
                }
            }
        }

    } catch (error) {
        show_toast('Error: ' + error.message, 'error');
        show_status('', '');
    } finally {
        finish_loading();
    }
}

function show_results_sections(visible) {
    ['summary-bar', 'gauge-section'].forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.classList.toggle('hidden', !visible);
    });
    var searchSection = document.querySelector('.search-section');
    if (searchSection) searchSection.classList.toggle('search-section--sticky', visible);
    if (!visible) {
        resultsGrid.innerHTML = '';
    }
}

// ===== RENDER RESULTS =====
function render_results(data, elapsed) {
    var results = data.results || {};
    var threat_score = data.threat_score || 0;

    var level_color = threat_color(threat_score);
    var threat_level = threat_label(threat_score);
    var valid_count = Object.values(results).filter(function(r) { return r && r.valid; }).length;
    var total_count = Object.keys(results).length;

    // Summary bar
    var sumTarget = document.getElementById('sum-target');
    if (sumTarget) sumTarget.textContent = data.query || '--';
    var sumScore = document.getElementById('sum-score');
    if (sumScore) sumScore.textContent = Math.round(threat_score) + '/100';
    var sumLevel = document.getElementById('sum-level');
    if (sumLevel) {
        sumLevel.textContent = threat_level;
        sumLevel.style.color = level_color;
    }
    var sumSources = document.getElementById('sum-sources');
    if (sumSources) sumSources.textContent = valid_count + ' / ' + total_count;
    var sumTime = document.getElementById('sum-time');
    if (sumTime) sumTime.textContent = (elapsed || '?') + 's';

    var summaryBar = document.getElementById('summary-bar');
    if (summaryBar) summaryBar.style.borderLeftColor = level_color;
    show_results_sections(true);

    // Gauge
    var gaugeFill = document.getElementById('gauge-fill');
    if (gaugeFill) {
        gaugeFill.style.width = '0%';
        gaugeFill.style.background = level_color;
        requestAnimationFrame(function() {
            requestAnimationFrame(function() {
                gaugeFill.style.width = Math.min(100, Math.round(threat_score)) + '%';
            });
        });
    }

    // Cards
    resultsGrid.innerHTML = '';
    for (var i = 0; i < CARD_DEFS.length; i++) {
        var def = CARD_DEFS[i];
        var key = def[0], title = def[1], icon = def[2], source = def[3];
        if (key in results) {
            resultsGrid.appendChild(create_result_card(title, icon, results[key], source));
        }
    }
}

// ===== SSE HELPERS =====
function resolve_card(source, data) {
    var def = null;
    for (var i = 0; i < CARD_DEFS.length; i++) {
        if (CARD_DEFS[i][0] === source) { def = CARD_DEFS[i]; break; }
    }
    if (!def) return;
    var source_key = def[3];
    var cardEl = resultsGrid.querySelector('[data-source="' + source_key + '"]');
    if (!cardEl) return;
    var realCard = create_result_card(def[1], def[2], data, source_key);
    realCard.classList.add('card-resolved');
    cardEl.replaceWith(realCard);
}

function update_summary(complete_data, all_results, elapsed) {
    var threat_score = complete_data.threat_score || 0;
    var level_color = threat_color(threat_score);
    var threat_level = threat_label(threat_score);
    var valid_count = Object.values(all_results).filter(function(r) { return r && r.valid; }).length;
    var total_count = Object.keys(all_results).length;
    var sumTarget = document.getElementById('sum-target');
    if (sumTarget) sumTarget.textContent = complete_data.query || '--';
    var sumScore = document.getElementById('sum-score');
    if (sumScore) sumScore.textContent = Math.round(threat_score) + '/100';
    var sumLevel = document.getElementById('sum-level');
    if (sumLevel) { sumLevel.textContent = threat_level; sumLevel.style.color = level_color; }
    var sumSources = document.getElementById('sum-sources');
    if (sumSources) sumSources.textContent = valid_count + ' / ' + total_count;
    var sumTime = document.getElementById('sum-time');
    if (sumTime) sumTime.textContent = (elapsed || '?') + 's';
    var summaryBar = document.getElementById('summary-bar');
    if (summaryBar) summaryBar.style.borderLeftColor = level_color;
    show_results_sections(true);
    var skeletons = resultsGrid.querySelectorAll('.skeleton-card');
    skeletons.forEach(function(s) { s.remove(); });
    var gaugeFill = document.getElementById('gauge-fill');
    if (gaugeFill) {
        gaugeFill.style.width = '0%';
        gaugeFill.style.background = level_color;
        requestAnimationFrame(function() {
            requestAnimationFrame(function() {
                gaugeFill.style.width = Math.min(100, Math.round(threat_score)) + '%';
            });
        });
    }
}

// ===== ICON MAP =====
var ICON_MAP = {
    'shield':        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
    'skull':         '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="9" r="1"></circle><circle cx="15" cy="9" r="1"></circle><path d="M8 20h8a2 2 0 0 0 2-2v-2H6v2a2 2 0 0 0 2 2z"></path><path d="M7 12a5 5 0 0 0 10 0"></path><path d="M5 8a7 7 0 0 1 14 0"></path></svg>',
    'radar':         '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 12 2 2"></path><path d="M12 2a10 10 0 1 0 10 10"></path><path d="M12 7a5 5 0 1 0 5 5"></path><circle cx="12" cy="12" r="2"></circle></svg>',
    'shield-alert':  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M12 8v4"></path><path d="M12 16h.01"></path></svg>',
    'link':          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>',
    'file-search':   '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="14" r="5"></circle><path d="M14.12 14l3.07 3.07"></path><path d="M15 3h-6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z"></path><line x1="9" y1="8" x2="15" y2="8"></line><line x1="9" y1="11" x2="15" y2="11"></line></svg>',
    'server':        '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8"></rect><rect x="2" y="14" width="20" height="8"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>',
    'lock':          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>',
    'git-branch':    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="6" y1="3" x2="6" y2="15"></line><circle cx="18" cy="6" r="3"></circle><circle cx="6" cy="18" r="3"></circle><path d="M18 9a9 9 0 0 1-9 9"></path></svg>',
    'map-pin':       '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle></svg>',
    'shield-check':  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><path d="M9 12l2 2 4-4"></path></svg>'
};

// ===== CARD BUILDER =====
function create_result_card(title, icon_name, data, source) {
    var card = document.createElement('div');
    card.className = 'result-card';

    var icon_html = ICON_MAP[icon_name] || ICON_MAP['shield'];

    function header(extra) {
        return '<div class="result-header" style="display:flex;align-items:center;">' +
            '<div class="icon">' + icon_html + '</div>' +
            '<h3>' + title.toUpperCase() + '</h3>' +
            get_health_dot(source) + (extra || '') +
            '</div>';
    }

    if (!data || !data.valid) {
        var errMsg = (data && data.error) ? data.error : 'No data available';
        card.innerHTML = header('') +
            '<div class="result-body"><p class="empty-state">' + errMsg + '</p></div>';
        return card;
    }

    var content_html = '';
    var field_count = 0;

    if (source === 'vt') {
        content_html = ri('Malicious Detections', data.malicious_detections || 0) +
            ri('Suspicious Detections', data.suspicious_detections || 0) +
            ri('Reputation Score', data.reputation_score != null ? data.reputation_score : 'N/A');
        field_count = 3;
    } else if (source === 'abuse') {
        content_html = ri('Abuse Confidence', (data.abuse_confidence_score || 0) + '%') +
            ri('Total Reports', data.total_reports || 0) +
            ri('Country', data.country || 'Unknown');
        field_count = 3;
    } else if (source === 'greynoise') {
        var cls = data.classification || 'unknown';
        var clsColors = { 'malicious': '#ef4444', 'benign': '#10b981', 'unknown': '#888' };
        var clsColor = clsColors[cls] || '#888';
        content_html = '<div class="result-item"><div class="result-label">Classification</div>' +
            '<div class="result-value" style="color:' + clsColor + ';font-weight:bold;">' + cls.toUpperCase() + '</div></div>' +
            ri('Mass Scanner (Noise)', data.noise ? 'Yes' : 'No') +
            ri('Known Good (RIOT)', data.riot ? 'Yes' : 'No') +
            ri('Name', data.name || 'N/A') +
            ri('Last Seen', data.last_seen || 'N/A');
        field_count = 5;
    } else if (source === 'crowdsec') {
        var behaviors = data.behaviors || [];
        var bhv_html = behaviors.length > 0
            ? behaviors.slice(0, 5).map(function(b) { return '<div class="card-list-item">' + b + '</div>'; }).join('')
                + (behaviors.length > 5 ? '<span class="card-list-more">and ' + (behaviors.length - 5) + ' more</span>' : '')
            : '<span class="card-list-none">None detected</span>';
        var scoreVal = data.overall_score != null ? data.overall_score + '/5' : 'N/A';
        content_html = ri('Overall Score', scoreVal) +
            ri('Malicious', data.is_bad ? 'Yes' : 'No') +
            ri('Reputation', data.reputation || 'N/A') +
            ri('Last Seen', data.last_seen || 'N/A') +
            '<div class="result-item"><div class="result-label">Attack Behaviors</div>' +
            '<div class="card-plain-list">' + bhv_html + '</div></div>';
        field_count = 4 + behaviors.length;
    } else if (source === 'urlhaus') {
        content_html = ri('Threat Score', (data.threat_score || 0) + '%') +
            ri('Threat', data.threat || 'None') +
            ri('Status', data.status || 'Unknown');
        field_count = 3;
    } else if (source === 'whois') {
        content_html = ri('Registrar', data.registrar || 'Unknown') +
            ri('Created', data.creation_date || 'N/A') +
            ri('Expires', data.expiration_date || 'N/A') +
            ri('Country', data.registrant_country || 'Unknown') +
            ri('Name Servers', (data.name_servers && data.name_servers.length > 0) ? data.name_servers.join(', ') : 'None');
        field_count = 5;
    } else if (source === 'dns') {
        var r = data.records || {};
        content_html = ri('A (IPv4)', (r.A && r.A.length > 0) ? r.A.join(', ') : 'None') +
            ri('AAAA (IPv6)', (r.AAAA && r.AAAA.length > 0) ? r.AAAA.join(', ') : 'None') +
            ri('MX (Mail)', (r.MX && r.MX.length > 0) ? r.MX.slice(0, 3).join(', ') : 'None') +
            ri('NS', (r.NS && r.NS.length > 0) ? r.NS.slice(0, 2).join(', ') : 'None');
        field_count = 4;
    } else if (source === 'ssl') {
        var cert = data.certificate || {};
        var subj = cert.subject || {};
        var iss = cert.issuer || {};
        content_html = ri('Subject CN', subj.CN || 'N/A') +
            ri('Issuer', iss.O || 'Unknown') +
            ri('Valid From', cert.not_before || 'N/A') +
            ri('Valid Until', cert.not_after || 'N/A');
        field_count = 4;
    } else if (source === 'crtsh') {
        var subs = data.subdomains || [];
        var shown_subs = subs.slice(0, 5);
        var extra_subs = subs.length > 5 ? subs.length - 5 : 0;
        var subs_html = shown_subs.length > 0
            ? shown_subs.map(function(s) { return '<div class="card-list-item">' + s + '</div>'; }).join('')
                + (extra_subs > 0 ? '<span class="card-list-more">and ' + extra_subs + ' more</span>' : '')
            : '<span class="card-list-none">None</span>';
        content_html = ri('Total Found', data.total_found || 0) +
            '<div class="result-item"><div class="result-label">Subdomains</div>' +
            '<div class="card-plain-list">' + subs_html + '</div></div>';
        field_count = 1 + subs.length;
    } else if (source === 'ipinfo') {
        if (!data.found) {
            content_html = ri('Status', 'Not Found');
            field_count = 1;
        } else {
            content_html = ri('Country', data.country || 'N/A') +
                ri('City', data.city || 'N/A') +
                ri('Org / ASN', data.org || 'N/A') +
                ri('Hostname', data.hostname || 'N/A');
            field_count = 4;
            if (data.vpn != null || data.proxy != null || data.hosting != null) {
                var flags = (data.vpn ? 'VPN ' : '') + (data.proxy ? 'Proxy ' : '') + (data.hosting ? 'Hosting' : '');
                content_html += ri('VPN / Proxy / Hosting', flags.trim() || 'No');
                field_count = 5;
            }
        }
    } else if (source === 'secheaders') {
        var present = data.present_headers || [];
        var missing = data.missing_headers || [];
        var grade = data.grade || 'F';
        var gradeColors = { A: '#10b981', B: '#84cc16', C: '#f59e0b', D: '#f97316' };
        var gradeColor = gradeColors[grade] || '#ef4444';
        content_html = '<div class="result-item"><div class="result-label">Grade</div>' +
            '<div class="result-value" style="font-size:1.2em;font-weight:bold;color:' + gradeColor + ';">' + grade + '</div></div>' +
            ri('Present', present.length + '/6') +
            '<div class="result-item" style="grid-column:1/-1;"><div class="result-label">Headers</div>' +
            '<div class="result-value" style="font-size:0.85em;">' +
            '<strong style="color:#10b981;">Present:</strong> ' + (present.join(', ') || 'None') + '<br>' +
            '<strong style="color:#ef4444;">Missing:</strong> ' + (missing.join(', ') || 'None') +
            '</div></div>';
        field_count = present.length + missing.length;
    }

    card.innerHTML = header(get_duration_text(data)) + '<div class="result-body">' + content_html + '</div>';

    // Attach expand/collapse footer after DOM insertion
    // Use requestAnimationFrame so the browser has measured the content height
    var field_count_final = field_count;
    requestAnimationFrame(function() {
        var body = card.querySelector('.result-body');
        if (!body) return;
        if (body.scrollHeight > body.clientHeight + 2) {
            var footer = document.createElement('div');
            footer.className = 'card-footer';
            footer.innerHTML =
                '<span class="card-footer-left">' +
                '<svg class="card-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#3f3f46" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>' +
                '<span class="card-footer-label">Show more</span>' +
                '</span>' +
                '<span class="card-footer-count">' + field_count_final + ' fields</span>';
            footer.addEventListener('click', function() {
                var expanded = card.classList.toggle('result-card--expanded');
                var chevron = footer.querySelector('.card-chevron');
                var label = footer.querySelector('.card-footer-label');
                chevron.style.transform = expanded ? 'rotate(180deg)' : 'rotate(0deg)';
                label.textContent = expanded ? 'Show less' : 'Show more';
            });
            card.appendChild(footer);
        }
    });

    return card;
}

// Result item shorthand
function ri(label, value) {
    return '<div class="result-item"><div class="result-label">' + label + '</div><div class="result-value">' + value + '</div></div>';
}

// ===== STATUS =====
function show_status(message, type) {
    if (!searchStatus) return;
    searchStatus.textContent = message;
    searchStatus.className = 'status-message' + (type ? ' ' + type : '');
}

function show_toast(message, type) {
    var toast = document.getElementById('toast');
    if (!toast) return;
    clearTimeout(toast_timer);
    toast.textContent = message;
    toast.className = 'toast toast--' + (type || 'success');
    toast.style.transition = 'opacity 0ms';
    toast.style.opacity = '1';
    toast_timer = setTimeout(function() {
        toast.style.transition = 'opacity 400ms ease';
        toast.style.opacity = '0';
    }, 3000);
}

// ===== DEFANG =====
if (defangBtn) {
    defangBtn.addEventListener('click', function() {
        var q = queryInput.value.trim();
        if (!q) { show_status('Enter text first', 'error'); return; }
        queryInput.value = q
            .replace(/\./g, '[.]')
            .replace(/:/g, '[:]')
            .replace(/http/gi, 'hxxp');
        show_status('Defanged', 'success');
    });
}

// ===== CLEAR =====
if (clearBtn) {
    clearBtn.addEventListener('click', function() {
        queryInput.value = '';
        resultsGrid.innerHTML = '';
        show_results_sections(false);
        show_status('', '');
        queryInput.focus();
    });
}

// ===== EXPORT =====
if (exportBtn) {
    exportBtn.addEventListener('click', async function() {
        if (!results_cache || !results_cache.query) {
            show_status('No results to export. Run a lookup first.', 'error');
            return;
        }
        try {
            var response = await fetch('/api/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: results_cache })
            });
            if (response.ok) {
                var data = await response.json();
                var blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                a.click();
                URL.revokeObjectURL(url);
                show_status('Exported successfully', 'success');
            } else {
                show_status('Export failed', 'error');
            }
        } catch (e) {
            show_status('Export error: ' + e.message, 'error');
        }
    });
}

// ===== INITIALIZE =====
load_health_status();
setInterval(load_health_status, 60000);
