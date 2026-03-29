// THREAT INTELLIGENCE DASHBOARD - PROFESSIONAL UI

const queryInput = document.getElementById('query-input');
const lookupForm = document.getElementById('lookup-form');
const resultsGrid = document.getElementById('results-grid');
const searchStatus = document.getElementById('search-status');
const threatWidget = document.getElementById('threat-widget');
const defangBtn = document.getElementById('defang-btn');
const clearBtn = document.getElementById('clear-btn');
const timeDisplay = document.getElementById('time-display');
const historySearch = document.getElementById('history-search');
const historyClear = document.getElementById('history-clear');

let results_cache = {};
let full_history = [];

// ===== TIME DISPLAY =====
function update_time() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: true 
    });
    const dateString = now.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric'
    });
    timeDisplay.textContent = `${dateString} — ${timeString}`;
}
setInterval(update_time, 1000);
update_time();

// ===== LOOKUP FUNCTIONALITY =====
lookupForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = queryInput.value.trim();
    
    if (!query) {
        show_status('Please enter an IP, domain, or URL', 'error');
        return;
    }
    
    await perform_lookup(query);
});

async function perform_lookup(query) {
    show_status('Analyzing threat intelligence...', 'loading');
    show_loading(true);
    threatWidget.classList.add('hidden');
    resultsGrid.innerHTML = '';
    
    try {
        const response = await fetch('/api/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        
        if (!response.ok) {
            const error = await response.json();
            show_status(error.error || 'Lookup failed', 'error');
            return;
        }
        
        const data = await response.json();
        results_cache = data;
        
        render_results(data);
        show_status('Analysis complete', 'success');
        load_dashboard_stats();
        
    } catch (error) {
        show_status('Error: ' + error.message, 'error');
    } finally {
        show_loading(false);
    }
}

function render_results(data) {
    const results = data.results || {};
    const threat_score = data.threat_score || 0;
    
    // Show threat widget
    threatWidget.classList.remove('hidden');
    document.getElementById('threat-score-value').textContent = Math.round(threat_score);
    
    const threat_level = threat_score >= 70 ? 'Critical' : threat_score >= 50 ? 'High' : threat_score >= 25 ? 'Medium' : 'Low';
    const threat_class = threat_score >= 70 ? 'critical' : threat_score >= 50 ? 'high' : threat_score >= 25 ? 'medium' : 'low';
    
    const threat_indicator = document.querySelector('.threat-level-indicator');
    threat_indicator.innerHTML = `
        <div>
            <span class="threat-badge ${threat_class}">${threat_level} Risk</span>
        </div>
    `;
    
    // Render result cards - Threat Intel Sources
    resultsGrid.innerHTML = '';
    
    // Threat Intelligence APIs
    if (results.virustotal) {
        resultsGrid.appendChild(create_result_card('VirusTotal', 'shield', results.virustotal, 'vt'));
    }
    if (results.abuseipdb) {
        resultsGrid.appendChild(create_result_card('AbuseIPDB', 'skull', results.abuseipdb, 'abuse'));
    }
    if (results.shodan) {
        resultsGrid.appendChild(create_result_card('Shodan', 'globe-2', results.shodan, 'shodan'));
    }
    if (results.otx) {
        resultsGrid.appendChild(create_result_card('AlienVault OTX', 'activity', results.otx, 'otx'));
    }
    if (results.urlhaus) {
        resultsGrid.appendChild(create_result_card('URLhaus', 'link', results.urlhaus, 'urlhaus'));
    }
    
    // Phase 1 APIs - Domain Intelligence
    if (results.whois) {
        resultsGrid.appendChild(create_result_card('WHOIS Registry', 'file-search', results.whois, 'whois'));
    }
    if (results.dns) {
        resultsGrid.appendChild(create_result_card('DNS Records', 'server', results.dns, 'dns'));
    }
    if (results.ssl) {
        resultsGrid.appendChild(create_result_card('SSL Certificate', 'lock', results.ssl, 'ssl'));
    }
}

function create_result_card(title, icon_name, data, source) {
    const card = document.createElement('div');
    card.className = 'result-card';
    
    // Icon SVG map - embedded for reliability
    const iconMap = {
        'shield': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
        'skull': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="9" r="1"></circle><circle cx="15" cy="9" r="1"></circle><path d="M8 20h8a2 2 0 0 0 2-2v-2H6v2a2 2 0 0 0 2 2z"></path><path d="M7 12a5 5 0 0 0 10 0"></path><path d="M5 8a7 7 0 0 1 14 0"></path></svg>',
        'globe-2': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><path d="M12 2a14.5 14.5 0 0 1 0 20"></path><path d="M2 12h20"></path></svg>',
        'activity': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>',
        'link': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>',
        'file-search': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="14" r="5"></circle><path d="M14.12 14l3.07 3.07"></path><path d="M15 3h-6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2z"></path><line x1="9" y1="8" x2="15" y2="8"></line><line x1="9" y1="11" x2="15" y2="11"></line></svg>',
        'server': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8"></rect><rect x="2" y="14" width="20" height="8"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>',
        'lock': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>'
    };
    
    const icon_html = iconMap[icon_name] || iconMap['shield'];
    
    if (!data || !data.valid) {
        card.innerHTML = `
            <div class="result-header">
                <div class="icon">${icon_html}</div>
                <h3>${title.toUpperCase()}</h3>
            </div>
            <div class="result-body">
                <p class="empty-state">No data or error: ${data?.error || 'Unknown error'}</p>
            </div>
        `;
        return card;
    }
    
    let content_html = '';
    
    if (source === 'vt') {
        content_html = `
            <div class="result-item">
                <div class="result-label">Malicious Detections</div>
                <div class="result-value">${data.malicious_detections || 0}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Suspicious Detections</div>
                <div class="result-value">${data.suspicious_detections || 0}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Reputation Score</div>
                <div class="result-value">${data.reputation_score || 'N/A'}</div>
            </div>
        `;
    } else if (source === 'abuse') {
        content_html = `
            <div class="result-item">
                <div class="result-label">Abuse Confidence Score</div>
                <div class="result-value">${data.abuse_confidence_score || 0}%</div>
            </div>
            <div class="result-item">
                <div class="result-label">Total Reports</div>
                <div class="result-value">${data.total_reports || 0}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Country</div>
                <div class="result-value">${data.country || 'Unknown'}</div>
            </div>
        `;
    } else if (source === 'shodan') {
        const ports = data.open_ports || [];
        content_html = `
            <div class="result-item">
                <div class="result-label">Open Ports (${ports.length})</div>
                <div class="result-value">${ports.length > 0 ? ports.join(', ') : 'None'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Organization</div>
                <div class="result-value">${data.organization || 'Unknown'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Hostnames</div>
                <div class="result-value">${data.hostnames?.length > 0 ? data.hostnames.join(', ') : 'None'}</div>
            </div>
        `;
    } else if (source === 'otx') {
        content_html = `
            <div class="result-item">
                <div class="result-label">Found</div>
                <div class="result-value">${data.found ? 'Yes' : 'No'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Pulse Count</div>
                <div class="result-value">${data.pulse_count || 0}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Reputation</div>
                <div class="result-value">${data.reputation || 'N/A'}</div>
            </div>
        `;
    } else if (source === 'urlhaus') {
        content_html = `
            <div class="result-item">
                <div class="result-label">Threat Score</div>
                <div class="result-value">${data.threat_score || 0}%</div>
            </div>
            <div class="result-item">
                <div class="result-label">Threat</div>
                <div class="result-value">${data.threat || 'None'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Status</div>
                <div class="result-value">${data.status || 'Unknown'}</div>
            </div>
        `;
    } else if (source === 'whois') {
        const records = data.raw || {};
        content_html = `
            <div class="result-item">
                <div class="result-label">Registrar</div>
                <div class="result-value">${data.registrar || 'Unknown'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Creation Date</div>
                <div class="result-value">${data.creation_date || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Expiration Date</div>
                <div class="result-value">${data.expiration_date || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Registrant Country</div>
                <div class="result-value">${data.registrant_country || 'Unknown'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Name Servers</div>
                <div class="result-value">${data.name_servers?.length > 0 ? data.name_servers.join(', ') : 'None'}</div>
            </div>
        `;
    } else if (source === 'dns') {
        const records = data.records || {};
        const a_records = records.A || [];
        const aaaa_records = records.AAAA || [];
        const mx_records = records.MX || [];
        content_html = `
            <div class="result-item">
                <div class="result-label">A Records (IPv4)</div>
                <div class="result-value">${a_records.length > 0 ? a_records.join(', ') : 'None'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">AAAA Records (IPv6)</div>
                <div class="result-value">${aaaa_records.length > 0 ? aaaa_records.join(', ') : 'None'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">MX Records (Mail)</div>
                <div class="result-value">${mx_records.length > 0 ? mx_records.slice(0, 3).join(', ') : 'None'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">NS Records</div>
                <div class="result-value">${records.NS?.length > 0 ? records.NS.slice(0, 2).join(', ') : 'None'}</div>
            </div>
        `;
    } else if (source === 'ssl') {
        const cert = data.certificate || {};
        const subject = cert.subject || {};
        content_html = `
            <div class="result-item">
                <div class="result-label">Subject CN</div>
                <div class="result-value">${subject.CN || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Issuer</div>
                <div class="result-value">${cert.issuer?.O || 'Unknown'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Valid From</div>
                <div class="result-value">${cert.not_before || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Valid Until</div>
                <div class="result-value">${cert.not_after || 'N/A'}</div>
            </div>
            <div class="result-item">
                <div class="result-label">Algorithm</div>
                <div class="result-value">${cert.signature_algorithm || 'N/A'}</div>
            </div>
        `;
    }
    
    card.innerHTML = `
        <div class="result-header">
            <div class="icon">${icon_html}</div>
            <h3>${title.toUpperCase()}</h3>
        </div>
        <div class="result-body">
            ${content_html}
        </div>
    `;
    
    return card;
}

// ===== HELPER FUNCTIONS =====
function show_status(message, type) {
    searchStatus.textContent = message;
    searchStatus.className = `status-message ${type}`;
}

function show_loading(show) {
    const modal = document.getElementById('loading-modal');
    modal.classList.toggle('hidden', !show);
}

function cleanup_iocs(text) {
    return text
        .replace(/\[.\]/g, '.')
        .replace(/\(dot\)/gi, '.')
        .replace(/\[\.\]/g, '.')
        .replace(/hxxp/gi, 'http');
}

// ===== DEFANG =====
defangBtn.addEventListener('click', () => {
    const query = queryInput.value.trim();
    if (!query) {
        show_status('Please enter text first', 'error');
        return;
    }
    
    const defanged = query
        .replace(/\./g, '[.]')
        .replace(/:/g, '[:]')
        .replace(/http/gi, 'hxxp');
    
    queryInput.value = defanged;
    show_status(' Defanged', 'success');
});

// ===== CLEAR =====
clearBtn.addEventListener('click', () => {
    queryInput.value = '';
    queryInput.focus();
    resultsGrid.innerHTML = '';
    threatWidget.classList.add('hidden');
    show_status('', '');
});

// ===== ANALYTICS =====
async function load_analytics() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('insights-list').innerHTML = `
            <li>Average threat score: ${stats.average_threat_score.toFixed(2)}/100</li>
            <li>Total scans performed: ${stats.total_scans}</li>
            <li>Primary threat source: ${stats.query_types ? Object.entries(stats.query_types).sort((a,b) => b[1] - a[1])[0]?.[0] || 'N/A' : 'N/A'}</li>
        `;
    } catch (error) {
        console.error('Failed to load analytics:', error);
    }
}

// ===== HISTORY =====
async function load_history() {
    try {
        const response = await fetch('/api/history?limit=50');
        const history = await response.json();
        full_history = history;  // Store for searching
        const list = document.getElementById('history-list');
        
        if (history.length === 0) {
            list.innerHTML = '<p class="empty-state">No scan history yet</p>';
            return;
        }
        
        list.innerHTML = history.map(item => {
            const threat_level = item.threat_score >= 70 ? 'Critical' : 
                                item.threat_score >= 50 ? 'High' : 
                                item.threat_score >= 25 ? 'Medium' : 'Low';
            return `
            <div class="history-item">
                <strong>${item.query}</strong>
                <small>${item.query_type.toUpperCase()} • Score: ${Math.round(item.threat_score)}/100 (${threat_level})</small>
            </div>
        `}).join('');
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

// ===== DASHBOARD STATS =====
async function load_dashboard_stats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('stat-total-scans').textContent = stats.total_scans;
        document.getElementById('stat-avg-score').textContent = stats.average_threat_score.toFixed(1);
        document.getElementById('stat-domains').textContent = stats.query_types?.domain || 0;
        document.getElementById('stat-ips').textContent = stats.query_types?.ip || 0;
        
        // Load recent scans
        const history_response = await fetch('/api/history?limit=5');
        const history = await history_response.json();
        
        const recent_list = document.getElementById('recent-scans-list');
        if (history.length === 0) {
            recent_list.innerHTML = '<p class="empty-state">No scans yet</p>';
        } else {
            recent_list.innerHTML = history.map(item => `
                <div class="scan-item">
                    ${item.query} <span style="opacity: 0.7; font-size: 0.85em;">(${ Math.round(item.threat_score)})</span>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

// ===== HISTORY SEARCH & CLEAR =====
if (historySearch) {
    historySearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const list = document.getElementById('history-list');
        
        if (!query) {
            list.innerHTML = full_history.map(item => `
                <div class="history-item">
                    <span>${item.query}</span>
                    <span>${item.query_type.toUpperCase()} - Score: ${Math.round(item.threat_score)}</span>
                </div>
            `).join('');
            return;
        }
        
        const filtered = full_history.filter(item => 
            item.query.toLowerCase().includes(query)
        );
        
        list.innerHTML = filtered.length > 0 
            ? filtered.map(item => `
                <div class="history-item">
                    <span>${item.query}</span>
                    <span>${item.query_type.toUpperCase()} - Score: ${Math.round(item.threat_score)}</span>
                </div>
            `).join('')
            : '<p class="empty-state">No results found</p>';
    });
}

if (historyClear) {
    historyClear.addEventListener('click', async () => {
        if (confirm('Clear all history? This cannot be undone.')) {
            try {
                // Clear database via a new endpoint call
                show_status('Clearing history...', 'loading');
                // Note: This requires a /api/clear-history endpoint
                show_status('History functionality in development', 'error');
            } catch (error) {
                show_status('Error clearing history: ' + error.message, 'error');
            }
        }
    });
}

// ===== MODALS =====
const detailModal = document.getElementById('detail-modal');
const modalClose = document.querySelector('.modal-close');

if (modalClose) {
    modalClose.addEventListener('click', () => {
        detailModal.classList.add('hidden');
    });
}

// Close modal when clicking outside (backdrop)
if (detailModal) {
    detailModal.addEventListener('click', (e) => {
        if (e.target === detailModal) {
            detailModal.classList.add('hidden');
        }
    });
}

// ===== QUICK QUERY VALIDATION =====
// Optional quick form (only attach if present in DOM)
const quickFormElement = document.getElementById('quick-form');
const quickQuery = document.getElementById('quick-query');
if (quickFormElement && quickQuery) {
    quickFormElement.addEventListener('submit', async (e) => {
        e.preventDefault();
        const query = quickQuery.value.trim();

        if (!query) {
            show_status('Please enter a query', 'error');
            return;
        }
        if (query.length > 255) {
            show_status('Query too long (max 255 characters)', 'error');
            quickQuery.focus();
            return;
        }

        queryInput.value = query;
        quickQuery.value = '';
        await perform_lookup(query);
    });
}

// ===== SETTINGS HANDLERS =====
const exportDataBtn = document.getElementById('export-data-btn');
const resetSettingsBtn = document.getElementById('reset-settings-btn');
const clearDataBtn = document.getElementById('clear-data-btn');

if (exportDataBtn) {
    exportDataBtn.addEventListener('click', async () => {
        try {
            const response = await fetch('/api/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ data: results_cache })
            });
            
            if (response.ok) {
                const data = await response.json();
                const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = data.filename;
                a.click();
                window.URL.revokeObjectURL(url);
                show_status('Data exported successfully', 'success');
            } else {
                show_status('Export failed', 'error');
            }
        } catch (error) {
            show_status('Error exporting data: ' + error.message, 'error');
        }
    });
}

if (resetSettingsBtn) {
    resetSettingsBtn.addEventListener('click', () => {
        if (confirm('Reset all settings to defaults?')) {
            localStorage.clear();
            document.body.classList.remove('light-mode');
            const themeToggle = document.getElementById('theme-toggle');
            if (themeToggle) themeToggle.textContent = '☀️';
            show_status('Settings reset to defaults', 'success');
        }
    });
}

if (clearDataBtn) {
    clearDataBtn.addEventListener('click', () => {
        if (confirm('Clear all scan history and cache? This cannot be undone.')) {
            // This would require a backend endpoint to clear database
            resultsGrid.innerHTML = '';
            queryInput.value = '';
            threatWidget.classList.add('hidden');
            show_status('Local cache cleared. Backend data requires restart.', 'success');
        }
    });
}

// ===== INITIALIZE =====
if (typeof setup_theme === 'function') setup_theme();
load_dashboard_stats();
setInterval(load_dashboard_stats, 30000);
