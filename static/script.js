// ADVANCED THREAT INTELLIGENCE DASHBOARD - JAVASCRIPT

const nav_items = document.querySelectorAll('.nav-item');
const sections = document.querySelectorAll('.content-section');
const queryInput = document.getElementById('query-input');
const lookupForm = document.getElementById('lookup-form');
const resultsGrid = document.getElementById('results-grid');
const searchStatus = document.getElementById('search-status');
const threatWidget = document.getElementById('threat-widget');
const themeToggle = document.getElementById('theme-toggle');
const defangBtn = document.getElementById('defang-btn');
const clearBtn = document.getElementById('clear-btn');
const quickForm = document.getElementById('quick-lookup-form');
const quickQuery = document.getElementById('quick-query');
const timeDisplay = document.getElementById('time-display');

let results_cache = {};

// ===== NAVIGATION =====
nav_items.forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        const target = item.getAttribute('data-section') + '-section';
        
        nav_items.forEach(i => i.classList.remove('active'));
        sections.forEach(s => s.classList.remove('active'));
        
        item.classList.add('active');
        document.getElementById(target).classList.add('active');
        
        // Update page title
        const titles = {
            'dashboard': 'Threat Intelligence Dashboard',
            'lookup': 'Lookup & Analysis',
            'history': 'Scan History',
            'analytics': 'Analytics & Insights',
            'settings': 'Settings & Configuration'
        };
        document.getElementById('page-title').textContent = titles[item.getAttribute('data-section')] || 'Dashboard';
        
        if (item.getAttribute('data-section') === 'analytics') {
            load_analytics();
        } else if (item.getAttribute('data-section') === 'history') {
            load_history();
        }
    });
});

// ===== THEME TOGGLE =====
function setup_theme() {
    const saved_theme = localStorage.getItem('theme') || 'dark';
    document.body.classList.toggle('light-mode', saved_theme === 'light');
    themeToggle.textContent = saved_theme === 'light' ? '' : '';
}

themeToggle.addEventListener('click', () => {
    const is_light = document.body.classList.toggle('light-mode');
    localStorage.setItem('theme', is_light ? 'light' : 'dark');
    themeToggle.textContent = is_light ? '' : '';
});

// ===== TIME DISPLAY =====
function update_time() {
    const now = new Date();
    timeDisplay.textContent = now.toLocaleTimeString();
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

quickForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const query = quickQuery.value.trim();
    
    if (!query) {
        show_status('Please enter a query', 'error');
        return;
    }
    
    queryInput.value = query;
    quickQuery.value = '';
    await perform_lookup(query);
    
    document.querySelector('[data-section="lookup"]').click();
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
        show_status(' Analysis complete', 'success');
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
    
    // Render result cards
    resultsGrid.innerHTML = '';
    
    if (results.virustotal) {
        resultsGrid.appendChild(create_result_card('VirusTotal', '', results.virustotal, 'vt'));
    }
    if (results.abuseipdb) {
        resultsGrid.appendChild(create_result_card('AbuseIPDB', '', results.abuseipdb, 'abuse'));
    }
    if (results.shodan) {
        resultsGrid.appendChild(create_result_card('Shodan', '', results.shodan, 'shodan'));
    }
    if (results.otx) {
        resultsGrid.appendChild(create_result_card('AlienVault OTX', '', results.otx, 'otx'));
    }
    if (results.urlhaus) {
        resultsGrid.appendChild(create_result_card('URLhaus', '', results.urlhaus, 'urlhaus'));
    }
}

function create_result_card(title, icon, data, source) {
    const card = document.createElement('div');
    card.className = 'result-card';
    
    if (!data || !data.valid) {
        card.innerHTML = `
            <div class="result-header">
                <span class="icon">${icon}</span>
                <h3>${title}</h3>
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
    }
    
    card.innerHTML = `
        <div class="result-header">
            <span class="icon">${icon}</span>
            <h3>${title}</h3>
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
        const list = document.getElementById('history-list');
        
        if (history.length === 0) {
            list.innerHTML = '<p class="empty-state">No scan history yet</p>';
            return;
        }
        
        list.innerHTML = history.map(item => `
            <div class="history-item">
                <span>${item.query}</span>
                <span>${item.query_type.toUpperCase()} - Score: ${Math.round(item.threat_score)}</span>
            </div>
        `).join('');
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

// ===== MODALS =====
const detailModal = document.getElementById('detail-modal');
const modalClose = document.querySelector('.modal-close');

if (modalClose) {
    modalClose.addEventListener('click', () => {
        detailModal.classList.add('hidden');
    });
}

// Close modal when clicking outside (backdrop)
detailModal.addEventListener('click', (e) => {
    if (e.target === detailModal) {
        detailModal.classList.add('hidden');
    }
});

// ===== INITIALIZE =====
setup_theme();
load_dashboard_stats();
setInterval(load_dashboard_stats, 30000);
