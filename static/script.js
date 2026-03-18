// THREAT INTELLIGENCE DASHBOARD - JavaScript Logic

const form = document.getElementById('lookup-form');
const queryInput = document.getElementById('query-input');
const queryDisplay = document.getElementById('query-display');
const status = document.getElementById('status');
const vtContent = document.getElementById('vt-content');
const abuseContent = document.getElementById('abuse-content');
const shodanContent = document.getElementById('shodan-content');
const bulkInput = document.getElementById('bulk-input');
const historyList = document.getElementById('history-list');
const defangBtn = document.getElementById('defang-btn');
const exportBtn = document.getElementById('export-btn');
const extractBtn = document.getElementById('extract-btn');
const bulkScanBtn = document.getElementById('bulk-scan-btn');

let lastResults = null;
const scanHistory = [];

// IP/Domain validation regex
const IP_REGEX = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
const DOMAIN_REGEX = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.[A-Za-z0-9-]{1,63})*$/;

/**
 * Create a badge element with status indicator
 */
function createBadge(value, label, isMalicious = false) {
    if (isMalicious) {
        const isRisky = value > 0;
        const indicatorClass = isRisky ? 'indicator-danger' : 'indicator-safe';
        const badgeClass = isRisky ? 'badge-danger' : 'badge-safe';
        return `<span class="badge ${badgeClass}"><span class="status-indicator ${indicatorClass}"></span>${label}: <code>${value}</code></span>`;
    }
    return `<span class="badge">${label}: <code>${value}</code></span>`;
}

/**
 * Render hostnames as scrollable chip container
 */
function renderHostnames(hostnames) {
    if (!hostnames || hostnames.length === 0) {
        return '<span class="monospace">N/A</span>';
    }
    return `<div class="tags-container">${hostnames.map(h => `<span class="tag">${h}</span>`).join('')}</div>`;
}

/**
 * Render ports as chips
 */
function renderPorts(ports) {
    if (!ports || ports.length === 0) {
        return '<span class="monospace">None detected</span>';
    }
    return `<div class="tags-container">${ports.map(p => `<span class="tag">${p}</span>`).join('')}</div>`;
}

/**
 * Add to scan history
 */
function addToHistory(query, success = true) {
    const timestamp = new Date().toLocaleTimeString();
    const statusIcon = success ? '✓' : '✗';
    const item = `${statusIcon} ${query} — ${timestamp}`;
    
    scanHistory.unshift(item);
    if (scanHistory.length > 20) scanHistory.pop();
    
    updateHistoryUI();
}

/**
 * Update history UI
 */
function updateHistoryUI() {
    if (scanHistory.length === 0) {
        historyList.innerHTML = '<p class="placeholder">No scans yet.</p>';
        return;
    }
    historyList.innerHTML = scanHistory
        .map(item => `<div class="history-item">${item}</div>`)
        .join('');
}

/**
 * Defang IP/Domain (remove special chars)
 */
defangBtn.addEventListener('click', () => {
    const query = queryInput.value.trim();
    if (!query) {
        alert('Please enter an IP or domain first.');
        return;
    }
    const defanged = query
        .replace(/\./g, '[.]')
        .replace(/:/g, '[:]')
        .replace(/http/gi, 'hxxp');
    queryInput.value = defanged;
    status.innerHTML = '<span class="status-ok">✓ IP/Domain defanged (safe for pasting)</span>';
});

/**
 * Export results as JSON
 */
exportBtn.addEventListener('click', () => {
    if (!lastResults) {
        alert('No results to export. Run a search first.');
        return;
    }
    const dataStr = JSON.stringify(lastResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threat-intel-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    status.innerHTML = '<span class="status-ok">✓ Report exported</span>';
});

/**
 * Extract IOCs from bulk input (simple extraction)
 */
extractBtn.addEventListener('click', () => {
    const text = bulkInput.value.trim();
    if (!text) {
        alert('Please paste some logs or text.');
        return;
    }

    const lines = text.split('\n').map(l => l.trim()).filter(l => l);
    const iocs = {
        ips: [],
        domains: [],
        urls: []
    };

    lines.forEach(line => {
        if (IP_REGEX.test(line)) {
            iocs.ips.push(line);
        } else if (line.includes('http')) {
            iocs.urls.push(line);
        } else if (DOMAIN_REGEX.test(line)) {
            iocs.domains.push(line);
        }
    });

    const summary = `Found: ${iocs.ips.length} IPs, ${iocs.domains.length} domains, ${iocs.urls.length} URLs`;
    alert(summary);
    console.log('Extracted IOCs:', iocs);
    bulkInput.value = JSON.stringify(iocs, null, 2);
});

/**
 * Bulk scan - scan all extracted IOCs
 */
bulkScanBtn.addEventListener('click', async () => {
    const iocs = bulkInput.value.trim();
    if (!iocs) {
        alert('Please extract IOCs first or paste IP addresses/domains.');
        return;
    }

    let queries = [];
    try {
        const parsed = JSON.parse(iocs);
        queries = [...(parsed.ips || []), ...(parsed.domains || [])];
    } catch {
        // Fallback: treat lines as individual queries
        queries = iocs.split('\n').map(l => l.trim()).filter(l => l);
    }

    if (queries.length === 0) {
        alert('No valid IPs or domains found.');
        return;
    }

    status.innerHTML = `<span class="status-partial">⏳ Scanning ${queries.length} items...</span>`;
    let successCount = 0;

    for (const query of queries) {
        try {
            const response = await fetch('/lookup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query }),
            });
            if (response.ok) {
                successCount++;
                addToHistory(query, true);
            } else {
                addToHistory(query, false);
            }
        } catch {
            addToHistory(query, false);
        }
    }

    status.innerHTML = `<span class="status-ok">✓ Bulk scan complete: ${successCount}/${queries.length} succeeded</span>`;
});

/**
 * Main query form submission
 */
form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const query = queryInput.value.trim();
    if (!query) {
        status.textContent = 'Please enter an IP address or domain.';
        return;
    }

    queryDisplay.innerHTML = `<span class="query-label">Query:</span> <code class="query-value">${query}</code>`;
    status.innerHTML = '<span class="status-partial">⏳ Loading threat intelligence...</span>';
    vtContent.innerHTML = '<p class="placeholder"><em>Loading...</em></p>';
    abuseContent.innerHTML = '<p class="placeholder"><em>Loading...</em></p>';
    shodanContent.innerHTML = '<p class="placeholder"><em>Loading...</em></p>';

    try {
        const response = await fetch('/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query }),
        });

        const data = await response.json();
        lastResults = data;

        status.innerHTML = response.ok
            ? '<span class="status-ok">✓ Query completed</span>'
            : '<span class="status-partial">⚠ Some providers failed - showing available results</span>';

        const results = data.results;
        const errors = data.errors;

        // ===== VIRUSTOTAL =====
        if (results.virustotal) {
            const vtData = results.virustotal;
            vtContent.innerHTML = `
                <div class="data-row">
                    <span class="data-label">Reputation</span>
                    ${createBadge(vtData.reputation_score ?? 'N/A', 'Score')}
                </div>
                <div class="data-row">
                    <span class="data-label">Malicious Detections</span>
                    ${createBadge(vtData.malicious_detections ?? 0, 'Count', true)}
                </div>
                <div class="data-row">
                    <span class="data-label">Suspicious Detections</span>
                    ${createBadge(vtData.suspicious_detections ?? 0, 'Count')}
                </div>
            `;
        } else if (errors?.virustotal) {
            vtContent.innerHTML = `<p class="error-text">✗ Error: ${errors.virustotal.substring(0, 50)}...</p>`;
        } else {
            vtContent.innerHTML = '<p class="info-text">• No data available</p>';
        }

        // ===== ABUSEIPDB =====
        if (results.abuseipdb) {
            const abuseData = results.abuseipdb;
            abuseContent.innerHTML = `
                <div class="data-row">
                    <span class="data-label">Abuse Confidence</span>
                    ${createBadge(abuseData.abuse_confidence_score ?? 'N/A', 'Score')}
                </div>
                <div class="data-row">
                    <span class="data-label">Total Reports</span>
                    <span class="monospace">${abuseData.total_reports ?? 'N/A'}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Country Code</span>
                    <span class="monospace">${abuseData.country || 'N/A'}</span>
                </div>
            `;
        } else if (errors?.abuseipdb) {
            abuseContent.innerHTML = `<p class="error-text">✗ Error: ${errors.abuseipdb.substring(0, 50)}...</p>`;
        } else {
            abuseContent.innerHTML = '<p class="info-text">• No data available</p>';
        }

        // ===== SHODAN =====
        if (results.shodan) {
            const shodanData = results.shodan;
            shodanContent.innerHTML = `
                <div class="data-row">
                    <span class="data-label">Organization</span>
                    <span class="monospace">${shodanData.organization || 'N/A'}</span>
                </div>
                <div class="data-row">
                    <span class="data-label">Open Ports</span>
                    ${renderPorts(shodanData.open_ports)}
                </div>
                <div class="data-row">
                    <span class="data-label">Hostnames</span>
                    ${renderHostnames(shodanData.hostnames)}
                </div>
            `;
        } else if (errors?.shodan) {
            shodanContent.innerHTML = `<p class="error-text">✗ Error: ${errors.shodan.substring(0, 50)}...</p>`;
        } else {
            shodanContent.innerHTML = '<p class="info-text">• No data available</p>';
        }

        addToHistory(query, response.ok);

    } catch (err) {
        status.innerHTML = '<span class="status-error">✗ Network error</span>';
        vtContent.innerHTML = `<p class="error-text">${err.message}</p>`;
        abuseContent.innerHTML = '';
        shodanContent.innerHTML = '';
        addToHistory(query, false);
    }
});