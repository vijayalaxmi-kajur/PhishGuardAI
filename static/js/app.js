/**
 * PhishGuardAI — Intelligent Phishing URL Detection Web Dashboard
 * Vanilla JavaScript (ES6+) Frontend Controller
 * 
 * Interacts with Flask REST API:
 *   - GET  /api/health
 *   - POST /api/scan
 *   - GET  /api/history
 *   - DELETE /api/history
 * 
 * Strict Security Rules:
 *   - No innerHTML for user-submitted URLs or untrusted data.
 *   - Never fetch, open, visit, or resolve submitted URLs.
 *   - Derived scan counts and metrics from actual API responses.
 */

(function () {
    'use strict';

    // 22 Features Schema Order & Human-Readable Metadata
    const FEATURE_METADATA = {
        url_len: {
            label: "URL Length",
            category: "Lexical & Length",
            description: "Total character count of the complete URL string."
        },
        dom_len: {
            label: "Domain Length",
            category: "Lexical & Length",
            description: "Length of the extracted fully qualified domain name."
        },
        is_ip: {
            label: "IP Address Host",
            category: "Structural & Security",
            description: "Binary indicator: 1 if hostname is an IPv4/IPv6 address, 0 otherwise."
        },
        tld_len: {
            label: "TLD Length",
            category: "Lexical & Length",
            description: "Length of the top-level domain segment (e.g., 'com', 'edu.au')."
        },
        subdom_cnt: {
            label: "Subdomain Count",
            category: "Structural & Security",
            description: "Number of dot-separated subdomain labels preceding the domain."
        },
        letter_cnt: {
            label: "Letter Count",
            category: "Character Composition",
            description: "Total count of alphabetic ASCII characters (a-z, A-Z)."
        },
        digit_cnt: {
            label: "Digit Count",
            category: "Character Composition",
            description: "Total count of numeric characters (0-9)."
        },
        special_cnt: {
            label: "Special Character Count",
            category: "Character Composition",
            description: "Count of all non-alphanumeric characters in the URL."
        },
        eq_cnt: {
            label: "Equal Sign Count (=)",
            category: "Special Symbol Counts",
            description: "Count of '=' symbols, typically separating parameter keys and values."
        },
        qm_cnt: {
            label: "Question Mark Count (?)",
            category: "Special Symbol Counts",
            description: "Count of '?' delimiters initiating the URL query string."
        },
        amp_cnt: {
            label: "Ampersand Count (&)",
            category: "Special Symbol Counts",
            description: "Count of '&' characters used as query parameter delimiters."
        },
        dot_cnt: {
            label: "Dot Count (.)",
            category: "Special Symbol Counts",
            description: "Count of '.' characters used in domain labels and file paths."
        },
        dash_cnt: {
            label: "Hyphen Count (-)",
            category: "Special Symbol Counts",
            description: "Count of '-' characters, often used in phishing domain spoofing."
        },
        under_cnt: {
            label: "Underscore Count (_)",
            category: "Special Symbol Counts",
            description: "Count of '_' characters, frequently found in obfuscated scripts."
        },
        letter_ratio: {
            label: "Letter Ratio",
            category: "Character Composition",
            description: "Proportion of alphabetic letters relative to total URL length."
        },
        digit_ratio: {
            label: "Digit Ratio",
            category: "Character Composition",
            description: "Proportion of numeric digits relative to total URL length."
        },
        spec_ratio: {
            label: "Special Character Ratio",
            category: "Character Composition",
            description: "Proportion of special characters relative to total URL length."
        },
        is_https: {
            label: "HTTPS Protocol",
            category: "Structural & Security",
            description: "Binary indicator: 1 if the URL scheme is HTTPS, 0 if HTTP."
        },
        slash_cnt: {
            label: "Slash Count (/)",
            category: "Special Symbol Counts",
            description: "Count of '/' characters, reflecting the directory path depth."
        },
        entropy: {
            label: "Shannon Entropy",
            category: "Character Composition",
            description: "Information entropy measuring character distribution randomness."
        },
        path_len: {
            label: "Path Length",
            category: "Lexical & Length",
            description: "Character length of the URL path component."
        },
        query_len: {
            label: "Query String Length",
            category: "Lexical & Length",
            description: "Character length of the URL query parameters string."
        },
        host_len: {
            label: "Host Length",
            category: "Component Isolation",
            description: "Length of the full hostname string (including subdomains and TLD)."
        },
        subdom_len: {
            label: "Subdomain Length",
            category: "Component Isolation",
            description: "Total character length of the subdomain prefix preceding the registered domain."
        },
        dom_entropy: {
            label: "Domain Entropy",
            category: "Component Isolation",
            description: "Shannon entropy calculated exclusively across the registered domain label."
        },
        dom_digit_cnt: {
            label: "Domain Digit Count",
            category: "Component Isolation",
            description: "Count of numeric digits strictly inside the registered domain name."
        },
        path_depth: {
            label: "Path Depth",
            category: "Lexical & Length",
            description: "Count of directory path segments separated by slashes."
        },
        query_param_cnt: {
            label: "Query Parameter Count",
            category: "Special Symbol Counts",
            description: "Count of structured key-value query parameters in the URL."
        },
        query_entropy: {
            label: "Query Entropy",
            category: "Component Isolation",
            description: "Shannon entropy calculated exclusively across the query parameter string."
        },
        query_digit_cnt: {
            label: "Query Digit Count",
            category: "Special Symbol Counts",
            description: "Count of numeric digits strictly within the query parameter string."
        }
    };

    // State Variables
    let isScanning = false;
    let latestFeatures = null;

    // DOM Elements Cache
    const elements = {
        // Status & Header
        statusDot: document.getElementById('status-dot'),
        statusTextOverall: document.getElementById('status-text-overall'),
        statusModelName: document.getElementById('status-model-name'),
        statusDbState: document.getElementById('status-db-state'),
        btnRefreshAll: document.getElementById('btn-refresh-all'),

        // Stat Cards
        statHealthStatus: document.getElementById('stat-health-status'),
        statHealthSub: document.getElementById('stat-health-sub'),
        statTotalScans: document.getElementById('stat-total-scans'),
        statTotalSub: document.getElementById('stat-total-sub'),
        statLegitScans: document.getElementById('stat-legit-scans'),
        statLegitSub: document.getElementById('stat-legit-sub'),
        statPhishScans: document.getElementById('stat-phish-scans'),
        statPhishSub: document.getElementById('stat-phish-sub'),

        // Scanner Form
        scanForm: document.getElementById('scan-form'),
        urlInput: document.getElementById('url-input'),
        btnScan: document.getElementById('btn-scan'),
        scanLoading: document.getElementById('scan-loading'),
        scanError: document.getElementById('scan-error'),
        scanErrorMessage: document.getElementById('scan-error-message'),
        btnCloseError: document.getElementById('btn-close-error'),

        // Result Card
        predictionSection: document.getElementById('prediction-section'),
        resultCard: document.getElementById('result-card'),
        resultTimestamp: document.getElementById('result-timestamp'),
        resultUrlDisplay: document.getElementById('result-url-display'),
        liveTelemetryContainer: document.getElementById('live-telemetry-container'),
        livePresenceDot: document.getElementById('live-presence-dot'),
        livePresenceBadge: document.getElementById('live-presence-badge'),
        telemetryServerStatus: document.getElementById('telemetry-server-status'),
        telemetryPageTitle: document.getElementById('telemetry-page-title'),
        telemetryIpAddress: document.getElementById('telemetry-ip-address'),
        telemetryWebServer: document.getElementById('telemetry-web-server'),
        telemetryCredentialForm: document.getElementById('telemetry-credential-form'),
        telemetrySslStatus: document.getElementById('telemetry-ssl-status'),
        verdictHero: document.getElementById('verdict-hero'),
        verdictIcon: document.getElementById('verdict-icon'),
        verdictTitle: document.getElementById('verdict-title'),
        resultProbValue: document.getElementById('result-prob-value'),
        resultConfidenceValue: document.getElementById('result-confidence-value'),
        resultThresholdValue: document.getElementById('result-threshold-value'),
        meterProgressBar: document.getElementById('meter-progressbar'),
        meterFill: document.getElementById('meter-fill'),
        meterSummaryText: document.getElementById('meter-summary-text'),
        resultExplanationContainer: document.getElementById('result-explanation-container'),
        resultExplanationList: document.getElementById('result-explanation-list'),
        resultWarningList: document.getElementById('result-warning-list'),

        // Features
        featureSection: document.getElementById('feature-section'),
        featuresGrid: document.getElementById('features-grid'),
        featureSearch: document.getElementById('feature-search'),

        // History
        historyTable: document.getElementById('history-table'),
        historyTbody: document.getElementById('history-tbody'),
        historyEmpty: document.getElementById('history-empty'),
        historyLoading: document.getElementById('history-loading'),
        btnRefreshHistory: document.getElementById('btn-refresh-history'),
        btnClearHistory: document.getElementById('btn-clear-history'),

        // Modal
        modalClearHistory: document.getElementById('modal-clear-history'),
        btnCancelClear: document.getElementById('btn-cancel-clear'),
        btnConfirmClear: document.getElementById('btn-confirm-clear')
    };

    /**
     * Format an ISO timestamp string into human-readable local and UTC notation.
     */
    function formatTimestamp(isoStr) {
        if (!isoStr) return '--';
        try {
            const date = new Date(isoStr);
            if (isNaN(date.getTime())) return isoStr;
            return date.toUTCString().replace('GMT', 'UTC');
        } catch (e) {
            return isoStr;
        }
    }

    /**
     * Display a clean dismissible error message banner.
     */
    function showError(message) {
        if (!elements.scanError || !elements.scanErrorMessage) return;
        elements.scanErrorMessage.textContent = message;
        elements.scanError.classList.remove('hidden');
    }

    /**
     * Hide the error message banner.
     */
    function hideError() {
        if (elements.scanError) {
            elements.scanError.classList.add('hidden');
        }
    }

    /**
     * Fetch API health status from GET /api/health.
     */
    async function fetchHealth() {
        try {
            const response = await fetch('/api/health', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            const data = await response.json();

            if (response.ok && data.status === 'healthy') {
                if (elements.statusDot) {
                    elements.statusDot.className = 'status-dot dot-green';
                }
                if (elements.statusTextOverall) {
                    elements.statusTextOverall.textContent = 'System Healthy';
                }
                if (elements.statusModelName) {
                    elements.statusModelName.textContent = data.model_name || 'Random Forest';
                }
                if (elements.statusDbState) {
                    elements.statusDbState.textContent = 'Ready';
                }
                if (elements.statHealthStatus) {
                    elements.statHealthStatus.textContent = 'Online';
                    elements.statHealthStatus.className = 'stat-value text-green';
                }
                if (elements.statHealthSub) {
                    elements.statHealthSub.textContent = `${data.model_name || 'Random Forest'} Active`;
                }
            } else {
                // Degraded or offline
                if (elements.statusDot) {
                    elements.statusDot.className = 'status-dot dot-amber';
                }
                if (elements.statusTextOverall) {
                    elements.statusTextOverall.textContent = data.status === 'degraded' ? 'System Degraded' : 'Degraded';
                }
                if (elements.statusModelName) {
                    elements.statusModelName.textContent = data.model_loaded ? (data.model_name || 'Active') : 'Unavailable';
                }
                if (elements.statusDbState) {
                    elements.statusDbState.textContent = data.database_ready ? 'Ready' : 'Error';
                }
                if (elements.statHealthStatus) {
                    elements.statHealthStatus.textContent = 'Degraded';
                    elements.statHealthStatus.className = 'stat-value text-red';
                }
                if (elements.statHealthSub) {
                    elements.statHealthSub.textContent = data.model_loaded ? 'Model loaded, DB error' : 'Model not loaded';
                }
            }
        } catch (error) {
            if (elements.statusDot) {
                elements.statusDot.className = 'status-dot dot-red';
            }
            if (elements.statusTextOverall) {
                elements.statusTextOverall.textContent = 'Server Offline';
            }
            if (elements.statHealthStatus) {
                elements.statHealthStatus.textContent = 'Offline';
                elements.statHealthStatus.className = 'stat-value text-red';
            }
            if (elements.statHealthSub) {
                elements.statHealthSub.textContent = 'Cannot connect to Flask API';
            }
        }
    }

    /**
     * Fetch scan history from GET /api/history.
     */
    async function fetchHistory() {
        if (!elements.historyTbody) return;

        if (elements.historyLoading) {
            elements.historyLoading.classList.remove('hidden');
        }

        try {
            const response = await fetch('/api/history?limit=100&offset=0', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            const data = await response.json();

            if (elements.historyLoading) {
                elements.historyLoading.classList.add('hidden');
            }

            if (!response.ok || !data.success) {
                showError(data.error || 'Failed to retrieve scan history.');
                return;
            }

            const historyList = Array.isArray(data.history) ? data.history : [];
            const totalCount = typeof data.total === 'number' ? data.total : historyList.length;

            // Render stats derived from real history data
            renderDashboardStats(historyList, totalCount);

            // Render history table
            renderHistoryTable(historyList);

        } catch (error) {
            if (elements.historyLoading) {
                elements.historyLoading.classList.add('hidden');
            }
            showError('Unable to connect to database history endpoint.');
        }
    }

    /**
     * Calculate and display dynamic dashboard statistics from real history records.
     */
    function renderDashboardStats(historyList, totalCount) {
        if (elements.statTotalScans) {
            elements.statTotalScans.textContent = totalCount.toLocaleString();
        }
        if (elements.statTotalSub) {
            elements.statTotalSub.textContent = `${historyList.length} recent loaded`;
        }

        // Count phishing and legitimate in current history
        let phishCount = 0;
        let legitCount = 0;

        historyList.forEach(item => {
            const v = (item.verdict || '').toLowerCase();
            if (v === 'phishing') {
                phishCount++;
            } else if (v === 'legitimate') {
                legitCount++;
            }
        });

        const sampleSize = historyList.length;
        const legitPct = sampleSize > 0 ? ((legitCount / sampleSize) * 100).toFixed(1) : '0.0';
        const phishPct = sampleSize > 0 ? ((phishCount / sampleSize) * 100).toFixed(1) : '0.0';

        if (elements.statLegitScans) {
            elements.statLegitScans.textContent = legitCount.toLocaleString();
        }
        if (elements.statLegitSub) {
            elements.statLegitSub.textContent = `${legitPct}% of recent scans`;
        }

        if (elements.statPhishScans) {
            elements.statPhishScans.textContent = phishCount.toLocaleString();
        }
        if (elements.statPhishSub) {
            elements.statPhishSub.textContent = `${phishPct}% of recent scans`;
        }
    }

    /**
     * Render history records into the table using safe DOM operations.
     */
    function renderHistoryTable(records) {
        if (!elements.historyTbody) return;

        // Clear existing rows safely
        while (elements.historyTbody.firstChild) {
            elements.historyTbody.removeChild(elements.historyTbody.firstChild);
        }

        if (!records || records.length === 0) {
            if (elements.historyEmpty) elements.historyEmpty.classList.remove('hidden');
            if (elements.historyTable) elements.historyTable.classList.add('hidden');
            return;
        }

        if (elements.historyEmpty) elements.historyEmpty.classList.add('hidden');
        if (elements.historyTable) elements.historyTable.classList.remove('hidden');

        records.forEach(record => {
            const tr = document.createElement('tr');

            // 1. ID Column
            const tdId = document.createElement('td');
            tdId.textContent = String(record.id);
            tr.appendChild(tdId);

            // 2. URL Column (Strictly safe textContent to avoid XSS)
            const tdUrl = document.createElement('td');
            tdUrl.className = 'history-url-cell';
            tdUrl.textContent = String(record.url);
            tdUrl.title = String(record.url);
            tr.appendChild(tdUrl);

            // 3. Verdict Column
            const tdVerdict = document.createElement('td');
            const verdictSpan = document.createElement('span');
            const v = String(record.verdict || '').toLowerCase();
            if (v === 'phishing') {
                verdictSpan.className = 'history-verdict-badge verdict-badge-phishing';
                verdictSpan.textContent = 'Phishing';
            } else if (v === 'website_not_present') {
                verdictSpan.className = 'history-verdict-badge verdict-badge-not-present';
                verdictSpan.textContent = 'Not Present';
            } else if (v === 'inconclusive') {
                verdictSpan.className = 'history-verdict-badge verdict-badge-inconclusive';
                verdictSpan.textContent = 'Inconclusive';
            } else if (v === 'suspicious') {
                verdictSpan.className = 'history-verdict-badge verdict-badge-suspicious';
                verdictSpan.textContent = 'Suspicious';
            } else {
                verdictSpan.className = 'history-verdict-badge verdict-badge-legitimate';
                verdictSpan.textContent = 'Legitimate';
            }
            tdVerdict.appendChild(verdictSpan);
            tr.appendChild(tdVerdict);

            // 4. Phishing Probability
            const tdProb = document.createElement('td');
            if (v === 'website_not_present') {
                tdProb.textContent = 'N/A';
            } else {
                const probVal = typeof record.phishing_probability === 'number' 
                    ? (record.phishing_probability * 100).toFixed(2) + '%' 
                    : '--';
                tdProb.textContent = probVal;
            }
            tr.appendChild(tdProb);

            // 5. Confidence
            const tdConf = document.createElement('td');
            if (v === 'website_not_present') {
                tdConf.textContent = 'Offline';
            } else {
                const confVal = typeof record.confidence_percent === 'number'
                    ? record.confidence_percent.toFixed(2) + '%'
                    : '--';
                tdConf.textContent = confVal;
            }
            tr.appendChild(tdConf);

            // 6. Scanned At (Formatted UTC)
            const tdDate = document.createElement('td');
            tdDate.textContent = formatTimestamp(record.scanned_at);
            tr.appendChild(tdDate);

            elements.historyTbody.appendChild(tr);
        });
    }

    /**
     * Submit URL to POST /api/scan and render classification result.
     */
    async function handleScanSubmit(event) {
        event.preventDefault();
        hideError();

        if (isScanning) return;

        const rawUrl = elements.urlInput ? elements.urlInput.value.trim() : '';

        // Client-side pre-flight validations
        if (!rawUrl) {
            showError('Please enter a target URL to scan.');
            if (elements.urlInput) elements.urlInput.focus();
            return;
        }

        if (rawUrl.length > 2048) {
            showError('URL exceeds maximum permitted length of 2048 characters.');
            return;
        }

        // Scheme validation
        const lowerUrl = rawUrl.toLowerCase();
        if (!lowerUrl.startsWith('http://') && !lowerUrl.startsWith('https://')) {
            showError("URL must begin with an explicit 'http://' or 'https://' scheme.");
            return;
        }

        // Lock UI in scanning state
        setScanningState(true);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ url: rawUrl })
            });

            const data = await response.json();

            setScanningState(false);

            if (!response.ok || !data.success) {
                showError(data.error || 'Scan analysis failed on target URL.');
                return;
            }

            // Render prediction result
            renderScanResult(data);

            // Render features breakdown (hidden if website is not present)
            if (data.feature_breakdown && Object.keys(data.feature_breakdown).length > 0) {
                latestFeatures = data.feature_breakdown;
                renderFeaturesGrid(data.feature_breakdown);
            } else if (elements.featureSection) {
                elements.featureSection.classList.add('hidden');
                latestFeatures = null;
            }

            // Refresh history table & metrics to include this scan
            fetchHistory();

        } catch (error) {
            setScanningState(false);
            showError('Network error: Unable to reach the PhishGuardAI scan endpoint.');
        }
    }

    /**
     * Set loading indicator and disable buttons while request is in flight.
     */
    function setScanningState(scanning) {
        isScanning = scanning;

        if (elements.btnScan) {
            elements.btnScan.disabled = scanning;
            if (scanning) {
                elements.btnScan.classList.add('loading');
            } else {
                elements.btnScan.classList.remove('loading');
            }
        }

        if (elements.urlInput) {
            elements.urlInput.disabled = scanning;
        }

        if (elements.scanLoading) {
            if (scanning) {
                elements.scanLoading.classList.remove('hidden');
            } else {
                elements.scanLoading.classList.add('hidden');
            }
        }
    }

    /**
     * Render the Prediction Result Card safely.
     */
    function renderScanResult(data) {
        if (!elements.predictionSection) return;

        elements.predictionSection.classList.remove('hidden');

        // Escaped URL text display (Safe DOM textContent)
        if (elements.resultUrlDisplay) {
            elements.resultUrlDisplay.textContent = data.url;
        }

        // Live Presence & Telemetry Panel
        const isOnline = data.website_present !== false;
        const telem = data.live_telemetry || data.presence_details || {};

        if (elements.livePresenceDot) {
            elements.livePresenceDot.className = isOnline 
                ? 'live-presence-dot presence-dot-online' 
                : 'live-presence-dot presence-dot-offline';
        }

        if (elements.livePresenceBadge) {
            if (isOnline) {
                elements.livePresenceBadge.className = 'live-presence-badge presence-badge-online';
                elements.livePresenceBadge.textContent = 'ONLINE / REACHABLE';
                elements.livePresenceBadge.title = 'Target verified online and actively responding';
            } else {
                elements.livePresenceBadge.className = 'live-presence-badge presence-badge-offline';
                elements.livePresenceBadge.textContent = telem.soft_404 ? '404 NOT FOUND' : 'OFFLINE / UNREACHABLE';
                elements.livePresenceBadge.title = telem.soft_404 ? 'Platform returned 404 Site Not Found' : 'Domain does not resolve in public DNS';
            }
        }

        // 1. Server Status
        if (elements.telemetryServerStatus) {
            if (isOnline) {
                elements.telemetryServerStatus.textContent = telem.http_status 
                    ? `Active (HTTP ${telem.http_status})` 
                    : 'Online (HTTP 200)';
                elements.telemetryServerStatus.className = 'telemetry-item-value text-green';
            } else {
                if (telem.http_status === 404 || telem.soft_404) {
                    elements.telemetryServerStatus.textContent = 'HTTP 404 (Site Not Found)';
                } else if (telem.http_status) {
                    elements.telemetryServerStatus.textContent = `Offline (HTTP ${telem.http_status})`;
                } else {
                    elements.telemetryServerStatus.textContent = 'Offline (NXDOMAIN / DNS Failure)';
                }
                elements.telemetryServerStatus.className = 'telemetry-item-value text-red';
            }
        }

        // 2. Live Page Title
        if (elements.telemetryPageTitle) {
            if (isOnline) {
                const titleStr = telem.page_title ? telem.page_title.trim() : '';
                elements.telemetryPageTitle.textContent = titleStr ? `"${titleStr}"` : 'No HTML Title Tag Found';
                elements.telemetryPageTitle.title = titleStr || 'No title';
            } else {
                const titleStr = telem.page_title ? telem.page_title.trim() : '';
                elements.telemetryPageTitle.textContent = titleStr ? `"${titleStr}" (Not Found)` : 'None (Host Not Reachable)';
                elements.telemetryPageTitle.title = titleStr || 'Host offline';
            }
        }

        // 3. Resolved IP Address
        if (elements.telemetryIpAddress) {
            if (telem.resolved_ip) {
                elements.telemetryIpAddress.textContent = telem.resolved_ip;
                elements.telemetryIpAddress.title = `DNS Resolved IP: ${telem.resolved_ip}`;
            } else {
                elements.telemetryIpAddress.textContent = 'No DNS Record (NXDOMAIN)';
                elements.telemetryIpAddress.title = 'Domain has no valid DNS A/AAAA records';
            }
        }

        // 4. Web Server
        if (elements.telemetryWebServer) {
            if (telem.server_header) {
                elements.telemetryWebServer.textContent = telem.server_header;
            } else if (telem.soft_404_platform) {
                elements.telemetryWebServer.textContent = `${telem.soft_404_platform} Edge CDN`;
            } else if (isOnline) {
                elements.telemetryWebServer.textContent = 'Protected / Custom Server';
            } else {
                elements.telemetryWebServer.textContent = 'None (Host Offline)';
            }
        }

        // 5. Credential / Login Form
        if (elements.telemetryCredentialForm) {
            if (!isOnline) {
                elements.telemetryCredentialForm.textContent = 'N/A (Host Offline)';
                elements.telemetryCredentialForm.className = 'telemetry-item-value text-muted';
            } else if (telem.has_password_input) {
                elements.telemetryCredentialForm.textContent = '⚠️ Password Input Detected';
                elements.telemetryCredentialForm.className = 'telemetry-item-value text-amber';
            } else {
                elements.telemetryCredentialForm.textContent = 'Clean (No Password Form)';
                elements.telemetryCredentialForm.className = 'telemetry-item-value text-green';
            }
        }

        // 6. SSL Security
        if (elements.telemetrySslStatus) {
            if (!isOnline) {
                elements.telemetrySslStatus.textContent = 'N/A (No Host)';
                elements.telemetrySslStatus.className = 'telemetry-item-value text-muted';
            } else if (telem.ssl_verified) {
                elements.telemetrySslStatus.textContent = '🔒 TLS / HTTPS Active';
                elements.telemetrySslStatus.className = 'telemetry-item-value text-green';
            } else {
                elements.telemetrySslStatus.textContent = '🔓 Unencrypted HTTP';
                elements.telemetrySslStatus.className = 'telemetry-item-value text-amber';
            }
        }

        // Timestamp
        if (elements.resultTimestamp) {
            elements.resultTimestamp.textContent = formatTimestamp(data.scanned_at);
        }

        const v = String(data.verdict || '').toLowerCase();
        const isNotPresent = v === 'website_not_present' || data.website_present === false;
        const isPhish = v === 'phishing';
        const isInconclusive = v === 'inconclusive';
        const isSuspicious = v === 'suspicious';
        const probPct = (data.phishing_probability * 100).toFixed(2);
        const confPct = (data.confidence_percent).toFixed(2);
        const thresholdVal = typeof data.threshold === 'number' ? data.threshold.toFixed(2) : '0.50';

        // Verdict styling & text
        if (elements.verdictHero && elements.resultCard) {
            if (isNotPresent) {
                elements.verdictHero.className = 'verdict-hero hero-not-present';
                elements.resultCard.className = 'card result-card verdict-is-not-present';
                if (elements.verdictTitle) {
                    elements.verdictTitle.textContent = data.standardized_verdict || 'Website Not Present';
                }
                // Globe with diagonal offline strike icon
                if (elements.verdictIcon) {
                    elements.verdictIcon.innerHTML = `
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                        </svg>
                    `;
                }
            } else if (isPhish) {
                elements.verdictHero.className = 'verdict-hero hero-phishing';
                elements.resultCard.className = 'card result-card verdict-is-phishing';
                if (elements.verdictTitle) {
                    elements.verdictTitle.textContent = data.standardized_verdict || 'Potential Phishing';
                }
                // Red shield/warning icon
                if (elements.verdictIcon) {
                    elements.verdictIcon.innerHTML = `
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    `;
                }
            } else if (isInconclusive) {
                elements.verdictHero.className = 'verdict-hero hero-inconclusive';
                elements.resultCard.className = 'card result-card verdict-is-inconclusive';
                if (elements.verdictTitle) {
                    elements.verdictTitle.textContent = data.standardized_verdict || 'Inconclusive (Abstained)';
                }
                // Amber question / alert icon
                if (elements.verdictIcon) {
                    elements.verdictIcon.innerHTML = `
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="12" y1="8" x2="12" y2="12"/>
                            <line x1="12" y1="16" x2="12.01" y2="16"/>
                        </svg>
                    `;
                }
            } else if (isSuspicious) {
                elements.verdictHero.className = 'verdict-hero hero-suspicious';
                elements.resultCard.className = 'card result-card verdict-is-suspicious';
                if (elements.verdictTitle) {
                    elements.verdictTitle.textContent = data.standardized_verdict || 'Suspicious URL';
                }
                // Orange warning icon
                if (elements.verdictIcon) {
                    elements.verdictIcon.innerHTML = `
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                            <line x1="12" y1="9" x2="12" y2="13"/>
                            <line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                    `;
                }
            } else {
                elements.verdictHero.className = 'verdict-hero hero-legitimate';
                elements.resultCard.className = 'card result-card verdict-is-legitimate';
                if (elements.verdictTitle) {
                    elements.verdictTitle.textContent = data.standardized_verdict || 'No Known Threat Detected';
                }
                // Green verified check shield icon
                if (elements.verdictIcon) {
                    elements.verdictIcon.innerHTML = `
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            <polyline points="9 12 11 14 15 10"/>
                        </svg>
                    `;
                }
            }
        }

        // Metrics values
        if (elements.resultProbValue) {
            if (isNotPresent) {
                elements.resultProbValue.textContent = 'N/A';
                elements.resultProbValue.className = 'metric-value text-muted';
            } else {
                elements.resultProbValue.textContent = `${probPct}%`;
                if (isPhish) {
                    elements.resultProbValue.className = 'metric-value text-red';
                } else if (isInconclusive || isSuspicious) {
                    elements.resultProbValue.className = 'metric-value text-amber';
                } else {
                    elements.resultProbValue.className = 'metric-value text-green';
                }
            }
        }
        if (elements.resultConfidenceValue) {
            if (isNotPresent) {
                elements.resultConfidenceValue.textContent = 'Offline';
            } else {
                elements.resultConfidenceValue.textContent = `${confPct}%`;
            }
        }
        if (elements.resultThresholdValue) {
            elements.resultThresholdValue.textContent = isNotPresent ? '--' : thresholdVal;
        }

        // Progress meter
        if (elements.meterProgressBar && elements.meterFill) {
            if (isNotPresent) {
                elements.meterProgressBar.setAttribute('aria-valuenow', '0');
                elements.meterFill.style.width = '0%';
                elements.meterFill.style.backgroundColor = 'var(--text-muted)';
            } else {
                elements.meterProgressBar.setAttribute('aria-valuenow', probPct);
                elements.meterFill.style.width = `${Math.min(100, Math.max(0, probPct))}%`;
                if (isInconclusive || isSuspicious) {
                    elements.meterFill.style.backgroundColor = 'var(--amber-primary)';
                } else if (isPhish) {
                    elements.meterFill.style.backgroundColor = 'var(--red-primary)';
                } else {
                    elements.meterFill.style.backgroundColor = 'var(--green-primary)';
                }
            }
        }

        if (elements.meterSummaryText) {
            if (isNotPresent) {
                const presenceDesc = data.presence_message || 'Domain does not resolve in public DNS or host is offline';
                elements.meterSummaryText.innerHTML = `Live DNS & connectivity check confirmed that <strong>this website is NOT present</strong> on the internet (${presenceDesc}). Analysis halted — no fake model metrics generated.`;
            } else if (isPhish) {
                elements.meterSummaryText.innerHTML = `Classifier estimated a <strong>${probPct}%</strong> probability of phishing (exceeds decision threshold of ${thresholdVal}).`;
            } else if (isInconclusive) {
                elements.meterSummaryText.innerHTML = `Classifier estimated a <strong>${probPct}%</strong> model score, but system abstained: <strong>INCONCLUSIVE</strong> due to query-domain contrast or conflicting evidence.`;
            } else if (isSuspicious) {
                elements.meterSummaryText.innerHTML = `Structural anomaly detected: <strong>SUSPICIOUS</strong> (calibrated model score: <strong>${probPct}%</strong>).`;
            } else {
                elements.meterSummaryText.innerHTML = `Classifier estimated a <strong>${probPct}%</strong> probability of phishing (within legitimate baseline &le; ${thresholdVal}).`;
            }
        }

        // Render explanations and warnings
        if (elements.resultExplanationContainer) {
            const hasExplanations = Array.isArray(data.explanation) && data.explanation.length > 0;
            const hasWarnings = Array.isArray(data.warnings) && data.warnings.length > 0;

            if (hasExplanations || hasWarnings) {
                elements.resultExplanationContainer.classList.remove('hidden');

                if (elements.resultExplanationList) {
                    while (elements.resultExplanationList.firstChild) {
                        elements.resultExplanationList.removeChild(elements.resultExplanationList.firstChild);
                    }
                    if (hasExplanations) {
                        data.explanation.forEach(exp => {
                            const li = document.createElement('li');
                            li.textContent = exp;
                            elements.resultExplanationList.appendChild(li);
                        });
                    }
                }

                if (elements.resultWarningList) {
                    while (elements.resultWarningList.firstChild) {
                        elements.resultWarningList.removeChild(elements.resultWarningList.firstChild);
                    }
                    if (hasWarnings) {
                        data.warnings.forEach(warn => {
                            const li = document.createElement('li');
                            li.textContent = warn;
                            elements.resultWarningList.appendChild(li);
                        });
                    }
                }
            } else {
                elements.resultExplanationContainer.classList.add('hidden');
            }
        }

        // Smoothly scroll down to result card
        elements.predictionSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    /**
     * Render the engineered features grid safely.
     */
    function renderFeaturesGrid(featureDict, filterQuery = '') {
        if (!elements.featuresGrid || !elements.featureSection) return;

        elements.featureSection.classList.remove('hidden');

        // Clear existing feature items safely
        while (elements.featuresGrid.firstChild) {
            elements.featuresGrid.removeChild(elements.featuresGrid.firstChild);
        }

        const query = (filterQuery || '').toLowerCase().trim();

        // Schema canonical order
        const baseKeys = [
            'url_len', 'dom_len', 'is_ip', 'tld_len', 'subdom_cnt',
            'letter_cnt', 'digit_cnt', 'special_cnt', 'eq_cnt', 'qm_cnt',
            'amp_cnt', 'dot_cnt', 'dash_cnt', 'under_cnt', 'letter_ratio',
            'digit_ratio', 'spec_ratio', 'is_https', 'slash_cnt', 'entropy',
            'path_len', 'query_len',
            'host_len', 'subdom_len', 'dom_entropy', 'dom_digit_cnt',
            'path_depth', 'query_param_cnt', 'query_entropy', 'query_digit_cnt'
        ];

        const featureKeys = baseKeys.filter(k => k in featureDict);
        Object.keys(featureDict).forEach(k => {
            if (!featureKeys.includes(k)) featureKeys.push(k);
        });

        let matchCount = 0;

        featureKeys.forEach(key => {
            const meta = FEATURE_METADATA[key] || {
                label: key,
                category: 'General Feature',
                description: 'Passive URL feature.'
            };

            const rawVal = featureDict[key];

            // Search filter matches key, label, category, or description
            if (query) {
                const searchTarget = `${key} ${meta.label} ${meta.category} ${meta.description}`.toLowerCase();
                if (!searchTarget.includes(query)) {
                    return;
                }
            }

            matchCount++;

            // Create card item
            const item = document.createElement('div');
            item.className = 'feature-item';

            // Top row
            const topDiv = document.createElement('div');
            topDiv.className = 'feature-item-top';

            const nameCode = document.createElement('code');
            nameCode.className = 'feature-name';
            nameCode.textContent = key;
            nameCode.title = meta.label;
            topDiv.appendChild(nameCode);

            const valBadge = document.createElement('span');
            valBadge.className = 'feature-value-badge';

            // Format numerical values sensibly
            if (key === 'is_ip' || key === 'is_https') {
                valBadge.textContent = rawVal === 1 ? '1 (Yes)' : '0 (No)';
                if (key === 'is_ip' && rawVal === 1) {
                    valBadge.className += ' text-red';
                } else if (key === 'is_https' && rawVal === 1) {
                    valBadge.className += ' text-green';
                }
            } else if (typeof rawVal === 'number') {
                if (Number.isInteger(rawVal)) {
                    valBadge.textContent = String(rawVal);
                } else {
                    // Floating point ratios / entropy formatted to 4 decimals
                    valBadge.textContent = rawVal.toFixed(4);
                }
            } else {
                valBadge.textContent = String(rawVal ?? '--');
            }
            topDiv.appendChild(valBadge);

            item.appendChild(topDiv);

            // Description
            const descP = document.createElement('p');
            descP.className = 'feature-desc';
            descP.textContent = meta.description;
            item.appendChild(descP);

            // Category tag
            const catSpan = document.createElement('span');
            catSpan.className = 'feature-category';
            catSpan.textContent = meta.category;
            item.appendChild(catSpan);

            elements.featuresGrid.appendChild(item);
        });

        if (matchCount === 0) {
            const noMatchDiv = document.createElement('div');
            noMatchDiv.className = 'text-muted';
            noMatchDiv.style.gridColumn = '1 / -1';
            noMatchDiv.style.padding = '1.5rem 0';
            noMatchDiv.textContent = `No features matching '${query}'.`;
            elements.featuresGrid.appendChild(noMatchDiv);
        }
    }

    /**
     * Clear all scan history records from the SQLite database.
     */
    async function handleClearHistoryConfirm() {
        closeClearModal();

        try {
            const response = await fetch('/api/history', {
                method: 'DELETE',
                headers: { 'Accept': 'application/json' }
            });
            const data = await response.json();

            if (!response.ok || !data.success) {
                showError(data.error || 'Failed to clear scan history.');
                return;
            }

            // Reload history to refresh table and dashboard counts
            fetchHistory();

        } catch (error) {
            showError('Unable to connect to database deletion endpoint.');
        }
    }

    function openClearModal() {
        if (elements.modalClearHistory) {
            elements.modalClearHistory.classList.remove('hidden');
            if (elements.btnCancelClear) elements.btnCancelClear.focus();
        }
    }

    function closeClearModal() {
        if (elements.modalClearHistory) {
            elements.modalClearHistory.classList.add('hidden');
            if (elements.btnClearHistory) elements.btnClearHistory.focus();
        }
    }

    /**
     * Attach Event Listeners
     */
    function attachEventListeners() {
        // Form submit
        if (elements.scanForm) {
            elements.scanForm.addEventListener('submit', handleScanSubmit);
        }

        // Close error alert banner
        if (elements.btnCloseError) {
            elements.btnCloseError.addEventListener('click', hideError);
        }

        // Refresh stats
        if (elements.btnRefreshAll) {
            elements.btnRefreshAll.addEventListener('click', () => {
                fetchHealth();
                fetchHistory();
            });
        }

        // Refresh history
        if (elements.btnRefreshHistory) {
            elements.btnRefreshHistory.addEventListener('click', fetchHistory);
        }

        // Clear history button
        if (elements.btnClearHistory) {
            elements.btnClearHistory.addEventListener('click', openClearModal);
        }

        // Modal cancel & confirm
        if (elements.btnCancelClear) {
            elements.btnCancelClear.addEventListener('click', closeClearModal);
        }
        if (elements.btnConfirmClear) {
            elements.btnConfirmClear.addEventListener('click', handleClearHistoryConfirm);
        }

        // Modal background click or ESC key
        if (elements.modalClearHistory) {
            elements.modalClearHistory.addEventListener('click', (e) => {
                if (e.target === elements.modalClearHistory) {
                    closeClearModal();
                }
            });
        }

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && elements.modalClearHistory && !elements.modalClearHistory.classList.contains('hidden')) {
                closeClearModal();
            }
        });

        // Sample URL chips
        const chips = document.querySelectorAll('.chip');
        chips.forEach(chip => {
            chip.addEventListener('click', () => {
                const sampleUrl = chip.getAttribute('data-url');
                if (elements.urlInput && sampleUrl) {
                    elements.urlInput.value = sampleUrl;
                    elements.urlInput.focus();
                }
            });
        });

        // Feature live search
        if (elements.featureSearch) {
            elements.featureSearch.addEventListener('input', (e) => {
                if (latestFeatures) {
                    renderFeaturesGrid(latestFeatures, e.target.value);
                }
            });
        }

        // Tab Navigation
        initTabs();

        // Developer Portal & SDK Code Generator
        initDeveloperPortal();
    }

    /**
     * Tab Navigation Switching Logic
     */
    function initTabs() {
        const tabBtns = document.querySelectorAll('.tab-btn');
        const panels = document.querySelectorAll('.tab-panel');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.getAttribute('data-target');
                tabBtns.forEach(b => b.classList.remove('active'));
                panels.forEach(p => p.classList.add('hidden'));

                btn.classList.add('active');
                const targetPanel = document.getElementById(targetId);
                if (targetPanel) {
                    targetPanel.classList.remove('hidden');
                }

                if (targetId === 'panel-developer') {
                    loadDeveloperData();
                }
            });
        });
    }

    /**
     * Code Snippets & Developer API Key Management
     */
    const CODE_SNIPPETS = {
        python: `# Python SDK Quickstart
from phishguard import PhishGuardClient

client = PhishGuardClient(
    api_key="YOUR_API_KEY",
    base_url="http://127.0.0.1:5000"
)

# Deep scan a suspicious link
result = client.scan("http://chase-bank-verify.xyz")
print("Verdict:", result["verdict"])
print("Risk Score:", result["phishing_probability"])
print("Explanation:", result["explanation"])`,

        node: `// Node.js & TypeScript SDK Quickstart
const { PhishGuardClient } = require("@phishguard/sdk");

const client = new PhishGuardClient({
    apiKey: "YOUR_API_KEY",
    baseUrl: "http://127.0.0.1:5000"
});

async function run() {
    const res = await client.scan("http://chase-bank-verify.xyz");
    console.log("Verdict:", res.verdict);
    console.log("Risk Level:", res.risk_level);
}
run();`,

        curl: `# Direct REST API cURL Request
curl -X POST http://127.0.0.1:5000/api/v1/scan \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -d '{"url": "http://chase-bank-verify.xyz", "check_presence": true}'`
    };

    let activeLang = 'python';
    let devSessionToken = localStorage.getItem('phishguard_dev_token') || null;

    function initDeveloperPortal() {
        const codeTabBtns = document.querySelectorAll('.code-tab-btn');
        const codeBox = document.getElementById('code-snippet-box');
        const btnCopySnippet = document.getElementById('btn-copy-snippet');
        const btnCreateKey = document.getElementById('btn-create-key');
        const btnCopyRawKey = document.getElementById('btn-copy-raw-key');

        // Snippet tab buttons
        codeTabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                codeTabBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeLang = btn.getAttribute('data-lang');
                if (codeBox && CODE_SNIPPETS[activeLang]) {
                    codeBox.textContent = CODE_SNIPPETS[activeLang];
                }
            });
        });

        // Copy snippet
        if (btnCopySnippet && codeBox) {
            btnCopySnippet.addEventListener('click', () => {
                navigator.clipboard.writeText(codeBox.textContent).then(() => {
                    btnCopySnippet.textContent = 'Copied! ✓';
                    setTimeout(() => { btnCopySnippet.textContent = 'Copy Code'; }, 1500);
                });
            });
        }

        // Copy raw newly generated key
        if (btnCopyRawKey) {
            btnCopyRawKey.addEventListener('click', () => {
                const rawKey = document.getElementById('raw-key-display');
                if (rawKey) {
                    navigator.clipboard.writeText(rawKey.textContent).then(() => {
                        btnCopyRawKey.textContent = 'Copied! ✓';
                        setTimeout(() => { btnCopyRawKey.textContent = 'Copy'; }, 1500);
                    });
                }
            });
        }

        // Self-Serve Razorpay Upgrade Buttons
        ['btn-upgrade-pro', 'btn-upgrade-biz'].forEach(btnId => {
            const btn = document.getElementById(btnId);
            if (btn) {
                btn.addEventListener('click', async () => {
                    await ensureDevSession();
                    if (!devSessionToken) return;

                    const tier = btn.getAttribute('data-tier') || 'developer_pro';
                    btn.disabled = true;
                    btn.textContent = 'Creating Order...';

                    try {
                        const resp = await fetch('/api/v1/billing/razorpay/create-order', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': 'Bearer ' + devSessionToken
                            },
                            body: JSON.stringify({ plan_tier: tier, currency: 'INR' })
                        });
                        const data = await resp.json();

                        if (!data.success || !data.order_id) {
                            alert('Order creation failed: ' + (data.error || 'Unknown error'));
                            return;
                        }

                        // Open Razorpay Standard Checkout modal if script loaded
                        if (window.Razorpay) {
                            const rzpOptions = {
                                key: data.key_id,
                                amount: data.amount,
                                currency: data.currency,
                                name: "PhishGuardAI",
                                description: data.plan_name + " Upgrade",
                                order_id: data.order_id,
                                prefill: {
                                    email: data.user_email,
                                    name: data.user_name
                                },
                                theme: {
                                    color: "#38bdf8"
                                },
                                handler: async function (paymentResp) {
                                    btn.textContent = 'Verifying...';
                                    try {
                                        const vResp = await fetch('/api/v1/billing/razorpay/verify-payment', {
                                            method: 'POST',
                                            headers: {
                                                'Content-Type': 'application/json',
                                                'Authorization': 'Bearer ' + devSessionToken
                                            },
                                            body: JSON.stringify({
                                                plan_tier: tier,
                                                razorpay_order_id: paymentResp.razorpay_order_id,
                                                razorpay_payment_id: paymentResp.razorpay_payment_id,
                                                razorpay_signature: paymentResp.razorpay_signature
                                            })
                                        });
                                        const vData = await vResp.json();
                                        if (vData.success) {
                                            alert('🎉 Payment Verified! Upgraded to ' + data.plan_name + ' successfully.');
                                            loadDeveloperData();
                                        } else {
                                            alert('Verification failed: ' + vData.error);
                                        }
                                    } catch (err) {
                                        alert('Verification error: ' + err.message);
                                    } finally {
                                        btn.disabled = false;
                                        btn.textContent = tier === 'business' ? '💼 Upgrade to Business (₹9,999/mo)' : '⚡ Upgrade to Pro (₹1,999/mo)';
                                    }
                                },
                                modal: {
                                    ondismiss: function() {
                                        btn.disabled = false;
                                        btn.textContent = tier === 'business' ? '💼 Upgrade to Business (₹9,999/mo)' : '⚡ Upgrade to Pro (₹1,999/mo)';
                                    }
                                }
                            };
                            const rzp = new window.Razorpay(rzpOptions);
                            rzp.open();
                        } else {
                            // Offline or local simulated fallback
                            if (confirm('Razorpay checkout modal requires network. Simulate instant activation for ' + data.plan_name + '?')) {
                                const vResp = await fetch('/api/v1/billing/razorpay/verify-payment', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                        'Authorization': 'Bearer ' + devSessionToken
                                    },
                                    body: JSON.stringify({
                                        plan_tier: tier,
                                        razorpay_order_id: data.order_id,
                                        razorpay_payment_id: 'pay_simulated_' + Date.now(),
                                        razorpay_signature: 'sig_mock'
                                    })
                                });
                                const vData = await vResp.json();
                                if (vData.success) {
                                    alert('🎉 Plan activated: ' + data.plan_name);
                                    loadDeveloperData();
                                }
                            }
                        }
                    } catch (err) {
                        alert('Billing error: ' + err.message);
                    } finally {
                        btn.disabled = false;
                        btn.textContent = tier === 'business' ? '💼 Upgrade to Business (₹9,999/mo)' : '⚡ Upgrade to Pro (₹1,999/mo)';
                    }
                });
            }
        });

        // Generate new API Key
        if (btnCreateKey) {
            btnCreateKey.addEventListener('click', async () => {
                await ensureDevSession();
                if (!devSessionToken) return;

                btnCreateKey.disabled = true;
                btnCreateKey.textContent = 'Generating...';

                try {
                    const resp = await fetch('/api/v1/keys', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + devSessionToken
                        },
                        body: JSON.stringify({ label: 'Production API Key ' + new Date().toLocaleTimeString(), is_live: true })
                    });
                    const data = await resp.json();

                    if (data.success && data.api_key) {
                        const banner = document.getElementById('new-key-banner');
                        const rawDisplay = document.getElementById('raw-key-display');
                        if (banner && rawDisplay) {
                            rawDisplay.textContent = data.api_key.raw_key;
                            banner.classList.remove('hidden');
                        }
                        loadDeveloperData();
                    }
                } catch (err) {
                    console.error('Failed to create key:', err);
                } finally {
                    btnCreateKey.disabled = false;
                    btnCreateKey.textContent = '+ Generate API Key';
                }
            });
        }
    }

    /**
     * Ensure developer session is active (register default test account if needed)
     */
    async function ensureDevSession() {
        if (devSessionToken) return devSessionToken;

        try {
            // Attempt login or register demo account
            let resp = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: 'developer@phishguard.ai', password: 'PhishGuardSecurePassword2026!' })
            });

            if (resp.status === 401) {
                // Register
                resp = await fetch('/api/v1/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: 'developer@phishguard.ai',
                        password: 'PhishGuardSecurePassword2026!',
                        full_name: 'Lead Developer',
                        plan_tier: 'free'
                    })
                });
            }

            const data = await resp.json();
            if (data.success && data.session_token) {
                devSessionToken = data.session_token;
                localStorage.setItem('phishguard_dev_token', devSessionToken);
            }
        } catch (err) {
            console.warn('Developer auto-session initialization failed:', err);
        }
        return devSessionToken;
    }

    /**
     * Load developer API keys and usage statistics
     */
    async function loadDeveloperData() {
        await ensureDevSession();
        if (!devSessionToken) return;

        // 1. Fetch keys
        try {
            const resp = await fetch('/api/v1/keys', {
                headers: { 'Authorization': 'Bearer ' + devSessionToken }
            });
            const data = await resp.json();

            if (data.success && Array.isArray(data.keys)) {
                renderKeysTable(data.keys);
            }
        } catch (err) {
            console.error('Failed to load keys:', err);
        }

        // 2. Fetch usage
        try {
            const resp = await fetch('/api/v1/user/usage', {
                headers: { 'Authorization': 'Bearer ' + devSessionToken }
            });
            const data = await resp.json();

            if (data.success && data.usage) {
                const u = data.usage;
                const countElem = document.getElementById('usage-count');
                const quotaElem = document.getElementById('usage-quota');
                const planBadge = document.getElementById('user-plan-badge');
                const fillElem = document.getElementById('usage-progress-fill');

                const used = u.scans_used_this_month || 0;

                if (countElem) countElem.textContent = used;
                if (quotaElem) quotaElem.textContent = "Unlimited";
                if (planBadge) planBadge.textContent = 'FULL DEVELOPER ACCESS';
                if (fillElem) {
                    fillElem.style.width = '100%';
                    fillElem.style.background = 'var(--green-primary)';
                }
            }
        } catch (err) {
            console.error('Failed to load usage:', err);
        }
    }

    /**
     * Render active API keys table rows
     */
    function renderKeysTable(keys) {
        const tbody = document.getElementById('api-keys-tbody');
        if (!tbody) return;

        if (keys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted); padding: 1rem;">No API keys generated yet. Click "+ Generate API Key" above.</td></tr>';
            return;
        }

        tbody.innerHTML = '';
        keys.forEach(k => {
            const tr = document.createElement('tr');

            const tdLabel = document.createElement('td');
            tdLabel.textContent = k.label || 'API Key';

            const tdPrefix = document.createElement('td');
            const spanPrefix = document.createElement('span');
            spanPrefix.className = 'key-mono';
            spanPrefix.textContent = k.key_prefix + '...';
            tdPrefix.appendChild(spanPrefix);

            const tdTier = document.createElement('td');
            const badgeTier = document.createElement('span');
            badgeTier.className = k.is_live ? 'badge badge-accent' : 'badge badge-warning';
            badgeTier.textContent = k.is_live ? 'Live' : 'Test';
            tdTier.appendChild(badgeTier);

            const tdCreated = document.createElement('td');
            tdCreated.textContent = (k.created_at || '').substring(0, 10) || 'Active';

            const tdAction = document.createElement('td');
            if (k.revoked) {
                const spanRev = document.createElement('span');
                spanRev.style.color = 'var(--text-muted)';
                spanRev.textContent = 'Revoked';
                tdAction.appendChild(spanRev);
            } else {
                const btnRevoke = document.createElement('button');
                btnRevoke.className = 'btn btn-danger btn-sm';
                btnRevoke.textContent = 'Revoke';
                btnRevoke.addEventListener('click', async () => {
                    if (confirm('Are you sure you want to revoke this API key?')) {
                        try {
                            const delResp = await fetch('/api/v1/keys/' + k.id, {
                                method: 'DELETE',
                                headers: { 'Authorization': 'Bearer ' + devSessionToken }
                            });
                            const delData = await delResp.json();
                            if (delData.success) {
                                loadDeveloperData();
                            }
                        } catch (err) {
                            alert('Failed to revoke key: ' + err.message);
                        }
                    }
                });
                tdAction.appendChild(btnRevoke);
            }

            tr.appendChild(tdLabel);
            tr.appendChild(tdPrefix);
            tr.appendChild(tdTier);
            tr.appendChild(tdCreated);
            tr.appendChild(tdAction);

            tbody.appendChild(tr);
        });
    }

    /**
     * Initialization routine on DOMContentLoaded
     */
    document.addEventListener('DOMContentLoaded', () => {
        attachEventListeners();
        fetchHealth();
        fetchHistory();
    });

})();
