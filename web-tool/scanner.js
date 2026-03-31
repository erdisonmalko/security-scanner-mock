// =============================
// scanner.js (clean structure)
// =============================

const API_BASE = "http://localhost:8000";

// -----------------------------
// Utilities
// -----------------------------

// Updated apiRequest to handle JSON or FormData
async function apiRequest(endpoint, payload, isFormData = false) {
  try {
    const options = {
      method: "POST",
    };

    if (isFormData) {
      // payload is already FormData
      options.body = payload;
      // Let browser set Content-Type automatically
    } else {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify(payload);
    }

    const res = await fetch(`${API_BASE}${endpoint}`, options);

    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || "API error");
    }

    return await res.json();
  } catch (err) {
    console.error("API Error:", err);
    throw err;
  }
}

function setLoading(element, isLoading) {
  if (isLoading) {
    element.innerHTML = `
      <div class="loading">
        <div class="spinner"></div>
        <div>Scanning...</div>
      </div>
    `;
    element.classList.add("show");
  }
}

function renderResult(element, result) {
  element.classList.add("show");

  let statusClass = "safe";
  let title = "SAFE";

  if (!result.is_safe) {
    const hasCritical = result.threats.some(t => t.severity === "critical");
    statusClass = hasCritical ? "danger" : "warning";
    title = hasCritical ? "CRITICAL THREATS" : "WARNINGS DETECTED";
  }

  let html = `
    <div class="result-title">${title}</div>
    <div class="result-details">
      Confidence: ${(result.confidence * 100).toFixed(0)}%
    </div>
  `;

  if (result.threats.length > 0) {
    html += `<ul class="threat-list">`;

    result.threats.forEach(t => {
      html += `
        <li>
          <span class="badge ${t.severity}">${t.severity}</span>
          ${t.description}
        </li>
      `;
    });

    html += `</ul>`;
  }

  element.className = `result show ${statusClass}`;
  element.innerHTML = html;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function renderError(element, error) {
  element.className = "result show danger";
  element.innerHTML = `
    <div class="result-title">Error</div>
    <div class="result-details">${error.message}</div>
  `;
}

// -----------------------------
// URL Scanner
// -----------------------------

async function scanURL() {
  const input = document.getElementById("urlInput");
  const resultEl = document.getElementById("urlResult");

  const url = input.value.trim();
  if (!url) {
    renderError(resultEl, new Error("Please enter a URL"));
    return;
  }

  try {
    setLoading(resultEl, true);

    const result = await apiRequest("/scan/url", { url });
    renderResult(resultEl, result);

  } catch (err) {
    renderError(resultEl, err);
  }
}

// -----------------------------
// File Scanner (path-based)
// -----------------------------
async function scanFile() {
  const input = document.getElementById("fileInput");
  const resultEl = document.getElementById("fileResult");

  if (!input.files.length) {
    renderError(resultEl, new Error("Please select a file"));
    return;
  }

  const file = input.files[0];
  const formData = new FormData();
  formData.append("file", file);

  try {
    setLoading(resultEl, true);

    // Tell apiRequest this is a FormData request
    const result = await apiRequest("/scan/file", formData, true);

    renderResult(resultEl, result);
  } catch (err) {
    renderError(resultEl, err);
  }
}

// -----------------------------
// File input helper (optional)
// -----------------------------

function handleFileSelect(event) {
  const file = event.target.files[0];
  const fileNameEl = document.getElementById("fileName");
  const scanButton = document.getElementById("scanButton");

  if (file) {
    fileNameEl.textContent = `Selected: ${file.name}`;
    scanButton.disabled = false;  // enable button
  } else {
    fileNameEl.textContent = "";
    scanButton.disabled = true;   // disable if no file
  }
}

// ============================================
// 3. SCAM TEXT DETECTOR IMPLEMENTATION
// ============================================

async function analyzeText() {
    const textInput = document.getElementById('textInput');
    const resultDiv = document.getElementById('textResult');
    const text = textInput.value.trim();

    if (!text) {
        renderResult(resultDiv, 'warning', 'Please enter text', 'You need to provide text to analyze.');
        return;
    }

    setLoading(resultDiv, true);

    // Simulate API delay for now
    await delay(1800);

    // Run text analysis
    const analysis = analyzeTextForScams(text);

    const riskScore = analysis.threats.length;
    
    if (riskScore === 0) {
        renderResult(resultDiv, 'safe', '✅ Text appears legitimate', 
            'No obvious phishing patterns detected. However, always verify sender identity through official channels.');
    } else if (riskScore <= 2) {
        let threatHtml = '<ul class="threat-list">';
        analysis.threats.forEach(threat => {
            threatHtml += `<li><span class="badge ${threat.severity}">${threat.severity.toUpperCase()}</span> ${threat.description}</li>`;
        });
        threatHtml += '</ul>';
        
        renderResult(resultDiv, 'warning', '⚠️ Some suspicious elements detected', 
            'This message contains patterns commonly found in phishing attempts:' + threatHtml);
    } else {
        let threatHtml = '<ul class="threat-list">';
        analysis.threats.forEach(threat => {
            threatHtml += `<li><span class="badge ${threat.severity}">${threat.severity.toUpperCase()}</span> ${threat.description}</li>`;
        });
        threatHtml += '</ul>';
        
        renderResult(resultDiv, 'danger', '🚨 High risk of phishing/scam', 
            'This message shows multiple red flags typical of scam attempts:' + threatHtml);
    }
}

function analyzeTextForScams(text) {
    const threats = [];
    const lowerText = text.toLowerCase();

    // Extract URLs from text
    const urlRegex = /(https?:\/\/[^\s]+)/gi;
    const urls = text.match(urlRegex) || [];

    // Check for urgency language
    const urgencyPhrases = [
        'act now', 'urgent', 'immediate action', 'within 24 hours',
        'account will be closed', 'suspended', 'expire', 'limited time',
        'verify immediately', 'confirm now', 'update required',
        'unusual activity', 'suspicious activity', 'unauthorized'
    ];

    urgencyPhrases.forEach(phrase => {
        if (lowerText.includes(phrase)) {
            threats.push({
                severity: 'high',
                description: `Urgency tactic: "${phrase}" (pressure to act quickly)`
            });
        }
    });

    // Check for financial/personal info requests
    const sensitiveRequests = [
        'social security', 'ssn', 'password', 'pin code', 'credit card',
        'bank account', 'routing number', 'date of birth', 'mothers maiden',
        'verify your identity', 'confirm your details', 'update payment'
    ];

    sensitiveRequests.forEach(request => {
        if (lowerText.includes(request)) {
            threats.push({
                severity: 'high',
                description: `Requests sensitive information: "${request}"`
            });
        }
    });

    // Check for suspicious sender patterns
    const senderPatterns = [
        'dear customer', 'dear user', 'dear member', 'valued customer',
        'account holder', 'attention'
    ];

    senderPatterns.forEach(pattern => {
        if (lowerText.includes(pattern)) {
            threats.push({
                severity: 'medium',
                description: `Generic greeting: "${pattern}" (legitimate companies use your name)`
            });
        }
    });

    // Check for threats/consequences
    const threatPhrases = [
        'account will be closed', 'lose access', 'legal action',
        'charged', 'penalty', 'arrest', 'warrant', 'irs', 'tax authority'
    ];

    threatPhrases.forEach(phrase => {
        if (lowerText.includes(phrase)) {
            threats.push({
                severity: 'high',
                description: `Threatening language: "${phrase}" (scare tactic)`
            });
        }
    });

    // Check for reward/prize claims
    const rewardPhrases = [
        'congratulations', 'you won', 'winner', 'prize', 'claim your',
        'free gift', 'selected', 'lucky', 'refund'
    ];

    rewardPhrases.forEach(phrase => {
        if (lowerText.includes(phrase)) {
            threats.push({
                severity: 'medium',
                description: `Unsolicited reward claim: "${phrase}"`
            });
        }
    });

    // Analyze URLs in the message
    if (urls.length > 0) {
        urls.forEach(url => {
            try {
                const parsedUrl = new URL(url);
                const urlAnalysis = analyzeURLSecurity(parsedUrl);
                
                if (urlAnalysis.threats.length > 0) {
                    threats.push({
                        severity: 'high',
                        description: `Suspicious link detected: ${parsedUrl.hostname}`
                    });
                }
            } catch (e) {
                // Invalid URL
                threats.push({
                    severity: 'medium',
                    description: 'Malformed URL detected in text'
                });
            }
        });
    }

    // Check for poor grammar/spelling (not perfect but helps)
    const grammarIssues = [
        'kindly', 'needful', 'revert back', 'do the needful'
    ];

    grammarIssues.forEach(issue => {
        if (lowerText.includes(issue)) {
            threats.push({
                severity: 'low',
                description: `Unusual phrasing: "${issue}" (common in phishing from non-native speakers)`
            });
        }
    });

    // Check for excessive punctuation
    if ((text.match(/!!!/g) || []).length > 0 || (text.match(/\?\?\?/g) || []).length > 0) {
        threats.push({
            severity: 'low',
            description: 'Excessive punctuation (!!!  or ???) - unprofessional'
        });
    }

    return { threats };
}


// -----------------------------
// Init (optional future hooks)
// -----------------------------

function init() {
  console.log("Security Scanner UI initialized");
}

window.onload = init;
