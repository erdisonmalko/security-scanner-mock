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

function renderSentimentResult(element, result) {
  element.classList.add("show");
  let sentimentClass = "neutral";
  if (result.sentiment === "POSITIVE") sentimentClass = "safe";
  else if (result.sentiment === "NEGATIVE") sentimentClass = "danger";

  const html = `
    <div class="result-title">Sentiment: ${result.sentiment}</div>
    <div class="result-details">Confidence: ${(result.confidence * 100).toFixed(0)}%</div>
  `;

  element.className = `result show ${sentimentClass}`;
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
  const textInput = document.getElementById("textInput");
  const resultEl = document.getElementById("textResult");

  const text = textInput.value.trim();

  if (!text) {
    renderError(resultEl, new Error("Please enter text"));
    return;
  }

  try {
    setLoading(resultEl, true);

    const result = await apiRequest("/huggingface/scan/text", { text });
    renderSentimentResult(resultEl, result);

  } catch (err) {
    renderError(resultEl, err);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const textInput = document.getElementById("textInput");
  const analyzeBtn = document.getElementById("analyzeText");

  textInput.addEventListener("input", () => {
    analyzeBtn.disabled = textInput.value.trim().length === 0;
  });
});

// -----------------------------
// Init (optional future hooks)
// -----------------------------

function init() {
  console.log("Security Scanner UI initialized");
}

window.onload = init;
