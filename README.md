# Security Scanner

A free, open-source security scanning suite. Includes:

* **Link Checker** – Detect phishing URLs, typosquatting, suspicious TLDs.
* **File Scanner** – Detect dangerous extensions, double extensions, suspicious filenames.
* **Scam Text Detector** – Detect urgency, sensitive info requests, and suspicious URLs in text.

This repo contains a **FastAPI backend** for file scanning and a **web frontend** for local demo/interaction.

---

## Quick Start

### 1. Backend (FastAPI)

```bash
# create venv(recomaneded)
python3 -m venv .venv && source .venv/bin/activate

```bash
# Install dependencies
pip install -r requirements.txt

# Start server (default port 8000)
uvicorn api.main:app --reload
```

**Endpoints:**

* `POST /scan/file` – Upload a file to scan for threats (`multipart/form-data`).
* `POST /scan/url` – (Optional) Analyze URLs client-side or via optional APIs.
* `POST /scan/text` – (Optional) Analyze text for scam indicators.

**Example (Python client):**

```python
import requests

with open("example.exe", "rb") as f:
    res = requests.post("http://127.0.0.1:8000/scan/file", files={"file": f})
    print(res.json())
```

---

### 2. Web Frontend (Client)

1. Open `index.html` in a browser **or** serve locally:

```bash
python3 -m http.server 5500
```

2. Upload files, URLs, or text to see scanning results.
3. File uploads are sent to the FastAPI backend; URL and text analysis run locally by default.

**File Upload Example in JS:**

```javascript
const formData = new FormData();
formData.append("file", fileInput.files[0]);
const result = await apiRequest("/scan/file", formData);
```

---

### 3. CLI / Local Demo

* For quick local tests, the web frontend works standalone.
* For production scanning, run the FastAPI server and point the web tool at it via `API_BASE`.

---

## Features

* **File Analysis:** Extensions, double extensions, entropy, suspicious strings, basic PE structure checks.
* **URL Analysis:** Pattern matching for phishing indicators.
* **Text Analysis:** Scam/alert detection using client-side heuristics.
* **Optional API Integration:** VirusTotal, Google Safe Browsing, PhishTank, URLhaus.

---

## Development Notes

* Python backend: FastAPI + `python-multipart` for file uploads.
* Frontend: Vanilla JS/HTML/CSS.
* Future: Add AI-assisted text scanning, historical database, bulk scanning, and browser extension.

---

## License

MIT – Free to use, modify, and distribute.

---
