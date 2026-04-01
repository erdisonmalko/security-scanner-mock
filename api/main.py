# =========================
# api/main.py
# =========================

# =========================
# Run with:
# uvicorn api.main:app --reload
# =========================

from fastapi import FastAPI, HTTPException,UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sys
import tempfile
import os

# Allow import from cli folder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import scanners and config
from cli.security_scanner import (
    URLScanner, FileScanner, ScannerConfig, TextScanner
)
from cli.text_analyzer_hugging_face import SentimentAnalyzer
# -------------------------FASTAPI SETUP-------------------------
app = FastAPI(title="Security Scanner API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# -------------------------
# Request Schemas
# -------------------------

class URLScanRequest(BaseModel):
    url: str
    verbose: Optional[bool] = False

class FileScanRequest(BaseModel):
    file_path: str
    verbose: Optional[bool] = False

class TextScanRequest(BaseModel):
    text: str
    verbose: bool = False
# -------------------------
# Helpers
# -------------------------

def serialize_result(result):
    return {
        "is_safe": result.is_safe,
        "confidence": result.confidence,
        "threats": result.threats,
        "metadata": result.metadata
    }

def serialize_sentiment_result(result: dict):
    return {
        "sentiment": result.get("sentiment"),
        "confidence": result.get("confidence"),
        "provider": result.get("provider", "huggingface")
    }
# -------------------------
# Endpoints
# -------------------------

@app.get("/")
def root():
    return {"message": "Security Scanner API is running"}


@app.post("/scan/url")
def scan_url(req: URLScanRequest):
    try:
        config = ScannerConfig.from_env()
        config.verbose = req.verbose
        # test if we can access the config values
        print(f"Config loaded: google_safe_browsing={'SET' if config.google_api_key else 'NOT SET'}, verbose={config.verbose}")
        scanner = URLScanner(config)
        result = scanner.scan(req.url)
        print(f"Scan result for url(is_safe): {result.is_safe}")
        return serialize_result(result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    try:
        print(f"Received file scan request for: {file.filename}")
        print(f"Saving uploaded file to temp location: {file.filename}")
        # Save to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name
            print(f"Saved uploaded file to: {tmp_path}")

        # Use existing FileScanner
        config = ScannerConfig.from_env()
        print(f"Config loaded: virustotal_api_key={'SET' if config.virustotal_api_key else 'NOT SET'}, verbose={config.verbose}")
        scanner = FileScanner(config)
        result = scanner.scan(tmp_path)

        # Clean up temp file
        os.unlink(tmp_path)
        # confirm deletion
        print(f"Deleted temp file: {tmp_path}, exists: {os.path.exists(tmp_path)}")
        return serialize_result(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/openai/scan/text")
async def scan_text(req: TextScanRequest):
    try:
        config = ScannerConfig.from_env()
        config.verbose = req.verbose

        scanner = TextScanner(config)
        result = scanner.scan(req.text)

        return serialize_result(result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post("/huggingface/scan/text")
async def scan_text(req: TextScanRequest):
    try:
    
        scanner = SentimentAnalyzer(provider="huggingface")
        result = scanner.analyze(req.text)

        serialize_sentiment = serialize_sentiment_result(result)
        return serialize_sentiment

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
