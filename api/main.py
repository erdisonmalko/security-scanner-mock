# =========================
# api/main.py
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
from cli.security_scanner import URLScanner, FileScanner, ScannerConfig

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

# -------------------------
# Helpers
# -------------------------

def serialize_result(result):
    return {
        "is_safe": result.is_safe,
        "confidence": result.confidence,
        "threats": result.threats,
        "metadata": result.metadata,
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

        scanner = URLScanner(config)
        result = scanner.scan(req.url)

        return serialize_result(result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/file")
async def scan_file(file: UploadFile = File(...)):
    try:

        print(f"Saving uploaded file to temp location: {file.filename}")
        # Save to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name
            print(f"Saved uploaded file to: {tmp_path}")

        # Use existing FileScanner
        config = ScannerConfig.from_env()
        scanner = FileScanner(config)
        result = scanner.scan(tmp_path)

        # Clean up temp file
        os.unlink(tmp_path)
        # confirm deletion
        print(f"Deleted temp file: {tmp_path}, exists: {os.path.exists(tmp_path)}")
        return serialize_result(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =========================
# Run with:
# uvicorn api.main:app --reload
# =========================
