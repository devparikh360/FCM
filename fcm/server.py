# server.py
from fastapi import FastAPI
from pydantic import BaseModel
from detection.engine import score_url, score_app, score_content
from fastapi.middleware.cors import CORSMiddleware

# --- Initialize app ---
app = FastAPI(title="FakeCatcherMan API")

# --- Enable CORS for local React frontend ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic models for input ---
class URLInput(BaseModel):
    url: str
    sector: str = "general"

class AppInput(BaseModel):
    url: str
    platform: str = "android"
    sector: str = "general"

class ContentInput(BaseModel):
    url: str
    sector: str = "general"

# --- Endpoints ---
@app.post("/detect/url")
def detect_url(data: URLInput):
    """
    Detect fraud for a URL
    """
    result = score_url(data.url, data.sector)
    return {"url": data.url, "result": result}  # <- wrap in "result"

@app.post("/detect/app")
def detect_app(data: AppInput):
    """
    Detect fraud for an app (APK or IPA)
    """
    result = score_app(data.url, platform=data.platform, sector=data.sector)
    return {"url": data.url, "result": result}  # <- wrap in "result"

@app.post("/detect/content")
def detect_content(data: ContentInput):
    """
    Detect fraud for uploaded content/file URL
    """
    result = score_content(data.url, data.sector)
    return {"url": data.url, "result": result}  # <- wrap in "result"

# --- Health check endpoint ---
@app.get("/health")
def health_check():
    return {"status": "OK", "message": "FakeCatcherMan API is running"}
