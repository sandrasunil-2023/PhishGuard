"""
PhishGuard - FastAPI Backend
Main application entry point.
"""

import os
import time
import hashlib
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl, field_validator
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv

from url_features import extract_features, features_to_vector, FEATURE_NAMES
from message_analyzer import analyze_message

# ─── Load environment variables ────────────────────────────────────────────────
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "phishguard")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishguard_model.pkl")

# ─── Global state ─────────────────────────────────────────────────────────────
model = None
db = None
scan_collection = None
stats_collection = None
message_collection = None


# ─── Lifespan (startup / shutdown) ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, db, scan_collection, stats_collection, message_collection

    # Load ML model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"[INFO] Model loaded from {MODEL_PATH}")
    else:
        print(f"[WARN] Model file not found at {MODEL_PATH}. Run train_model.py first.")

    # Connect to MongoDB
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        db = client[DATABASE_NAME]
        scan_collection = db["scans"]
        stats_collection = db["stats"]
        message_collection = db["message_scans"]
        # Indexes for fast lookups
        scan_collection.create_index("url_hash")
        scan_collection.create_index("timestamp")
        message_collection.create_index("timestamp")
        print(f"[INFO] MongoDB connected: {MONGODB_URI} / {DATABASE_NAME}")
    except ConnectionFailure as exc:
        print(f"[WARN] MongoDB unavailable ({exc}). Scans will not be persisted.")
        db = None

    yield  # ← Application runs here

    print("[INFO] PhishGuard shutting down.")


# ─── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="AI-powered phishing URL detection API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Schemas ───────────────────────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v


class MessageRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Message cannot be empty")
        if len(v) > 10000:
            raise ValueError("Message too long (max 10,000 chars)")
        return v


class BulkURLRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v: list) -> list:
        if not v:
            raise ValueError("URLs list cannot be empty")
        if len(v) > 20:
            raise ValueError("Maximum 20 URLs per bulk request")
        return [u.strip() for u in v if u.strip()]


class ScanResult(BaseModel):
    url: str
    prediction: str          # "phishing" | "legitimate"
    confidence: float        # 0.0 – 1.0
    risk_score: int          # 0 – 100
    features: dict
    top_indicators: list[str]
    scan_id: str
    timestamp: str
    cached: bool


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _is_recent_scan(scan: dict, max_age_seconds: int = 600) -> bool:
    """Return whether a stored scan is recent enough to reuse safely."""
    try:
        timestamp = datetime.fromisoformat(scan["timestamp"].replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - timestamp).total_seconds() < max_age_seconds
    except (KeyError, TypeError, ValueError):
        return False


def _get_top_indicators(features: dict, prediction: str) -> list[str]:
    """Generate human-readable risk indicators from features."""
    indicators = []

    if features.get("has_ip_address"):
        indicators.append("Uses raw IP address instead of domain name")
    if features.get("is_https") == 0:
        indicators.append("Not using HTTPS (insecure connection)")
    if features.get("suspicious_tld"):
        indicators.append("Suspicious or free TLD (e.g. .tk, .xyz, .ml)")
    if features.get("brand_not_in_domain"):
        indicators.append("Brand name in URL but not in actual domain (impersonation)")
    if features.get("count_dots", 0) > 5:
        indicators.append(f"Unusually many dots in URL ({features['count_dots']})")
    if features.get("count_hyphens", 0) > 4:
        indicators.append(f"Many hyphens in URL ({features['count_hyphens']})")
    if features.get("url_length", 0) > 100:
        indicators.append(f"Very long URL ({features['url_length']} chars)")
    if features.get("has_suspicious_keyword"):
        indicators.append("Contains suspicious keywords (e.g. login, verify, secure)")
    if features.get("is_url_shortener"):
        indicators.append("URL shortener detected (hides real destination)")
    if features.get("has_encoded_chars"):
        indicators.append("URL-encoded characters present (obfuscation)")
    if features.get("count_at", 0) > 0:
        indicators.append("@ symbol in URL (can redirect to malicious host)")
    if features.get("has_redirect"):
        indicators.append("Redirect parameter detected in URL")
    if features.get("double_slash_in_path"):
        indicators.append("Double slash in path (suspicious structure)")
    if features.get("subdomain_count", 0) > 3:
        indicators.append(f"Many subdomains ({features['subdomain_count']}) — common in phishing")
    if features.get("domain_entropy", 0) > 4.0:
        indicators.append("High domain entropy (likely randomly generated domain)")
    if features.get("has_port"):
        indicators.append("Non-standard port in URL")

    # If legit and no indicators found
    if not indicators and prediction == "legitimate":
        indicators.append("No suspicious signals detected")
        indicators.append("HTTPS secure connection")
        indicators.append("Recognized domain structure")

    return indicators[:6]  # Return top 6


def _predict(url: str) -> dict:
    """Run ML prediction on a URL."""
    features = extract_features(url)
    vector = features_to_vector(features)
    X = np.array([vector], dtype=float)

    if model is not None:
        proba = model.predict_proba(X)[0]
        phish_prob = float(proba[1])
        legit_prob = float(proba[0])
        prediction = "phishing" if phish_prob >= 0.5 else "legitimate"
        confidence = phish_prob if prediction == "phishing" else legit_prob
    else:
        # Fallback heuristic when model not loaded
        phish_signals = sum([
            features.get("has_ip_address", 0),
            features.get("is_https", 1) == 0,
            features.get("suspicious_tld", 0),
            features.get("brand_not_in_domain", 0),
            features.get("is_url_shortener", 0),
            features.get("has_suspicious_keyword", 0),
            1 if features.get("url_length", 0) > 100 else 0,
            1 if features.get("count_hyphens", 0) > 3 else 0,
            1 if features.get("count_dots", 0) > 5 else 0,
            features.get("has_redirect", 0),
        ])
        # Three independent structural signals (for example plain HTTP, a
        # suspicious TLD, and credential language) are enough to flag a URL
        # before a trained model is available.
        phish_prob = min(0.95, 0.15 + phish_signals * 0.18)
        legit_prob = 1 - phish_prob
        prediction = "phishing" if phish_signals >= 3 else "legitimate"
        confidence = phish_prob if prediction == "phishing" else legit_prob

    risk_score = int(phish_prob * 100)
    indicators = _get_top_indicators(features, prediction)

    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "risk_score": risk_score,
        "features": features,
        "top_indicators": indicators,
    }


def _save_scan(url: str, result: dict) -> str:
    """Persist scan result to MongoDB. Returns scan_id."""
    scan_id = _url_hash(url + str(time.time()))[:16]
    if scan_collection is not None:
        doc = {
            "scan_id": scan_id,
            "url": url,
            "url_hash": _url_hash(url),
            "prediction": result["prediction"],
            "confidence": result["confidence"],
            "risk_score": result["risk_score"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            scan_collection.insert_one(doc)
        except Exception as e:
            print(f"[WARN] Failed to save scan: {e}")
    return scan_id


# ─── Routes ────────────────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "PhishGuard API",
        "version": "1.0.0",
        "status": "online",
        "model_loaded": model is not None,
        "db_connected": db is not None,
    }


@app.get("/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "db_connected": db is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan", tags=["Scan"])
async def scan_url(request: URLRequest):
    """
    Scan a single URL for phishing indicators.
    Returns prediction, confidence, risk score, and top indicators.
    """
    url = request.url

    # Check cache (same URL scanned in last 10 minutes)
    cached_doc = None
    if scan_collection is not None:
        url_hash = _url_hash(url)
        cached_doc = scan_collection.find_one(
            {"url_hash": url_hash},
            sort=[("timestamp", -1)]
        )

    if cached_doc and _is_recent_scan(cached_doc):
        # Re-extract features for full response (not stored)
        features = extract_features(url)
        indicators = _get_top_indicators(features, cached_doc["prediction"])
        return {
            "url": url,
            "prediction": cached_doc["prediction"],
            "confidence": cached_doc["confidence"],
            "risk_score": cached_doc["risk_score"],
            "features": features,
            "top_indicators": indicators,
            "scan_id": cached_doc["scan_id"],
            "timestamp": cached_doc["timestamp"],
            "cached": True,
        }

    # Fresh prediction
    result = _predict(url)
    scan_id = _save_scan(url, result)

    return {
        "url": url,
        "prediction": result["prediction"],
        "confidence": result["confidence"],
        "risk_score": result["risk_score"],
        "features": result["features"],
        "top_indicators": result["top_indicators"],
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cached": False,
    }


@app.post("/api/scan/bulk", tags=["Scan"])
async def scan_bulk(request: BulkURLRequest):
    """
    Scan up to 20 URLs at once.
    """
    results = []
    for url in request.urls:
        try:
            result = _predict(url)
            scan_id = _save_scan(url, result)
            results.append({
                "url": url,
                "prediction": result["prediction"],
                "confidence": result["confidence"],
                "risk_score": result["risk_score"],
                "top_indicators": result["top_indicators"],
                "scan_id": scan_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": None,
            })
        except Exception as e:
            results.append({
                "url": url,
                "prediction": None,
                "confidence": None,
                "risk_score": None,
                "top_indicators": [],
                "scan_id": None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e),
            })
    return {"results": results, "total": len(results)}


@app.get("/api/history", tags=["History"])
async def get_history(limit: int = 20, skip: int = 0):
    """
    Retrieve recent scan history from the database.
    """
    if scan_collection is None:
        return {"scans": [], "total": 0, "message": "Database not connected"}

    total = scan_collection.count_documents({})
    cursor = scan_collection.find(
        {}, {"_id": 0}
    ).sort("timestamp", -1).skip(skip).limit(limit)
    scans = list(cursor)
    return {"scans": scans, "total": total}


@app.get("/api/stats", tags=["Stats"])
async def get_stats():
    """
    Aggregate statistics: total scans, phishing ratio, top risk domains.
    """
    if scan_collection is None:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "legitimate_count": 0,
            "phishing_ratio": 0.0,
            "message": "Database not connected",
        }

    total = scan_collection.count_documents({})
    phishing = scan_collection.count_documents({"prediction": "phishing"})
    legitimate = total - phishing

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "legitimate_count": legitimate,
        "phishing_ratio": round(phishing / total, 4) if total > 0 else 0.0,
    }


@app.delete("/api/history", tags=["History"])
async def clear_history():
    """Clear URL and message scan history from the database."""
    if scan_collection is None and message_collection is None:
        raise HTTPException(status_code=503, detail="Database not connected")
    url_deleted = scan_collection.delete_many({}).deleted_count if scan_collection is not None else 0
    message_deleted = message_collection.delete_many({}).deleted_count if message_collection is not None else 0
    return {
        "deleted": url_deleted + message_deleted,
        "url_scans_deleted": url_deleted,
        "message_scans_deleted": message_deleted,
        "message": "History cleared",
    }


# ─── /check-url alias (matches project spec naming) ───────────────────────────
@app.post("/check-url", tags=["Scan"])
async def check_url(request: URLRequest):
    """
    Alias for /api/scan — scan a URL for phishing. Matches project spec endpoint name.
    """
    return await scan_url(request)


# ─── Social Engineering Message Detector ──────────────────────────────────────
@app.post("/check-message", tags=["Message"])
async def check_message(request: MessageRequest):
    """
    Analyze a message or email body for social engineering tactics.
    Returns verdict, risk score, warning signs, and detected manipulation categories.
    """
    result = analyze_message(request.message)

    scan_id = _url_hash(request.message[:64] + str(time.time()))[:16]

    # Save to MongoDB (store only metadata, not full message content)
    if message_collection is not None:
        doc = {
            "scan_id": scan_id,
            "scan_type": "message",
            "message_preview": request.message[:80] + ("…" if len(request.message) > 80 else ""),
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "categories_triggered": result.categories_triggered,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            message_collection.insert_one(doc)
        except Exception as e:
            print(f"[WARN] Failed to save message scan: {e}")

    return {
        "scan_type": "message",
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "categories_triggered": result.categories_triggered,
        "warning_signs": result.warning_signs,
        "statistics": {
            "word_count": result.word_count,
            "has_urls": result.has_urls,
            "url_count": result.url_count,
            "caps_ratio": result.caps_ratio,
            "exclamation_count": result.exclamation_count,
        },
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/message-history", tags=["Message"])
async def get_message_history(limit: int = 20, skip: int = 0):
    """
    Retrieve recent message scan history.
    """
    if message_collection is None:
        return {"scans": [], "total": 0, "message": "Database not connected"}

    total = message_collection.count_documents({})
    cursor = message_collection.find(
        {}, {"_id": 0}
    ).sort("timestamp", -1).skip(skip).limit(limit)
    scans = list(cursor)
    return {"scans": scans, "total": total}


@app.get("/api/stats", tags=["Stats"], include_in_schema=False)
async def get_stats_extended():
    """
    Extended stats including both URL and message scans.
    """
    url_total = scan_collection.count_documents({}) if scan_collection is not None else 0
    url_phish = scan_collection.count_documents({"prediction": "phishing"}) if scan_collection is not None else 0
    msg_total = message_collection.count_documents({}) if message_collection is not None else 0
    msg_danger = message_collection.count_documents({"verdict": "dangerous"}) if message_collection is not None else 0
    msg_suspicious = message_collection.count_documents({"verdict": "suspicious"}) if message_collection is not None else 0

    return {
        "url_scans": {
            "total": url_total,
            "phishing_count": url_phish,
            "legitimate_count": url_total - url_phish,
            "phishing_ratio": round(url_phish / url_total, 4) if url_total > 0 else 0.0,
        },
        "message_scans": {
            "total": msg_total,
            "dangerous_count": msg_danger,
            "suspicious_count": msg_suspicious,
            "safe_count": msg_total - msg_danger - msg_suspicious,
        },
        "combined_total": url_total + msg_total,
    }
