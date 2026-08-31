import os
import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any

from feature_extractor import extract_features, FEATURE_NAMES
import database

# Initialize Database tables
database.init_db()

app = FastAPI(
    title="Live Phishing Detection System API",
    description="Real-Time Phishing Detection Engine powered by Scikit-Learn Random Forest Classifier & Manifest V3 Chrome Extension",
    version="1.0.0"
)

# Enable CORS for Chrome Extension background & content scripts
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load Trained ML Model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_rf_model.pkl")
model_data = None
rf_model = None

def load_ml_model():
    global model_data, rf_model
    if os.path.exists(MODEL_PATH):
        try:
            model_data = joblib.load(MODEL_PATH)
            rf_model = model_data["model"]
            print("Successfully loaded Random Forest ML model!")
        except Exception as e:
            print(f"Error loading model: {e}")
    else:
        print("Model file not found. Running training script automatically...")
        from train_model import train_and_save_model
        model_data = train_and_save_model()
        rf_model = model_data["model"]

load_ml_model()

# --- Pydantic Schemas ---
class PredictRequest(BaseModel):
    url: str

class WhitelistRequest(BaseModel):
    domain: str

class ReportRequest(BaseModel):
    url: str
    comments: Optional[str] = None

# --- API Endpoints ---

@app.get("/")
def read_root():
    return {
        "system": "Live Phishing Detection Engine",
        "status": "Online",
        "model_loaded": rf_model is not None,
        "model_accuracy": f"{model_data.get('accuracy', 0) * 100:.1f}%" if model_data else "N/A"
    }

@app.post("/api/v1/predict")
def predict_url_phishing(request: PredictRequest):
    """
    Main endpoint used by Chrome Extension to analyze an active web URL in real-time.
    Calculates feature vector, checks whitelist, predicts risk probability, and returns classification.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    extracted = extract_features(url)
    domain = extracted["domain"]
    feature_vector = extracted["feature_vector"]
    breakdown = extracted["breakdown"]

    # 1. Check Whitelist
    if database.is_whitelisted(domain):
        classification = "Safe"
        risk_score = 0.0
        confidence = 100.0
        is_whitelisted_domain = True
        breakdown.insert(0, {"feature": "Trusted Whitelist", "risk": "Safe", "detail": f"{domain} is in custom trusted whitelist"})
    else:
        is_whitelisted_domain = False
        if rf_model is not None:
            # Predict probability using Random Forest
            X_input = np.array([feature_vector])
            probabilities = rf_model.predict_proba(X_input)[0]
            # Probability of Class 1 (Phishing)
            phishing_prob = float(probabilities[1])
            risk_score = round(phishing_prob * 100.0, 1)

            # Assign Classification Status
            if risk_score >= 60.0:
                classification = "Phishing"
            elif risk_score >= 30.0:
                classification = "Suspicious"
            else:
                classification = "Safe"
            
            confidence = round(float(np.max(probabilities)) * 100.0, 1)
        else:
            # Fallback heuristic calculation if model not available
            risk_score = min(100.0, len(breakdown) * 25.0)
            classification = "Phishing" if risk_score >= 60 else ("Suspicious" if risk_score >= 35 else "Safe")
            confidence = 80.0

    # Log scan result in SQLite
    database.log_scan(url, domain, risk_score, classification)

    return {
        "url": url,
        "domain": domain,
        "classification": classification,
        "risk_score": risk_score,
        "confidence": confidence,
        "is_whitelisted": is_whitelisted_domain,
        "extracted_features": extracted["features"],
        "breakdown": breakdown
    }

@app.get("/api/v1/whitelist")
def get_whitelisted_domains():
    """Retrieve all whitelisted domains."""
    return {"whitelist": database.get_whitelist()}

@app.post("/api/v1/whitelist")
def add_whitelisted_domain(request: WhitelistRequest):
    """Add a new domain to the custom whitelist."""
    domain = request.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty")
    success = database.add_to_whitelist(domain)
    if not success:
        return {"status": "already_exists", "message": f"{domain} is already whitelisted"}
    return {"status": "success", "message": f"{domain} added to whitelist"}

@app.delete("/api/v1/whitelist/{domain}")
def remove_whitelisted_domain(domain: str):
    """Remove a domain from the custom whitelist."""
    success = database.remove_from_whitelist(domain)
    if not success:
        raise HTTPException(status_code=404, detail="Domain not found in whitelist")
    return {"status": "success", "message": f"{domain} removed from whitelist"}

@app.post("/api/v1/report")
def report_phishing_site(request: ReportRequest):
    """Submit a misclassified or suspicious site for admin review/retraining."""
    url = request.url.strip()
    extracted = extract_features(url)
    report_id = database.create_report(url, extracted["domain"], request.comments)
    return {
        "status": "success",
        "report_id": report_id,
        "message": "Phishing site reported successfully for review"
    }

@app.get("/api/v1/reports")
def get_user_reports():
    """Get list of user-reported phishing sites."""
    return {"reports": database.get_reports()}

@app.get("/api/v1/history")
def get_history_logs(limit: int = Query(50, ge=1, le=200)):
    """Retrieve scanned history logs."""
    return {"history": database.get_scan_history(limit=limit)}

@app.get("/api/v1/stats")
def get_dashboard_stats():
    """Get overall detection statistics for dashboard widgets."""
    return database.get_stats()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
