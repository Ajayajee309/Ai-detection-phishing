"""
=====================================================================
  AI-Based Phishing Attack Detection - Flask Application
  File: app.py
  Description: Flask web server that serves the frontend and exposes
               a REST API endpoint for phishing URL prediction.
               Loads the pre-trained Random Forest model and returns
               prediction results with confidence and risk level.
=====================================================================
"""

import os
import re
import sys
import joblib
import numpy as np
from flask import Flask, request, jsonify, render_template

# ─── Add project root to sys.path ─────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_extractor import extract_features, get_feature_names


# ─── Flask App Setup ──────────────────────────────────────────────
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_SORT_KEYS"] = False


# ─── Model & Scaler Paths ─────────────────────────────────────────
MODEL_PATH  = os.path.join("model", "model.pkl")
SCALER_PATH = os.path.join("model", "scaler.pkl")

# ─── Load Model at Startup ────────────────────────────────────────
model  = None
scaler = None


def load_model():
    """Load the Random Forest model and scaler from disk."""
    global model, scaler
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at '{MODEL_PATH}'.\n"
            "Run: python model/train_model.py"
        )
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"Scaler not found at '{SCALER_PATH}'.\n"
            "Run: python model/train_model.py"
        )
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print(f"[INFO] Model loaded from  → {MODEL_PATH}")
    print(f"[INFO] Scaler loaded from → {SCALER_PATH}")


# ─── Helper Functions ─────────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate the URL format.
    Returns (is_valid, error_message).
    """
    if not url or not url.strip():
        return False, "URL cannot be empty."

    url = url.strip()

    # Check minimum length
    if len(url) < 4:
        return False, "URL is too short."

    # Check maximum length
    if len(url) > 2048:
        return False, "URL is too long (max 2048 characters)."

    # Add protocol if missing for validation
    check_url = url if url.startswith(("http://", "https://")) else "http://" + url

    # Basic URL pattern check
    url_pattern = re.compile(
        r"^(https?://)?"                     # Protocol (optional)
        r"(\d{1,3}\.){3}\d{1,3}"            # IP address
        r"|"
        r"^(https?://)?"                     # Protocol (optional)
        r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"  # Subdomain
        r"+[a-zA-Z]{2,}"                     # TLD
        r"(:\d+)?(/.*)?$",                   # Port + Path
        re.IGNORECASE
    )

    # A simpler check — just ensure it has at least a dot
    if "." not in check_url.split("?")[0]:
        return False, "Please enter a valid URL (e.g., https://example.com)."

    return True, ""


def determine_risk_level(confidence: float, is_phishing: bool) -> dict:
    """
    Determine risk level and provide security recommendation
    based on the model's confidence score.

    Args:
        confidence: Model's confidence (0.0 to 1.0)
        is_phishing: True if classified as phishing

    Returns:
        dict with risk_level, risk_color, and recommendation
    """
    if not is_phishing:
        if confidence >= 0.85:
            return {
                "risk_level": "Low",
                "risk_color": "green",
                "risk_icon": "shield-check",
                "recommendation": (
                    "This URL appears to be safe. The website shows strong "
                    "indicators of legitimacy. Always verify the site before "
                    "entering sensitive information."
                )
            }
        else:
            return {
                "risk_level": "Low-Medium",
                "risk_color": "blue",
                "risk_icon": "shield",
                "recommendation": (
                    "This URL appears mostly safe but has some ambiguous features. "
                    "Exercise standard caution when browsing and avoid entering "
                    "sensitive information unless you trust the source."
                )
            }
    else:
        if confidence >= 0.80:
            return {
                "risk_level": "High",
                "risk_color": "red",
                "risk_icon": "shield-x",
                "recommendation": (
                    "⚠️ HIGH RISK: This URL shows strong phishing indicators! "
                    "Do NOT visit this website, enter any credentials, or click "
                    "any links. Report this URL to your organization's security team "
                    "and to Anti-Phishing authorities (e.g., reportphishing@apwg.org)."
                )
            }
        else:
            return {
                "risk_level": "Medium",
                "risk_color": "orange",
                "risk_icon": "shield-alert",
                "recommendation": (
                    "⚠️ CAUTION: This URL shows some phishing characteristics. "
                    "Avoid entering personal or financial information. "
                    "Verify the website independently before proceeding. "
                    "Check for HTTPS, correct spelling, and domain legitimacy."
                )
            }


def analyze_url_features(url: str, features: dict) -> list:
    """
    Generate human-readable feature analysis for display.
    Returns a list of analyzed feature objects.
    """
    analysis = []

    # HTTPS Check
    analysis.append({
        "name": "HTTPS Protocol",
        "value": "Yes" if features["uses_https"] else "No",
        "status": "safe" if features["uses_https"] else "warning",
        "description": "Secure connection used" if features["uses_https"]
                       else "No SSL/TLS encryption detected"
    })

    # IP Address
    analysis.append({
        "name": "IP Address in URL",
        "value": "Detected" if features["has_ip_address"] else "Not Found",
        "status": "danger" if features["has_ip_address"] else "safe",
        "description": "Phishing indicator: IP instead of domain"
                       if features["has_ip_address"]
                       else "Domain name used (normal)"
    })

    # @ Symbol
    analysis.append({
        "name": "@ Symbol in URL",
        "value": "Detected" if features["has_at_symbol"] else "Not Found",
        "status": "danger" if features["has_at_symbol"] else "safe",
        "description": "Phishing trick: browser ignores text before @"
                       if features["has_at_symbol"]
                       else "No suspicious @ symbol"
    })

    # URL Length
    url_len = features["url_length"]
    url_len_status = "safe" if url_len < 54 else ("warning" if url_len < 75 else "danger")
    analysis.append({
        "name": "URL Length",
        "value": f"{url_len} characters",
        "status": url_len_status,
        "description": "Normal length" if url_len < 54
                       else ("Moderately long" if url_len < 75 else "Suspiciously long URL")
    })

    # Dots Count
    dots = features["count_dots"]
    analysis.append({
        "name": "Dot Count",
        "value": str(dots),
        "status": "safe" if dots <= 3 else ("warning" if dots <= 5 else "danger"),
        "description": "Normal subdomain depth" if dots <= 3
                       else "Many subdomains detected (possible phishing)"
    })

    # Suspicious Keywords
    kw_count = features["count_suspicious_keywords"]
    analysis.append({
        "name": "Suspicious Keywords",
        "value": str(kw_count),
        "status": "safe" if kw_count == 0 else ("warning" if kw_count <= 2 else "danger"),
        "description": "No suspicious keywords found" if kw_count == 0
                       else f"{kw_count} phishing keyword(s) detected"
    })

    # Suspicious TLD
    analysis.append({
        "name": "Domain Extension (TLD)",
        "value": "Suspicious" if features["has_suspicious_tld"] else "Normal",
        "status": "danger" if features["has_suspicious_tld"] else "safe",
        "description": "High-risk TLD commonly used in phishing"
                       if features["has_suspicious_tld"]
                       else "TLD appears legitimate"
    })

    # Hyphens
    hyphens = features["count_hyphens"]
    analysis.append({
        "name": "Hyphens in Domain",
        "value": str(hyphens),
        "status": "safe" if hyphens <= 1 else ("warning" if hyphens <= 3 else "danger"),
        "description": "Normal" if hyphens <= 1
                       else "Excessive hyphens (common phishing pattern)"
    })

    return analysis


# ─── Routes ───────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main frontend page."""
    return render_template("index.html")


@app.route("/api/predict", methods=["POST"])
def predict():
    """
    POST /api/predict
    Body: { "url": "https://example.com" }
    Returns: JSON with prediction, confidence, risk level, and features
    """
    # ─── Parse request ────────────────────────────────────────────
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid JSON body."}), 400

    url = data.get("url", "").strip()

    # ─── Validate URL ─────────────────────────────────────────────
    is_valid, error_msg = validate_url(url)
    if not is_valid:
        return jsonify({"success": False, "error": error_msg}), 422

    # ─── Check model is loaded ────────────────────────────────────
    if model is None or scaler is None:
        return jsonify({
            "success": False,
            "error": "Model not loaded. Please train the model first."
        }), 503

    try:
        # ─── Extract features ─────────────────────────────────────
        features_dict = extract_features(url)
        feature_names = get_feature_names()
        feature_vector = np.array([[features_dict[f] for f in feature_names]])

        # ─── Scale features ───────────────────────────────────────
        feature_vector_scaled = scaler.transform(feature_vector)

        # ─── Predict ──────────────────────────────────────────────
        prediction    = model.predict(feature_vector_scaled)[0]
        probabilities = model.predict_proba(feature_vector_scaled)[0]

        is_phishing  = bool(prediction == 1)
        confidence   = float(max(probabilities))
        phish_prob   = float(probabilities[1])
        legit_prob   = float(probabilities[0])

        # ─── Risk assessment ──────────────────────────────────────
        risk_info = determine_risk_level(confidence, is_phishing)

        # ─── Feature analysis ─────────────────────────────────────
        feature_analysis = analyze_url_features(url, features_dict)

        # ─── Build response ───────────────────────────────────────
        response = {
            "success":          True,
            "url":              url,
            "prediction":       "Phishing" if is_phishing else "Legitimate",
            "is_phishing":      is_phishing,
            "confidence":       round(confidence * 100, 2),
            "phishing_prob":    round(phish_prob * 100, 2),
            "legitimate_prob":  round(legit_prob * 100, 2),
            "risk_level":       risk_info["risk_level"],
            "risk_color":       risk_info["risk_color"],
            "risk_icon":        risk_info["risk_icon"],
            "recommendation":   risk_info["recommendation"],
            "feature_analysis": feature_analysis,
            "raw_features":     features_dict
        }

        return jsonify(response), 200

    except Exception as e:
        app.logger.error(f"Prediction error for URL '{url}': {str(e)}")
        return jsonify({
            "success": False,
            "error": f"An error occurred during analysis: {str(e)}"
        }), 500


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        "status":       "healthy",
        "model_loaded": model is not None,
        "app":          "AI Phishing Detection"
    }), 200


@app.route("/api/features", methods=["GET"])
def features():
    """Returns the list of features used by the model."""
    return jsonify({
        "features": get_feature_names(),
        "count":    len(get_feature_names())
    }), 200


# ─── Main Entry Point ─────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  AI-BASED PHISHING DETECTION - WEB APPLICATION")
    print("=" * 60)

    try:
        load_model()
        print("[INFO] Starting Flask server at http://127.0.0.1:5000\n")
        app.run(
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False
        )
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}\n")
        sys.exit(1)
