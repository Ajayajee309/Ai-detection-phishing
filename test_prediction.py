"""
=====================================================================
  AI-Based Phishing Detection - Prediction Test Script
  File: test_prediction.py
  Description: Quick test script to verify model loading and
               make sample predictions without starting the Flask app.
               Run after training the model.
=====================================================================
"""

import os
import sys
import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_extractor import extract_features, get_feature_names

MODEL_PATH  = os.path.join("model", "model.pkl")
SCALER_PATH = os.path.join("model", "scaler.pkl")

# ─── Test URLs ────────────────────────────────────────────────────
TEST_URLS = [
    # Legitimate
    ("https://www.google.com/search?q=python",          0),
    ("https://www.amazon.com/products",                 0),
    ("https://github.com/user/repository",              0),
    ("https://stackoverflow.com/questions/12345",       0),

    # Phishing
    ("http://paypal-verify-account-12345.tk/secure-login",  1),
    ("http://192.168.1.1/admin/login?user=admin",           1),
    ("http://amazon-prize-winner-abc123.xyz/claim",         1),
    ("http://user@google-security-alert.pw/verify",         1),
]


def predict(model, scaler, url: str) -> dict:
    """Run prediction for a single URL."""
    features_dict   = extract_features(url)
    feature_names   = get_feature_names()
    feature_vector  = np.array([[features_dict[f] for f in feature_names]])
    scaled_vector   = scaler.transform(feature_vector)
    prediction      = model.predict(scaled_vector)[0]
    proba           = model.predict_proba(scaled_vector)[0]
    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "phishing_prob": round(proba[1] * 100, 2),
        "legit_prob":    round(proba[0] * 100, 2),
    }


def main():
    print("\n" + "=" * 70)
    print("  PHISHGUARD AI – MODEL PREDICTION TEST")
    print("=" * 70)

    # Load model
    if not os.path.exists(MODEL_PATH):
        print(f"\n[ERROR] Model not found at '{MODEL_PATH}'")
        print("Run: python model/train_model.py first\n")
        return

    print("\n[INFO] Loading model...")
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("[INFO] Model loaded successfully!\n")

    # Run predictions
    correct = 0
    results_table = []

    for url, true_label in TEST_URLS:
        result = predict(model, scaler, url)
        pred_label = 1 if result["prediction"] == "Phishing" else 0
        is_correct = pred_label == true_label
        if is_correct:
            correct += 1

        results_table.append({
            "url":      url[:55] + "…" if len(url) > 55 else url,
            "expected": "Phishing" if true_label == 1 else "Legitimate",
            "predicted": result["prediction"],
            "confidence": f"{max(result['phishing_prob'], result['legit_prob']):.1f}%",
            "correct":  "✓" if is_correct else "✗"
        })

    # Print table
    print(f"{'URL':<58} {'Expected':<12} {'Predicted':<12} {'Conf':<8} {'OK?'}")
    print("-" * 95)
    for r in results_table:
        print(f"{r['url']:<58} {r['expected']:<12} {r['predicted']:<12} {r['confidence']:<8} {r['correct']}")

    print("-" * 95)
    accuracy = correct / len(TEST_URLS) * 100
    print(f"\nTest Accuracy: {correct}/{len(TEST_URLS)} = {accuracy:.1f}%")
    print("\n✅ All tests passed!" if correct == len(TEST_URLS) else f"\n⚠️  {len(TEST_URLS)-correct} incorrect predictions")
    print()


if __name__ == "__main__":
    main()
