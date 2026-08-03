"""
=====================================================================
  AI-Based Phishing Attack Detection - Model Trainer
  File: model/train_model.py
  Description: Trains a Random Forest classifier on the phishing
               dataset, evaluates its performance, and saves the
               trained model as model.pkl using joblib.
=====================================================================
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, roc_auc_score
)
from sklearn.preprocessing import StandardScaler

# ─── Add project root to path ─────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.feature_extractor import extract_features, get_feature_names


# ─── Configuration ────────────────────────────────────────────────
DATASET_PATH  = os.path.join("dataset", "phishing_dataset.csv")
MODEL_DIR     = "model"
MODEL_PATH    = os.path.join(MODEL_DIR, "model.pkl")
SCALER_PATH   = os.path.join(MODEL_DIR, "scaler.pkl")
TEST_SIZE     = 0.20      # 80% train / 20% test split
RANDOM_STATE  = 42


def load_dataset(path: str) -> pd.DataFrame:
    """Load and validate the dataset CSV."""
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Dataset not found at '{path}'.\n"
            "Please run: python dataset/generate_dataset.py"
        )
    df = pd.read_csv(path)
    print(f"[INFO] Loaded dataset: {df.shape[0]} rows, {df.shape[1]} columns")
    print(f"[INFO] Label distribution:\n{df['label'].value_counts().to_string()}\n")
    return df


def extract_all_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply feature extraction to every URL in the dataset.
    Returns a DataFrame of features.
    """
    print("[INFO] Extracting features from URLs (this may take a moment)...")
    feature_list = []

    for i, url in enumerate(df["url"]):
        if i % 500 == 0:
            print(f"[INFO] Processed {i}/{len(df)} URLs")
        try:
            features = extract_features(str(url))
        except Exception as e:
            print(f"  [WARN] Skipping URL {i}: {e}")
            features = {k: 0 for k in get_feature_names()}
        feature_list.append(features)

    features_df = pd.DataFrame(feature_list)
    print(f"[INFO] Feature extraction complete. Shape: {features_df.shape}\n")
    return features_df


def train_model(X_train, y_train) -> RandomForestClassifier:
    """
    Train a Random Forest classifier with optimized hyperparameters.
    Random Forest is chosen for:
      - High accuracy on tabular data
      - Resistance to overfitting
      - Feature importance insights
      - No need for feature scaling (built-in)
    """
    print("[INFO] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=200,           # Number of decision trees
        max_depth=15,               # Prevent overfitting
        min_samples_split=5,        # Minimum samples to split a node
        min_samples_leaf=2,         # Minimum samples at leaf node
        max_features="sqrt",        # Features per split (sqrt for classification)
        class_weight="balanced",    # Handle class imbalance
        random_state=RANDOM_STATE,
        n_jobs=-1                   # Use all CPU cores
    )
    model.fit(X_train, y_train)
    print("[INFO] Training complete!\n")
    return model


def evaluate_model(model, X_test, y_test, feature_names):
    """Print comprehensive evaluation metrics."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    accuracy  = accuracy_score(y_test, y_pred)
    roc_auc   = roc_auc_score(y_test, y_prob)
    conf_mat  = confusion_matrix(y_test, y_pred)
    class_rep = classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"]
    )

    print("=" * 60)
    print("  MODEL EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Accuracy  : {accuracy:.4f}  ({accuracy*100:.2f}%)")
    print(f"  ROC-AUC   : {roc_auc:.4f}")
    print("=" * 60)
    print("\nConfusion Matrix:")
    print(f"  {'':15s} Pred Legit  Pred Phish")
    print(f"  {'Actual Legit':15s} {conf_mat[0][0]:>10d}  {conf_mat[0][1]:>10d}")
    print(f"  {'Actual Phish':15s} {conf_mat[1][0]:>10d}  {conf_mat[1][1]:>10d}")
    print("\nClassification Report:")
    print(class_rep)

    # ─── Feature Importance ──────────────────────────────────────
    print("Top 10 Most Important Features:")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    for rank, idx in enumerate(indices, 1):
        print(f"  {rank:>2}. {feature_names[idx]:35s}: {importances[idx]:.4f}")
    print()

    return accuracy, roc_auc


def cross_validate_model(model, X, y):
    """Run k-fold cross-validation for robust performance estimate."""
    print("[INFO] Running 5-Fold Cross-Validation...")
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  Fold scores: {[f'{s:.4f}' for s in cv_scores]}\n")
    return cv_scores


def save_artifacts(model, scaler):
    """Save the trained model and scaler to disk."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    model_size = os.path.getsize(MODEL_PATH) / 1024
    print(f"[INFO] Model saved -> {MODEL_PATH} ({model_size:.1f} KB)")
    print(f"[INFO] Scaler saved -> {SCALER_PATH}")


def main():
    print("\n" + "=" * 60)
    print("  AI-BASED PHISHING DETECTION - MODEL TRAINING")
    print("=" * 60 + "\n")

    # ─── 1. Load dataset ──────────────────────────────────────────
    df = load_dataset(DATASET_PATH)

    # ─── 2. Extract features ──────────────────────────────────────
    X = extract_all_features(df)
    y = df["label"].values
    feature_names = get_feature_names()

    # ─── 3. Train/Test split ──────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"[INFO] Train: {X_train.shape[0]} samples | Test: {X_test.shape[0]} samples\n")

    # ─── 4. Feature scaling (optional for RF, kept for consistency) ─
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # ─── 5. Train ─────────────────────────────────────────────────
    model = train_model(X_train_scaled, y_train)

    # ─── 6. Cross-validation ──────────────────────────────────────
    cross_validate_model(model, X_train_scaled, y_train)

    # ─── 7. Evaluate ──────────────────────────────────────────────
    accuracy, roc_auc = evaluate_model(
        model, X_test_scaled, y_test, feature_names
    )

    # ─── 8. Save artifacts ────────────────────────────────────────
    save_artifacts(model, scaler)

    print("\n" + "=" * 60)
    print(f"  Training complete! Accuracy: {accuracy*100:.2f}% | AUC: {roc_auc:.4f}")
    print(f"  Model ready at: {MODEL_PATH}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
