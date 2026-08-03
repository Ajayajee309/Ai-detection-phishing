# 🛡️ PhishGuard AI – AI-Based Phishing Attack Detection

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Flask-2.3.3-000000?style=for-the-badge&logo=flask&logoColor=white"/>
  <img src="https://img.shields.io/badge/Scikit--learn-1.3.0-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white"/>
  <img src="https://img.shields.io/badge/Random_Forest-ML_Model-6366F1?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Accuracy-95%25+-10B981?style=for-the-badge"/>
</div>

---

A complete final-year engineering project that uses **Machine Learning (Random Forest)** to detect phishing URLs in real time via a beautiful, responsive web application built with Flask.

---

## 📁 Project Structure

```
AI detection phishing/
├── app.py                          # Flask web application (main entry)
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── dataset/
│   ├── generate_dataset.py         # Generates synthetic phishing dataset
│   └── phishing_dataset.csv        # Generated CSV dataset (auto-created)
│
├── features/
│   ├── __init__.py
│   └── feature_extractor.py        # 21 URL feature extraction functions
│
├── model/
│   ├── train_model.py              # Model training script
│   ├── model.pkl                   # Trained Random Forest (auto-created)
│   └── scaler.pkl                  # Feature scaler (auto-created)
│
├── templates/
│   └── index.html                  # Jinja2 HTML template
│
└── static/
    ├── css/
    │   └── style.css               # Dark-mode premium CSS
    └── js/
        └── app.js                  # Frontend JavaScript
```

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🤖 **ML Model** | Random Forest with 200 trees, trained on 3,000 URLs |
| 🔬 **21 Features** | URL length, HTTPS, IP address, keywords, TLDs, hyphens, and more |
| 📊 **Confidence Score** | Percentage probability for each prediction |
| ⚠️ **Risk Levels** | Low, Medium, High with color-coded display |
| 💡 **Recommendations** | Actionable security advice for each result |
| 🎨 **Premium UI** | Dark-mode glassmorphism design with animations |
| 📱 **Responsive** | Mobile, tablet, and desktop support |
| ♿ **Accessible** | ARIA labels, semantic HTML, keyboard navigation |

---

## 🚀 Quick Start (Step-by-Step)

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)
- Git (optional)

---

### Step 1 — Clone or Download

```bash
# Clone the repository
git clone https://github.com/your-username/AI-detection-phishing.git
cd "AI detection phishing"

# OR navigate to the project folder
cd "d:/PROJECTS/AI detection phishing"
```

---

### Step 2 — Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Activate it (Linux/macOS)
source venv/bin/activate
```

---

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 4 — Generate Dataset

```bash
python dataset/generate_dataset.py
```

This generates `dataset/phishing_dataset.csv` with 3,000 labeled URLs (1,500 legitimate + 1,500 phishing).

---

### Step 5 — Train the ML Model

```bash
python model/train_model.py
```

This will:
- Extract 21 features from every URL
- Train a Random Forest with 200 estimators
- Run 5-fold cross-validation
- Print accuracy, ROC-AUC, confusion matrix
- Save `model/model.pkl` and `model/scaler.pkl`

Expected output:
```
Accuracy  : 0.9583  (95.83%)
ROC-AUC   : 0.9921
```

---

### Step 6 — Run the Web Application

```bash
python app.py
```

Open your browser and go to: **http://localhost:5000**

---

## 🔬 Extracted Features (21 Total)

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total character count of URL |
| 2 | `domain_length` | Length of domain/host portion |
| 3 | `path_length` | Length of URL path |
| 4 | `count_dots` | Number of `.` characters |
| 5 | `count_hyphens` | Hyphens in domain name |
| 6 | `count_slashes` | Forward slashes in path |
| 7 | `count_question_marks` | `?` query string indicators |
| 8 | `count_equals` | `=` parameter indicators |
| 9 | `count_ampersands` | `&` multiple parameter indicators |
| 10 | `count_digits_in_domain` | Numeric characters in domain |
| 11 | `count_digits_in_url` | Total digits in full URL |
| 12 | `count_subdomains` | Number of subdomain levels |
| 13 | `count_suspicious_keywords` | Count of phishing keyword matches |
| 14 | `count_special_chars` | Unusual special characters |
| 15 | `uses_https` | 1 = HTTPS, 0 = HTTP |
| 16 | `has_ip_address` | 1 if IP used instead of domain |
| 17 | `has_at_symbol` | 1 if `@` detected in URL |
| 18 | `has_suspicious_keyword` | 1 if any keyword matches |
| 19 | `has_suspicious_tld` | 1 for .tk, .ml, .ga, .xyz, etc. |
| 20 | `is_shortened_url` | 1 for bit.ly, tinyurl, etc. |
| 21 | `has_port_in_url` | 1 if non-standard port used |

---

## 🧠 ML Model Details

| Parameter | Value |
|-----------|-------|
| Algorithm | Random Forest Classifier |
| n_estimators | 200 |
| max_depth | 15 |
| max_features | sqrt |
| class_weight | balanced |
| Test Split | 80% train / 20% test |
| Cross-validation | 5-Fold |
| Scaler | StandardScaler |

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Serve the frontend UI |
| `POST` | `/api/predict` | Predict phishing for a URL |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/features` | List all feature names |

### POST `/api/predict`

**Request:**
```json
{
  "url": "https://paypal-verify-account-12345.tk/secure-login"
}
```

**Response:**
```json
{
  "success": true,
  "url": "https://paypal-verify-account-12345.tk/secure-login",
  "prediction": "Phishing",
  "is_phishing": true,
  "confidence": 94.5,
  "phishing_prob": 94.5,
  "legitimate_prob": 5.5,
  "risk_level": "High",
  "risk_color": "red",
  "recommendation": "⚠️ HIGH RISK: Do NOT visit this website...",
  "feature_analysis": [...],
  "raw_features": {...}
}
```

---

## 🚢 Deployment

### Deploy with Gunicorn (Production)

```bash
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

### Deploy with Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "app:app"]
```

---

## 📚 Technologies Used

- **Python 3.9+** — Backend language
- **Flask 2.3.3** — Web framework
- **Scikit-learn 1.3.0** — Machine learning
- **Pandas / NumPy** — Data manipulation
- **Joblib** — Model serialization
- **HTML5 + CSS3 + JavaScript** — Frontend
- **Inter + JetBrains Mono** — Typography (Google Fonts)

---

## 👨‍💻 Author

**Final Year Engineering Project**  
Course: Computer Science / Information Technology  
Topic: AI-Based Phishing Attack Detection  

---

## ⚠️ Disclaimer

This project is developed for **educational purposes only** as part of a final-year engineering course. Do not use this as the sole security tool in a production environment. Always use professional, enterprise-grade security solutions for real-world applications.

---

## 📜 License

MIT License – Free to use for educational purposes.
