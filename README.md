# PhishGuardAI: ML-Based Phishing URL Detection System

**PhishGuardAI** is an engineering project designed to detect phishing and malicious URLs using Machine Learning techniques. The system analyzes lexical, structural, and domain properties of web addresses to classify whether a given URL is legitimate or a phishing attempt.

---

## 1. System Architecture Overview

PhishGuardAI follows a modular architecture separating data processing, machine learning inference, persistent storage, and API delivery:

```
[ User Input (URL) ]
         │
         ▼
[ Web Frontend (HTML / CSS / Vanilla JS) ]
         │ HTTP JSON
         ▼
[ Flask REST API (app.py) ]
         │
         ├──► [ SQLite DB (Scan History & Logs) ]
         │
         ▼
[ Feature Extractor (src/features.py) ]
  - Lexical properties (length, special characters, entropy)
  - Domain properties (subdomain depth, IP usage, TLD)
  - Suspicious token indicators (security keywords, prefixes)
         │ Extracted Feature Vector
         ▼
[ Trained ML Estimator (models/phishing_model.joblib) ]
  - Binary classification (0 = Legitimate, 1 = Phishing)
  - Probability / Confidence Score
         │
         ▼
[ Response JSON with verdict and detailed feature breakdown ]
```

---

## 2. Project Directory Structure

```text
PhishGuardAI/
│
├── dataset/             # Labeled URL datasets (raw and processed CSVs)
│   └── README.md        # Dataset schema and ingestion instructions
│
├── models/              # Serialized ML artifacts (.joblib, metrics, feature maps)
│   └── README.md        # Model registry documentation
│
├── src/                 # Reusable Python source code modules
│   └── __init__.py      # Package indicator
│
├── .gitignore           # Git ignore rules for venv, cache, and local DBs
├── app.py               # Minimal Flask entry point and health endpoints
├── README.md            # Project documentation and guide
└── requirements.txt     # Python package dependencies
```

---

## 3. Technology Stack

* **Programming Language:** Python 3.10+ (Tested on Python 3.12)
* **Data Manipulation & Computation:** Pandas, NumPy
* **Machine Learning & Persistence:** Scikit-learn, Joblib
* **Feature Extraction Utilities:** tldextract, urllib3
* **Backend Web Framework:** Flask, Flask-CORS
* **Database (Future Phase):** SQLite (built-in Python `sqlite3`)
* **Frontend (Future Phase):** HTML5, Vanilla CSS3, Modern JavaScript (No Node.js / npm)

---

## 4. Setup Instructions (Windows PowerShell)

Follow these steps to set up the development environment locally:

### Step 1: Open PowerShell in the Project Root
Ensure you are in the project folder:
```powershell
cd C:\Users\yalla\OneDrive\Desktop\PhishGuardAI
```

### Step 2: Create a Virtual Environment
```powershell
python -m venv venv
```

### Step 3: Activate the Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
*(If you encounter a script execution policy restriction, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` and retry activation).*

### Step 4: Upgrade Pip & Install Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 5: Verify the Setup
Run the Flask server:
```powershell
python app.py
```
Open a secondary PowerShell window or browser and test the health check:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -Method Get
```

Expected output:
```json
{
  "database_ready": true,
  "model_trained": false,
  "status": "healthy"
}
```

---

## 5. Development Roadmap

1. **Phase 1: Backend Foundation** *(Current)* - Establish clean directory layout, dependencies, and baseline Flask entry point.
2. **Phase 2: Dataset Acquisition & Validation** - Ingest verified legitimate and phishing URL datasets, inspect class balance, and handle missing/malformed URLs.
3. **Phase 3: URL Feature Extraction Engine** - Implement domain, lexical, and structural feature extractors (e.g., URL length, dot count, hyphens, entropy, IP address indicators).
4. **Phase 4: ML Model Training & Benchmarking** - Train and compare baseline classifiers (e.g., Logistic Regression vs. Random Forest) and export the best-performing model.
5. **Phase 5: API & SQLite History Integration** - Integrate inference pipeline with Flask endpoints and record scans into SQLite database.
6. **Phase 6: Lightweight Frontend UI** - Build a clean dashboard with HTML, CSS, and Vanilla JS for interactive URL scanning and history visualization.
