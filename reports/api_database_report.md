# PhishGuardAI — REST API & SQLite Scan History Documentation

**Project:** PhishGuardAI — Intelligent Phishing URL Detection System  
**Implementation Phase:** Phase 6 — REST API & SQLite Database Integration  
**Backend Framework:** Flask 3.1+ (Python)  
**Database:** SQLite 3 (Python Standard Library `sqlite3`)  
**Persistent Storage Location:** `data/scan_history.db`  
**Primary ML Model:** Random Forest Classifier (`models/phishing_model.joblib`)  

---

## 1. System Architecture & Component Interaction

```
[ Client Request (Browser / PowerShell / Postman) ]
                     │
                     │ HTTP JSON
                     ▼
          Flask Web Server (app.py)
   ┌────────────────────────────────────────────────────────┐
   │ 1. Request Validator (Length, Scheme, Structure)       │
   │ 2. Feature Extractor (src/feature_extraction.py)       │
   │ 3. ML Inference Engine (models/phishing_model.joblib)  │
   │ 4. History Logger (src/database.py)                    │
   └────────────────────────────────────────────────────────┘
         │                                    │
         ▼                                    ▼
[ SQLite DB (data/scan_history.db) ]    [ JSON Response ]
  - id (Primary Key)                      - verdict: "phishing" | "legitimate"
  - url                                   - phishing_probability (0.0 to 1.0)
  - verdict                               - confidence_percent
  - phishing_probability                  - feature_breakdown (22 features)
  - confidence_percent                    - scanned_at (UTC timestamp)
  - scanned_at (UTC)
```

---

## 2. SQLite Database Schema & Design

The database interface is implemented in `src/database.py`. It uses Python's built-in `sqlite3` with strict parameterized queries (`?`) to prevent SQL injection vulnerabilities.

### Table Schema: `scans`
```sql
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    phishing_probability REAL NOT NULL,
    confidence_percent REAL NOT NULL,
    scanned_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_id_desc ON scans(id DESC);
```

### Key Principles:
1. **Isolated Connection Lifecycles:** Every database operation uses a dedicated context manager (`get_db_connection`) that automatically commits and closes the SQLite file handle, preventing file lock errors on Windows.
2. **Data Minimization:** Never stores passwords, tokens, query parameters that contain secrets, or unnecessary user identity data.
3. **Non-Destructive Initialization:** Calling `initialize_database()` creates tables only if they do not exist (`IF NOT EXISTS`), preserving all historical scan records across server restarts.

---

## 3. Model Loading & Verification Protocol

1. **Path Resolution:** The model path is computed relative to the project root (`models/phishing_model.joblib`), independent of the shell working directory.
2. **Artifact Structure Inspection:**
   The training pipeline saved a dictionary wrapper containing the model and metadata. `app.py` inspects the loaded artifact:
   ```python
   if isinstance(artifact, dict):
       model = artifact["model"]
       feature_names = artifact["feature_names"]
       model_name = artifact["model_name"]
   ```
3. **Integrity & Interface Checks:**
   * Verifies `hasattr(model, "predict_proba")`.
   * Enforces feature count matching 22 features (`len(feature_names) == 22`).
   * Dynamic Class Index Mapping: Dynamically queries `model.classes_` to find the exact column index of label `1` (`list(model.classes_).index(1)`), avoiding any assumptions about internal column ordering.
4. **Degraded State Handling:**
   If the model artifact is missing or corrupted, the server starts in a **degraded** state: `/api/health` returns HTTP 503 with `"model_loaded": false`, and `/api/scan` returns HTTP 503 without crashing the server.

---

## 4. URL Validation & Security Safeguards

To prevent abuse and security risks:
1. **Strict Offline Execution:** Processing a URL scan never fetches, pings, opens, or resolves DNS for the submitted URL. The URL is treated purely as a passive text string for mathematical feature extraction.
2. **Scheme Restrictions:** Only `http` and `https` schemes are accepted. Dangerous or unsupported schemes (`javascript:`, `file:`, `ftp:`, `data:`, `tel:`) are rejected with HTTP 400.
3. **Length Constraint:** URLs are capped at **2,048 characters** to prevent denial-of-service via memory exhaustion.
4. **Host Requirement:** The URL must contain a valid hostname or domain.

---

## 5. API Endpoints Specification

### 1. `GET /`
Returns backend identity, version, operational phase, and API sitemap.
* **Response (HTTP 200):**
```json
{
  "endpoints": {
    "health": "/api/health (GET)",
    "history": "/api/history (GET, DELETE)",
    "scan": "/api/scan (POST)"
  },
  "model_loaded": true,
  "model_name": "Random Forest Classifier",
  "phase": "Phase 6 - REST API & SQLite Scan History",
  "project": "PhishGuardAI",
  "status": "online",
  "version": "1.0.0"
}
```

---

### 2. `GET /api/health`
Monitors system health, model availability, and database readiness.
* **Response (HTTP 200 when healthy):**
```json
{
  "database_ready": true,
  "model_loaded": true,
  "model_name": "Random Forest Classifier",
  "status": "healthy",
  "timestamp": "2026-10-28T07:34:53.269500+00:00"
}
```

---

### 3. `POST /api/scan`
Extracts 22 features, runs machine learning inference, records the scan into SQLite, and returns the classification verdict.

* **Headers:** `Content-Type: application/json`
* **Request Body:**
```json
{
  "url": "https://www.rmit.edu.au/"
}
```

* **Success Response (HTTP 200):**
```json
{
  "confidence_percent": 100.0,
  "feature_breakdown": {
    "amp_cnt": 0,
    "dash_cnt": 0,
    "digit_cnt": 0,
    "digit_ratio": 0.0,
    "dom_len": 11,
    "dot_cnt": 3,
    "entropy": 3.7091479170272446,
    "eq_cnt": 0,
    "is_https": 1,
    "is_ip": 0,
    "letter_cnt": 17,
    "letter_ratio": 0.7083333333333334,
    "path_len": 1,
    "qm_cnt": 0,
    "query_len": 0,
    "slash_cnt": 3,
    "spec_ratio": 0.2916666666666667,
    "special_cnt": 7,
    "subdom_cnt": 1,
    "tld_len": 6,
    "under_cnt": 0,
    "url_len": 24
  },
  "phishing_probability": 0.0,
  "scanned_at": "2026-10-28T07:34:53.422241+00:00",
  "success": true,
  "threshold": 0.5,
  "url": "https://www.rmit.edu.au/",
  "verdict": "legitimate"
}
```

* **Phishing URL Example Response (HTTP 200):**
```json
{
  "confidence_percent": 100.0,
  "phishing_probability": 1.0,
  "threshold": 0.5,
  "url": "https://tds67586i7fusryuyiugkj-ys64dufy576uyij.pages.dev/",
  "verdict": "phishing",
  "success": true
}
```

* **Error Response Example (HTTP 400 Bad Request):**
```json
{
  "error": "Unsupported URL scheme 'ftp'. Only HTTP and HTTPS schemes are supported.",
  "success": false
}
```

---

### 4. `GET /api/history`
Retrieves past scan records with pagination support.

* **Query Parameters:**
  * `limit` (int, default `50`, max `100`): Maximum records to return.
  * `offset` (int, default `0`): Pagination offset.
* **Success Response (HTTP 200):**
```json
{
  "count": 2,
  "history": [
    {
      "confidence_percent": 100.0,
      "id": 2,
      "phishing_probability": 1.0,
      "scanned_at": "2026-10-28T07:34:53.477361+00:00",
      "url": "https://tds67586i7fusryuyiugkj-ys64dufy576uyij.pages.dev/",
      "verdict": "phishing"
    },
    {
      "confidence_percent": 100.0,
      "id": 1,
      "phishing_probability": 0.0,
      "scanned_at": "2026-10-28T07:34:53.422241+00:00",
      "url": "https://www.rmit.edu.au/",
      "verdict": "legitimate"
    }
  ],
  "limit": 10,
  "offset": 0,
  "success": true,
  "total": 2
}
```

---

### 5. `DELETE /api/history`
Deletes all records from the SQLite scans table while preserving database integrity.

* **Success Response (HTTP 200):**
```json
{
  "deleted_records": 2,
  "message": "Scan history deleted successfully.",
  "success": true
}
```

---

## 6. How to Run the Server & Tests in PowerShell

### 1. Run Complete Unit Test Suite (46 Tests):
```powershell
python -m unittest discover -s tests -v
```

### 2. Start the Flask Server:
```powershell
python app.py
```

### 3. Test API Endpoints via PowerShell (in a second tab):

#### Check Health:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/health" -Method Get
```

#### Scan a Legitimate URL:
```powershell
$body = @{ url = "https://www.rmit.edu.au/" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/scan" -Method Post -Body $body -ContentType "application/json"
```

#### Scan a Suspicious / Phishing URL:
```powershell
$body = @{ url = "https://tds67586i7fusryuyiugkj-ys64dufy576uyij.pages.dev/" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/scan" -Method Post -Body $body -ContentType "application/json"
```

#### Retrieve Scan History:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/history?limit=10" -Method Get
```

#### Clear Scan History:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/history" -Method Delete
```
