# Dataset Directory

This directory will store the raw and processed labeled phishing URL datasets.

### Expected Format:
- CSV file format (e.g., `dataset.csv` or `phishing_urls.csv`)
- Minimum required columns:
  - `url`: The raw target URL string (e.g., `http://example.com/login`)
  - `label` / `status`: Binary ground truth target:
    - `0` (or `legitimate` / `benign`)
    - `1` (or `phishing` / `malicious`)

### Data Integrity Rules:
- No synthetic or invented rows should be manually populated here.
- Sourced from benchmark datasets such as PhishTank, OpenPhish, or Kaggle URL datasets in the next phase.
