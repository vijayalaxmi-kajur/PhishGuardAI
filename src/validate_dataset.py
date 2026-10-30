"""PhishGuardAI - Dataset Validation and Integrity Inspector

This script inspects and validates labeled phishing URL datasets without
modifying or deleting the original data. It checks schema, missing values,
duplicates, class balance, conflicting labels, and malformed URLs, and saves
a detailed validation report in the reports/ directory.
"""

import os
import sys
import argparse
from datetime import datetime
from typing import Optional, Tuple, List
import pandas as pd

# Standard candidate column names for automatic identification
URL_CANDIDATES = [
    "url", "urls", "url_address", "web_address", "link", 
    "website", "domain", "site_url", "target_url"
]

LABEL_CANDIDATES = [
    "label", "labels", "class", "classes", "target", 
    "status", "type", "result", "is_phishing", "phishing", "classification"
]


def find_csv_files(dataset_dir: str) -> List[str]:
    """Find all CSV files inside the dataset directory."""
    if not os.path.exists(dataset_dir):
        return []
    return [
        os.path.join(dataset_dir, f)
        for f in os.listdir(dataset_dir)
        if f.lower().endswith(".csv") and not f.startswith(".")
    ]


def detect_column(
    columns: List[str], 
    candidates: List[str], 
    col_type: str, 
    user_specified: Optional[str] = None
) -> str:
    """Identify column by user argument or fuzzy candidate matching."""
    if user_specified:
        # Check if user specified exact column exists
        for col in columns:
            if col.strip().lower() == user_specified.strip().lower():
                return col
        raise ValueError(
            f"Specified {col_type} column '{user_specified}' was not found in dataset.\n"
            f"Available columns: {columns}"
        )

    # Automatic matching against candidates
    matched = []
    for col in columns:
        clean_name = col.strip().lower()
        if clean_name in candidates:
            matched.append(col)

    if len(matched) == 1:
        return matched[0]
    elif len(matched) > 1:
        raise ValueError(
            f"Ambiguous {col_type} column! Multiple candidate columns matched: {matched}\n"
            f"Please specify explicitly using --{col_type.lower()}-col <column_name>."
        )
    else:
        raise ValueError(
            f"Could not automatically identify the {col_type} column.\n"
            f"Available columns in dataset: {columns}\n"
            f"Please specify explicitly using --{col_type.lower()}-col <column_name>."
        )


def validate_dataset(
    file_path: str,
    url_col_arg: Optional[str] = None,
    label_col_arg: Optional[str] = None,
    sample_size: int = 5,
    report_path: Optional[str] = None
) -> bool:
    """Inspect and validate a phishing URL dataset CSV file."""
    output_lines = []

    def log(msg: str = ""):
        print(msg)
        output_lines.append(msg)

    log("=" * 80)
    log("          PHISHGUARDAI — DATASET VALIDATION & INTEGRITY REPORT          ")
    log("=" * 80)
    log(f"Execution Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log(f"Dataset File Target : {file_path}")

    # Check file existence
    if not os.path.exists(file_path):
        log("\n[ERROR] Dataset file not found!")
        log(f"Provided path: {file_path}")
        log("Please verify that you placed your CSV file in the dataset/ directory.")
        return False

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    log(f"File Size           : {file_size_mb:.2f} MB")
    log("-" * 80)

    # Load dataset with fallback encodings
    df = None
    for encoding in ["utf-8", "latin1", "cp1252"]:
        try:
            df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
            log(f"Successfully loaded CSV using '{encoding}' encoding.")
            break
        except UnicodeDecodeError:
            continue
        except Exception as e:
            log(f"\n[ERROR] Failed to read CSV file: {e}")
            return False

    if df is None:
        log("\n[ERROR] Unable to decode CSV file with standard encodings (utf-8, latin1, cp1252).")
        return False

    # 1. Dataset Dimensions & Schema
    total_rows, total_cols = df.shape
    columns = list(df.columns)
    log(f"\n[1] DATASET DIMENSIONS & SCHEMA:")
    log(f"  • Total Rows    : {total_rows:,}")
    log(f"  • Total Columns : {total_cols}")
    log("  • Column Names & Types:")
    for col in columns:
        dtype = str(df[col].dtype)
        non_null_count = df[col].count()
        log(f"      - {col:<25} [Type: {dtype:<10} | Non-Null: {non_null_count:,}/{total_rows:,}]")

    if total_rows == 0:
        log("\n[ERROR] Dataset contains 0 rows! Cannot perform validation on empty dataset.")
        return False

    # 2. Identify Target Columns
    log(f"\n[2] COLUMN IDENTIFICATION:")
    try:
        url_col = detect_column(columns, URL_CANDIDATES, "URL", url_col_arg)
        label_col = detect_column(columns, LABEL_CANDIDATES, "Label", label_col_arg)
        log(f"  • Identified URL Column   : '{url_col}'")
        log(f"  • Identified Label Column : '{label_col}'")
    except ValueError as ve:
        log(f"\n[ERROR] {ve}")
        return False

    # 3. Sample Records
    log(f"\n[3] SAMPLE RECORDS (First {sample_size} rows):")
    sample_df = df[[url_col, label_col]].head(sample_size)
    for idx, row in sample_df.iterrows():
        url_preview = str(row[url_col])
        if len(url_preview) > 65:
            url_preview = url_preview[:62] + "..."
        log(f"  [{idx+1}] Label: {str(row[label_col]):<15} | URL: {url_preview}")

    # 4. Missing / Empty Values Check
    log(f"\n[4] MISSING & EMPTY VALUE ANALYSIS:")
    total_null_urls = df[url_col].isnull().sum()
    total_null_labels = df[label_col].isnull().sum()

    # Check for empty or whitespace-only strings
    empty_urls = df[url_col].apply(lambda x: isinstance(x, str) and x.strip() == "").sum()
    empty_labels = df[label_col].apply(lambda x: isinstance(x, str) and x.strip() == "").sum()

    log(f"  • Null/NaN URLs       : {total_null_urls:,} ({(total_null_urls / total_rows) * 100:.2f}%)")
    log(f"  • Empty string URLs   : {empty_urls:,}")
    log(f"  • Null/NaN Labels     : {total_null_labels:,} ({(total_null_labels / total_rows) * 100:.2f}%)")
    log(f"  • Empty string Labels : {empty_labels:,}")

    # 5. Duplicate Row & Duplicate URL Analysis
    log(f"\n[5] DUPLICATE ANALYSIS:")
    exact_duplicate_rows = df.duplicated().sum()
    duplicate_urls = df[url_col].duplicated().sum()
    unique_urls = df[url_col].nunique(dropna=True)

    log(f"  • Exact Duplicate Rows (all columns) : {exact_duplicate_rows:,}")
    log(f"  • Duplicate URL Instances            : {duplicate_urls:,}")
    log(f"  • Distinct / Unique URLs             : {unique_urls:,}")

    # Detect Conflicting Labels (Same URL mapped to multiple distinct labels)
    conflicts_df = df.groupby(url_col)[label_col].nunique()
    conflicting_urls = conflicts_df[conflicts_df > 1]
    num_conflicts = len(conflicting_urls)
    log(f"  • Conflicting URL Labels (Same URL, Different Labels) : {num_conflicts:,}")
    if num_conflicts > 0:
        log("    [WARNING] Contradictory labels detected! Examples:")
        for conflict_url in conflicting_urls.index[:3]:
            conflicting_entries = df[df[url_col] == conflict_url][label_col].unique()
            log(f"      - '{conflict_url}' mapped to {list(conflicting_entries)}")
        log("    (Note: These contradictory entries should be pruned during preprocessing in Phase 3).")

    # 6. Label Distribution & Class Balance Check
    log(f"\n[6] CLASS LABEL DISTRIBUTION & BALANCE:")
    label_counts = df[label_col].value_counts(dropna=False)
    for lbl, count in label_counts.items():
        pct = (count / total_rows) * 100
        log(f"  • Class '{lbl}' : {count:,} instances ({pct:.2f}%)")

    num_classes = len(label_counts)
    has_both_classes = num_classes >= 2

    # Check for expected class values
    if has_both_classes:
        log(f"  • Multi-class / Binary status: {num_classes} classes detected.")
        top_two = label_counts.iloc[:2]
        ratio = top_two.iloc[0] / max(top_two.iloc[1], 1)
        log(f"  • Dominant Class Imbalance Ratio: {ratio:.2f}:1")
        if ratio > 4.0:
            log("    [NOTE] Class distribution is imbalanced (>4:1). Resampling or stratified evaluation recommended.")
        else:
            log("    [OK] Class balance is acceptable for supervised learning.")
    else:
        log("  [CRITICAL WARNING] Only ONE class detected! Supervised learning requires at least two distinct classes.")

    # 7. Malformed URL Entry Inspection
    log(f"\n[7] URL INTEGRITY & ANOMALY INSPECTION:")
    # Check for non-string URLs
    non_string_urls = df[url_col].apply(lambda x: not isinstance(x, str)).sum()
    # Suspiciously short URLs (< 4 characters, e.g. '/', '.', 'abc')
    short_urls = df[url_col].apply(lambda x: isinstance(x, str) and len(x.strip()) < 4).sum()

    log(f"  • Non-string URL values       : {non_string_urls:,}")
    log(f"  • Suspiciously short (<4 char): {short_urls:,}")

    if short_urls > 0:
        log("    Sample short entries:")
        short_samples = df[df[url_col].apply(lambda x: isinstance(x, str) and len(x.strip()) < 4)][url_col].head(3)
        for s in short_samples:
            log(f"      - '{s}'")

    # 8. Final Verdict & Integrity Summary
    log("\n" + "=" * 80)
    log("                       FINAL VALIDATION VERDICT                         ")
    log("=" * 80)

    verdict_passed = True
    issues = []

    if total_rows < 100:
        issues.append("Dataset size is very small (< 100 samples).")
        verdict_passed = False

    if not has_both_classes:
        issues.append("Dataset lacks binary representation (needs both benign and phishing).")
        verdict_passed = False

    if total_null_urls > 0 or total_null_labels > 0:
        issues.append(f"Missing data present: {total_null_urls} null URLs, {total_null_labels} null labels.")

    if num_conflicts > 0:
        issues.append(f"{num_conflicts} URLs have conflicting labels.")

    if verdict_passed and not issues:
        log("  [STATUS: PASSED] Dataset is healthy, structurally valid, and ready for Phase 3.")
    elif verdict_passed and issues:
        log("  [STATUS: PASSED WITH WARNINGS]")
        log("  Dataset is usable, but requires cleaning steps during feature preprocessing:")
        for issue in issues:
            log(f"    - {issue}")
    else:
        log("  [STATUS: FAILED / ACTION REQUIRED]")
        for issue in issues:
            log(f"    - {issue}")

    log("=" * 80)

    # 9. Save Report to Disk
    if report_path is None:
        report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "dataset_validation_report.txt")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(output_lines) + "\n")
        log(f"\n[REPORT SAVED] Full report written to: {report_path}")
    except Exception as e:
        log(f"\n[WARNING] Could not save report file: {e}")

    return verdict_passed


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuardAI - Labeled Phishing URL Dataset Validator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--file", "-f",
        type=str,
        default=None,
        help="Path to CSV dataset file (defaults to auto-detecting CSV in dataset/ directory)."
    )
    parser.add_argument(
        "--url-col", "-u",
        type=str,
        default=None,
        help="Name of the URL column (e.g. 'url', 'URL', 'url_address'). Auto-detected if omitted."
    )
    parser.add_argument(
        "--label-col", "-l",
        type=str,
        default=None,
        help="Name of the label column (e.g. 'label', 'status', 'type'). Auto-detected if omitted."
    )
    parser.add_argument(
        "--sample-size", "-s",
        type=int,
        default=5,
        help="Number of sample records to preview (default: 5)."
    )
    parser.add_argument(
        "--report-out", "-r",
        type=str,
        default=None,
        help="Custom output file path for the validation report."
    )

    args = parser.parse_args()

    # Determine file path
    target_file = args.file
    if not target_file:
        base_dir = os.path.dirname(os.path.dirname(__file__))
        dataset_dir = os.path.join(base_dir, "dataset")
        csv_files = find_csv_files(dataset_dir)

        if not csv_files:
            print("\n" + "=" * 80)
            print("  [INFO] No CSV dataset file found in the dataset/ directory.")
            print("=" * 80)
            print("To proceed with dataset validation:")
            print("  1. Download a verified phishing URL dataset (in CSV format).")
            print("  2. Save it directly into the dataset/ directory:")
            print(f"     -> {os.path.abspath(dataset_dir)}")
            print("  3. Run this script again:")
            print("     python src/validate_dataset.py\n")
            print("Alternatively, pass the file path explicitly:")
            print("     python src/validate_dataset.py --file <path_to_csv>\n")
            sys.exit(1)
        elif len(csv_files) == 1:
            target_file = csv_files[0]
            print(f"[Auto-Detected Dataset] Found '{os.path.basename(target_file)}' in dataset/")
        else:
            print(f"\nMultiple CSV files found in dataset/ directory:")
            for idx, f in enumerate(csv_files, 1):
                print(f"  [{idx}] {os.path.basename(f)}")
            target_file = csv_files[0]
            print(f"Defaulting to: {os.path.basename(target_file)}")
            print("To select a specific file, run: python src/validate_dataset.py --file <path>\n")

    # Run validation
    success = validate_dataset(
        file_path=target_file,
        url_col_arg=args.url_col,
        label_col_arg=args.label_col,
        sample_size=args.sample_size,
        report_path=args.report_out
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
