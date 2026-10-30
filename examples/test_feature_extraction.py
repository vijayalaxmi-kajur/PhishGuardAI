"""PhishGuardAI - URL Feature Extraction Demonstration & CLI Example

Demonstrates how to extract the 22 standardized numerical features from any URL
without contacting external servers or visiting websites.

Usage:
    # Run default demonstration with sample URLs:
    python examples/test_feature_extraction.py

    # Extract features for a custom URL:
    python examples/test_feature_extraction.py --url "https://pay.paypal-security-update.com/login"
"""

import os
import sys
import argparse

# Add project root to sys.path to allow imports from src
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.feature_extraction import URLFeatureExtractor


def display_features(url: str, extractor: URLFeatureExtractor):
    """Format and print feature extraction results for a given URL."""
    print("=" * 80)
    print(f"TARGET URL: {url}")
    print("=" * 80)

    # 1. Reference metadata
    meta = extractor.extract_metadata(url)
    print("REFERENCE COMPONENTS:")
    print(f"  - Registered Domain (dom) : {meta['dom']}")
    print(f"  - Top-Level Domain (tld)  : {meta['tld']}")
    print("-" * 80)

    # 2. Extract feature dictionary
    features = extractor.extract_features(url)
    print("EXTRACTED NUMERICAL FEATURES (22 Total):")
    
    col_width = 18
    lines = list(features.items())
    # Display in 2 neat columns
    for i in range(0, len(lines), 2):
        k1, v1 = lines[i]
        val1_str = f"{v1:.4f}" if isinstance(v1, float) else f"{v1}"
        col1 = f"  [{i+1:>2}] {k1:<14}: {val1_str:>10}"
        
        if i + 1 < len(lines):
            k2, v2 = lines[i+1]
            val2_str = f"{v2:.4f}" if isinstance(v2, float) else f"{v2}"
            col2 = f"  [{i+2:>2}] {k2:<14}: {val2_str:>10}"
            print(f"{col1}  |{col2}")
        else:
            print(col1)

    print("-" * 80)

    # 3. Ordered numerical vector
    vector = extractor.extract_vector(url)
    print("ORDERED NUMERICAL VECTOR (Ready for Scikit-learn estimator):")
    print(f"  Shape: 1x{len(vector)}")
    print(f"  Values: {[round(x, 4) if isinstance(x, float) else x for x in vector]}")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuardAI - Feature Extraction Demo (No Network Calls)"
    )
    parser.add_argument(
        "--url", "-u",
        type=str,
        default=None,
        help="Custom URL string to inspect."
    )
    args = parser.parse_args()

    extractor = URLFeatureExtractor()

    if args.url:
        display_features(args.url, extractor)
    else:
        print("\n[INFO] No custom URL provided. Running demonstration across diverse URL types:\n")
        sample_urls = [
            "https://www.rmit.edu.au/",
            "http://202.194.232.100:8005/english/index.asp",
            "https://pay.pagcorefeiraosetembro.site/2wq7Gr7X0A?auth_token=987123",
            "www.google.com/search?q=machine+learning+cybersecurity"
        ]
        for url in sample_urls:
            display_features(url, extractor)


if __name__ == "__main__":
    main()
