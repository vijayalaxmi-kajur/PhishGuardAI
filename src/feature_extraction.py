"""PhishGuardAI - URL Feature Extraction Engine

This module implements the URLFeatureExtractor class, responsible for extracting
the 22 structural, lexical, and domain-level numerical features required by the
PhishGuardAI machine learning detection model.

Features extracted match the exact schema and definitions established by the
peer-reviewed URL-Phish benchmark dataset (Linh & Hung, 2025).
"""

import math
import collections
import urllib.parse
import ipaddress
from typing import Dict, List, Any, Union, Optional
import tldextract


class URLFeatureExtractor:
    """Extracts 22 standardized numerical features from raw URL strings.
    
    This extractor operates strictly offline and performs no network requests.
    It utilizes character analysis, URI parsing (urllib.parse), and Public
    Suffix List parsing (tldextract offline mode).
    """

    FEATURE_NAMES: List[str] = [
        "url_len",
        "dom_len",
        "is_ip",
        "tld_len",
        "subdom_cnt",
        "letter_cnt",
        "digit_cnt",
        "special_cnt",
        "eq_cnt",
        "qm_cnt",
        "amp_cnt",
        "dot_cnt",
        "dash_cnt",
        "under_cnt",
        "letter_ratio",
        "digit_ratio",
        "spec_ratio",
        "is_https",
        "slash_cnt",
        "entropy",
        "path_len",
        "query_len",
    ]

    def __init__(self) -> None:
        """Initialize the extractor with an offline TLDExtract instance."""
        # suffix_list_urls=None ensures strict offline mode (no network calls)
        self._extractor = tldextract.TLDExtract(suffix_list_urls=None)

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate the Shannon entropy of characters in a string.
        
        Formula: H(S) = -sum(P(c) * log2(P(c)))
        
        Args:
            text: Input string.
            
        Returns:
            Shannon entropy as a float (0.0 for empty strings).
        """
        if not text:
            return 0.0
        counts = collections.Counter(text)
        total = len(text)
        return float(-sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values()))

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        """Determine whether a hostname or domain string is a valid IPv4 or IPv6 address.
        
        Args:
            host: Hostname string (without port).
            
        Returns:
            True if host is an IP address, False otherwise.
        """
        if not host:
            return False
        # Remove potential port specification if present (e.g. 192.168.1.1:8080)
        clean_host = host.split(":")[0]
        try:
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            return False

    def extract_features(self, url: Union[str, Any]) -> Dict[str, Union[int, float]]:
        """Extract the 22 numerical features from a URL string as a dictionary.
        
        Args:
            url: The raw URL string to analyze.
            
        Returns:
            Dictionary mapping feature names to their extracted numerical values.
        """
        # 1. Input normalization: ensure clean string
        if url is None:
            raw_url = ""
        else:
            raw_url = str(url).strip()

        url_len = len(raw_url)

        # Handle empty URL gracefully
        if url_len == 0:
            return {name: 0.0 if "ratio" in name or name == "entropy" else 0 for name in self.FEATURE_NAMES}

        # 2. Scheme & HTTPS check
        is_https = 1 if raw_url.lower().startswith("https://") or raw_url.lower().startswith("https:") else 0

        # 3. Character counts & ratios
        letter_cnt = sum(1 for c in raw_url if c.isalpha())
        digit_cnt = sum(1 for c in raw_url if c.isdigit())
        special_cnt = url_len - (letter_cnt + digit_cnt)

        letter_ratio = float(letter_cnt / url_len) if url_len > 0 else 0.0
        digit_ratio = float(digit_cnt / url_len) if url_len > 0 else 0.0
        spec_ratio = float(special_cnt / url_len) if url_len > 0 else 0.0

        # Specific character frequencies
        eq_cnt = raw_url.count("=")
        qm_cnt = raw_url.count("?")
        amp_cnt = raw_url.count("&")
        dot_cnt = raw_url.count(".")
        dash_cnt = raw_url.count("-")
        under_cnt = raw_url.count("_")
        slash_cnt = raw_url.count("/")

        # Shannon entropy
        entropy = self._calculate_entropy(raw_url)

        # 4. URL path and query parsing using urllib.parse
        # To parse URLs without an explicit scheme reliably with urlparse, prepend '//'
        parse_target = raw_url if ("://" in raw_url or raw_url.startswith("//")) else f"//{raw_url}"
        try:
            parsed = urllib.parse.urlparse(parse_target)
            path_len = len(parsed.path)
            query_len = len(parsed.query)
            netloc_host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        except Exception:
            path_len = 0
            query_len = 0
            netloc_host = ""

        # 5. Domain, TLD, Subdomain & IP extraction using tldextract
        try:
            extracted = self._extractor(raw_url)
            subdomain_str = extracted.subdomain
            domain_part = extracted.domain
            suffix_part = extracted.suffix
        except Exception:
            subdomain_str = ""
            domain_part = ""
            suffix_part = ""

        # Check IP address usage
        is_ip = 1 if (self._is_ip_address(netloc_host) or self._is_ip_address(domain_part)) else 0

        if is_ip == 1:
            dom = netloc_host if netloc_host else domain_part
            tld = ""
            subdom_cnt = 0
        else:
            if suffix_part:
                dom = f"{domain_part}.{suffix_part}" if domain_part else suffix_part
                tld = suffix_part
            else:
                dom = domain_part
                tld = ""
            subdom_cnt = len(subdomain_str.split(".")) if subdomain_str else 0

        dom_len = len(dom)
        tld_len = len(tld)

        # Construct and return dictionary in standard order
        return {
            "url_len": url_len,
            "dom_len": dom_len,
            "is_ip": is_ip,
            "tld_len": tld_len,
            "subdom_cnt": subdom_cnt,
            "letter_cnt": letter_cnt,
            "digit_cnt": digit_cnt,
            "special_cnt": special_cnt,
            "eq_cnt": eq_cnt,
            "qm_cnt": qm_cnt,
            "amp_cnt": amp_cnt,
            "dot_cnt": dot_cnt,
            "dash_cnt": dash_cnt,
            "under_cnt": under_cnt,
            "letter_ratio": letter_ratio,
            "digit_ratio": digit_ratio,
            "spec_ratio": spec_ratio,
            "is_https": is_https,
            "slash_cnt": slash_cnt,
            "entropy": entropy,
            "path_len": path_len,
            "query_len": query_len,
        }

    def extract_vector(self, url: Union[str, Any]) -> List[Union[int, float]]:
        """Extract the 22 numerical features as an ordered list (feature vector).
        
        Args:
            url: The raw URL string to analyze.
            
        Returns:
            List of 22 numerical feature values in exact schema order.
        """
        features_dict = self.extract_features(url)
        return [features_dict[name] for name in self.FEATURE_NAMES]

    def extract_metadata(self, url: Union[str, Any]) -> Dict[str, str]:
        """Extract reference textual components (url, dom, tld) for debugging/logging.
        
        Args:
            url: The raw URL string.
            
        Returns:
            Dictionary with 'url', 'dom', and 'tld'.
        """
        raw_url = "" if url is None else str(url).strip()
        if not raw_url:
            return {"url": "", "dom": "", "tld": ""}

        parse_target = raw_url if ("://" in raw_url or raw_url.startswith("//")) else f"//{raw_url}"
        try:
            parsed = urllib.parse.urlparse(parse_target)
            netloc_host = parsed.netloc.split(":")[0] if parsed.netloc else ""
        except Exception:
            netloc_host = ""

        try:
            extracted = self._extractor(raw_url)
            domain_part = extracted.domain
            suffix_part = extracted.suffix
        except Exception:
            domain_part = ""
            suffix_part = ""

        is_ip = self._is_ip_address(netloc_host) or self._is_ip_address(domain_part)
        if is_ip:
            dom = netloc_host if netloc_host else domain_part
            tld = ""
        else:
            dom = f"{domain_part}.{suffix_part}" if suffix_part and domain_part else (domain_part or suffix_part)
            tld = suffix_part

        return {
            "url": raw_url,
            "dom": dom,
            "tld": tld
        }
