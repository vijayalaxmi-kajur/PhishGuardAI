"""PhishGuardAI - Experimental Feature Extraction Engine (Phase C)

This module implements the ExperimentalURLFeatureExtractor class.
It preserves the exact 22-feature production schema for backward compatibility,
while providing an expanded 30-feature schema that isolates component-level
characteristics (domain vs path vs query string entropy and token distributions).

Features are extracted strictly offline using standard library parsing and
cached Public Suffix List rules via tldextract.
"""

import math
import collections
import urllib.parse
import ipaddress
from typing import Dict, List, Any, Union, Optional
import tldextract


class ExperimentalURLFeatureExtractor:
    """Extracts both standardized 22-feature baseline vectors and expanded

    30-feature component-isolated vectors from raw URL strings.
    """

    # Preserved original 22 production features in exact order
    BASELINE_FEATURE_NAMES: List[str] = [
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

    # Additional component-isolated features for Phase C
    NEW_FEATURE_NAMES: List[str] = [
        "host_len",          # Length of full hostname (e.g. 'www.youtube.com' = 15)
        "subdom_len",        # Length of subdomain string (e.g. 'www' = 3)
        "dom_entropy",       # Shannon entropy calculated STRICTLY on registered domain
        "dom_digit_cnt",     # Digits inside registered domain only (detects suspicious domain digits)
        "path_depth",        # Count of directory segments in path
        "query_param_cnt",   # Count of structured key-value query parameters
        "query_entropy",     # Shannon entropy calculated STRICTLY across query string
        "query_digit_cnt",   # Digits inside query string only (normal in video/catalog IDs)
    ]

    EXPERIMENTAL_FEATURE_NAMES: List[str] = BASELINE_FEATURE_NAMES + NEW_FEATURE_NAMES

    def __init__(self) -> None:
        """Initialize the extractor with an offline TLDExtract instance."""
        # suffix_list_urls=None ensures strict offline mode (no network calls)
        self._extractor = tldextract.TLDExtract(suffix_list_urls=None)

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of characters in a string.
        
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
    def is_ip_address(host: str) -> bool:
        """Determine whether a hostname or domain string is a valid IPv4 or IPv6 address.
        
        Args:
            host: Hostname string (without port).
            
        Returns:
            True if host is an IP address, False otherwise.
        """
        if not host:
            return False
        clean_host = host.split(":")[0]
        try:
            ipaddress.ip_address(clean_host)
            return True
        except ValueError:
            return False

    def extract_baseline_features(self, url: Union[str, Any]) -> Dict[str, Union[int, float]]:
        """Extract the exact 22 production features matching URLFeatureExtractor.
        
        Args:
            url: The raw URL string to analyze.
            
        Returns:
            Dictionary mapping feature names to their extracted numerical values.
        """
        if url is None:
            raw_url = ""
        else:
            raw_url = str(url).strip()

        url_len = len(raw_url)
        if url_len == 0:
            return {name: 0.0 if "ratio" in name or name == "entropy" else 0 for name in self.BASELINE_FEATURE_NAMES}

        is_https = 1 if raw_url.lower().startswith("https://") or raw_url.lower().startswith("https:") else 0

        letter_cnt = sum(1 for c in raw_url if c.isalpha())
        digit_cnt = sum(1 for c in raw_url if c.isdigit())
        special_cnt = url_len - (letter_cnt + digit_cnt)

        letter_ratio = float(letter_cnt / url_len) if url_len > 0 else 0.0
        digit_ratio = float(digit_cnt / url_len) if url_len > 0 else 0.0
        spec_ratio = float(special_cnt / url_len) if url_len > 0 else 0.0

        eq_cnt = raw_url.count("=")
        qm_cnt = raw_url.count("?")
        amp_cnt = raw_url.count("&")
        dot_cnt = raw_url.count(".")
        dash_cnt = raw_url.count("-")
        under_cnt = raw_url.count("_")
        slash_cnt = raw_url.count("/")

        entropy = self.calculate_entropy(raw_url)

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

        try:
            extracted = self._extractor(raw_url)
            subdomain_str = extracted.subdomain
            domain_part = extracted.domain
            suffix_part = extracted.suffix
        except Exception:
            subdomain_str = ""
            domain_part = ""
            suffix_part = ""

        is_ip = 1 if (self.is_ip_address(netloc_host) or self.is_ip_address(domain_part)) else 0

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

    def extract_experimental_features(self, url: Union[str, Any]) -> Dict[str, Union[int, float]]:
        """Extract all 30 features (22 baseline + 8 component-isolated features).
        
        Args:
            url: The raw URL string to analyze.
            
        Returns:
            Dictionary mapping 30 feature names to their extracted numerical values.
        """
        baseline_dict = self.extract_baseline_features(url)

        if url is None:
            raw_url = ""
        else:
            raw_url = str(url).strip()

        parse_target = raw_url if ("://" in raw_url or raw_url.startswith("//")) else f"//{raw_url}"
        try:
            parsed = urllib.parse.urlparse(parse_target)
            host_str = parsed.netloc.split(":")[0] if parsed.netloc else ""
            path_str = parsed.path
            query_str = parsed.query
        except Exception:
            host_str = ""
            path_str = ""
            query_str = ""

        try:
            extracted = self._extractor(raw_url)
            subdomain_str = extracted.subdomain
            domain_part = extracted.domain
            suffix_part = extracted.suffix
        except Exception:
            subdomain_str = ""
            domain_part = ""
            suffix_part = ""

        is_ip = baseline_dict["is_ip"]
        if is_ip == 1:
            dom = host_str if host_str else domain_part
        else:
            dom = f"{domain_part}.{suffix_part}" if suffix_part and domain_part else (domain_part or suffix_part)

        host_len = len(host_str)
        subdom_len = len(subdomain_str)
        dom_entropy = self.calculate_entropy(dom)
        dom_digit_cnt = sum(1 for c in dom if c.isdigit())

        # Path depth: number of non-empty path segments
        path_segments = [seg for seg in path_str.strip("/").split("/") if seg]
        path_depth = len(path_segments)

        # Query parsing
        if query_str:
            try:
                qs_dict = urllib.parse.parse_qs(query_str, keep_blank_values=True)
                query_param_cnt = len(qs_dict)
            except Exception:
                query_param_cnt = query_str.count("=") or 1
            query_entropy = self.calculate_entropy(query_str)
            query_digit_cnt = sum(1 for c in query_str if c.isdigit())
        else:
            query_param_cnt = 0
            query_entropy = 0.0
            query_digit_cnt = 0

        component_dict = {
            "host_len": host_len,
            "subdom_len": subdom_len,
            "dom_entropy": dom_entropy,
            "dom_digit_cnt": dom_digit_cnt,
            "path_depth": path_depth,
            "query_param_cnt": query_param_cnt,
            "query_entropy": query_entropy,
            "query_digit_cnt": query_digit_cnt,
        }

        full_features = {**baseline_dict, **component_dict}
        return full_features

    def extract_vector(self, url: Union[str, Any], schema: str = "experimental") -> List[Union[int, float]]:
        """Extract ordered numerical vector.
        
        Args:
            url: The raw URL string.
            schema: 'baseline' (22 features) or 'experimental' (30 features).
            
        Returns:
            List of numerical values matching the requested schema.
        """
        if schema == "baseline":
            d = self.extract_baseline_features(url)
            return [d[name] for name in self.BASELINE_FEATURE_NAMES]
        elif schema == "experimental":
            d = self.extract_experimental_features(url)
            return [d[name] for name in self.EXPERIMENTAL_FEATURE_NAMES]
        else:
            raise ValueError(f"Unknown feature schema: {schema}. Choose 'baseline' or 'experimental'.")
