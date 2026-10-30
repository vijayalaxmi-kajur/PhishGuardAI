"""PhishGuardAI - Centralized URL Validation and Normalization Engine

Provides strict, offline RFC-compliant syntactic validation and Punycode/IDN
analysis for all URLs before feature extraction and machine learning inference.

Key Capabilities:
1. Protocol Restriction: Restricts scheme strictly to 'http' and 'https'.
2. Hostname & Authority Integrity:
   - Rejects empty, whitespace-only, or missing hostnames (e.g. 'http://', 'https://///').
   - Rejects non-web URI schemes (e.g. 'file:', 'javascript:', 'data:', 'ftp:', 'mailto:').
   - Validates IPv4 octets ([0-255]) and prevents malformed IPv4 strings (e.g. '256.256.256.256', '1.2.3.4.5').
   - Safely parses bracketed IPv6 authorities (e.g. '[::1]') and rejects malformed IPv6 brackets.
3. Punycode & IDN Inspection:
   - Detects internationalized domain names (labels starting with 'xn--' or raw non-ASCII unicode).
   - Normalizes hostnames safely using idna decoding and encoding without network or DNS lookups.
   - Detects mixed-script confusable homograph attacks (e.g. Latin characters mixed with Cyrillic/Greek).
4. Safe Failures:
   - Malformed, empty, or unsupported inputs are cleanly rejected with informative error messages.
   - Invalid URLs never enter the ML classification pipeline and never receive 'NO KNOWN THREAT DETECTED'.
"""

import re
import math
import ipaddress
import urllib.parse
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple
import idna


@dataclass
class URLValidationResult:
    """Structured result returned by centralized URL validation."""
    is_valid: bool
    error_message: Optional[str] = None
    clean_url: str = ""
    scheme: str = ""
    host: str = ""
    original_host: str = ""
    normalized_host: str = ""
    unicode_host: str = ""
    is_punycode: bool = False
    has_mixed_script: bool = False
    is_ip: bool = False
    is_ipv6: bool = False
    port: Optional[int] = None
    path: str = ""
    query: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary representation."""
        return {
            "is_valid": self.is_valid,
            "error_message": self.error_message,
            "clean_url": self.clean_url,
            "scheme": self.scheme,
            "host": self.host,
            "original_host": self.original_host,
            "normalized_host": self.normalized_host,
            "unicode_host": self.unicode_host,
            "is_punycode": self.is_punycode,
            "has_mixed_script": self.has_mixed_script,
            "is_ip": self.is_ip,
            "is_ipv6": self.is_ipv6,
            "port": self.port,
            "path": self.path,
            "query": self.query,
        }


def detect_mixed_script(decoded_host: str) -> bool:
    """Detect whether any domain label mixes Latin characters with non-Latin scripts.
    
    In IDN homograph spoofing attacks, adversaries frequently insert a single Cyrillic
    or Greek character into an otherwise Latin label (e.g. '\\u0430pple.com' where 'а' is Cyrillic).
    Legitimate internationalized domains are typically composed entirely of their native script.
    
    Args:
        decoded_host: Decoded Unicode hostname (e.g. from idna.decode).
        
    Returns:
        True if any discrete label mixes Latin and non-Latin alphabetic characters.
    """
    labels = decoded_host.split(".")
    for label in labels:
        has_latin = any("LATIN" in unicodedata.name(c, "") for c in label)
        has_non_latin = any("LATIN" not in unicodedata.name(c, "") and c.isalnum() for c in label)
        if has_latin and has_non_latin:
            return True
    return False


def validate_url(url: Any, max_length: int = 4096) -> URLValidationResult:
    """Execute centralized offline syntactic validation and IDN inspection on a URL.
    
    Args:
        url: Raw URL input (any type).
        max_length: Maximum permitted string length (default 4096; app.py can pass 2048).
        
    Returns:
        URLValidationResult indicating validity, parsed components, and IDN metadata.
    """
    # 1. Type validation
    if url is None:
        return URLValidationResult(is_valid=False, error_message="Field 'url' is required.")
    if not isinstance(url, str):
        return URLValidationResult(is_valid=False, error_message="Field 'url' must be a string.")

    # 2. Whitespace and length validation
    clean = url.strip()
    if len(clean) == 0:
        return URLValidationResult(is_valid=False, error_message="Field 'url' cannot be empty or whitespace.")

    if any(c in clean for c in (" ", "\t", "\n", "\r")):
        return URLValidationResult(is_valid=False, error_message="URL contains invalid unencoded whitespace characters.")

    if len(clean) > max_length:
        return URLValidationResult(
            is_valid=False,
            error_message=f"URL exceeds maximum allowed length of {max_length} characters."
        )

    # 3. Scheme extraction and whitelist validation
    if "://" in clean:
        scheme_part, _ = clean.split("://", 1)
        scheme = scheme_part.lower()
    elif ":" in clean:
        scheme_part, _ = clean.split(":", 1)
        scheme = scheme_part.lower()
    else:
        scheme = ""

    if not scheme:
        return URLValidationResult(
            is_valid=False,
            error_message="Invalid URL: missing URL scheme (http:// or https:// required)."
        )

    if scheme not in ("http", "https"):
        return URLValidationResult(
            is_valid=False,
            error_message=f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS schemes are supported."
        )

    # 4. Syntactic parsing via urllib.parse.urlsplit
    try:
        parsed = urllib.parse.urlsplit(clean)
    except ValueError as e:
        return URLValidationResult(is_valid=False, error_message=f"Malformed URL format: {str(e)}")
    except Exception:
        return URLValidationResult(is_valid=False, error_message="Malformed URL format.")

    if not parsed.netloc:
        return URLValidationResult(
            is_valid=False,
            error_message="Invalid URL: missing domain or host specification."
        )

    try:
        raw_host = parsed.hostname
    except ValueError as e:
        return URLValidationResult(is_valid=False, error_message=f"Malformed URL authority: {str(e)}")

    if not raw_host:
        return URLValidationResult(
            is_valid=False,
            error_message="Invalid URL: missing domain or host specification."
        )

    # 5. IP Address validation (IPv4 and IPv6)
    is_ip = False
    is_ipv6 = False
    host_lower = raw_host.lower()

    if host_lower.startswith("[") or "]" in host_lower or ":" in host_lower:
        clean_ipv6 = host_lower.strip("[]")
        try:
            ipaddress.IPv6Address(clean_ipv6)
            is_ip = True
            is_ipv6 = True
        except Exception as e:
            return URLValidationResult(is_valid=False, error_message=f"Malformed IPv6 address: {str(e)}")
    elif re.fullmatch(r"[\d\.]+", host_lower):
        # All digits and dots -> must be valid IPv4
        try:
            ipaddress.IPv4Address(host_lower)
            is_ip = True
        except Exception as e:
            return URLValidationResult(is_valid=False, error_message=f"Malformed IPv4 address: {str(e)}")
    else:
        # 6. Domain name syntactic structure checks
        if len(host_lower) > 253:
            return URLValidationResult(is_valid=False, error_message="Hostname exceeds maximum length of 253 characters.")

        labels = host_lower.split(".")
        for label in labels:
            if not label:
                return URLValidationResult(
                    is_valid=False,
                    error_message="Invalid URL: missing domain or host specification."
                )
            if len(label) > 63:
                return URLValidationResult(is_valid=False, error_message=f"Hostname label '{label[:15]}...' exceeds 63 characters.")
            if label.startswith("-") or label.endswith("-"):
                return URLValidationResult(is_valid=False, error_message=f"Hostname label '{label}' cannot start or end with a hyphen.")

    # 7. Punycode & IDN Inspection
    is_punycode = False
    has_mixed_script = False
    unicode_host = host_lower
    normalized_host = host_lower

    labels = host_lower.split(".")
    has_xn = any(l.startswith("xn--") for l in labels)

    if has_xn:
        is_punycode = True
        try:
            unicode_host = idna.decode(host_lower)
            normalized_host = host_lower
            has_mixed_script = detect_mixed_script(unicode_host)
        except Exception as e:
            return URLValidationResult(is_valid=False, error_message=f"Malformed Punycode domain: {str(e)}")
    elif any(ord(c) > 127 for c in host_lower):
        # Raw Unicode characters present in hostname
        try:
            normalized_host = idna.encode(host_lower).decode("ascii")
            is_punycode = True
            unicode_host = host_lower
            has_mixed_script = detect_mixed_script(unicode_host)
        except Exception as e:
            return URLValidationResult(is_valid=False, error_message=f"Malformed internationalized domain: {str(e)}")

    return URLValidationResult(
        is_valid=True,
        error_message=None,
        clean_url=clean,
        scheme=scheme,
        host=host_lower,
        original_host=raw_host,
        normalized_host=normalized_host,
        unicode_host=unicode_host,
        is_punycode=is_punycode,
        has_mixed_script=has_mixed_script,
        is_ip=is_ip,
        is_ipv6=is_ipv6,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query,
    )
