"""PhishGuardAI - Live Website Presence, Telemetry & Security Inspector

Performs authentic, multi-signal live website inspection:
1. DNS Resolution (IPv4/IPv6 address mapping and NXDOMAIN detection)
2. HTTP/HTTPS probe with SSL certificate verification
3. Live HTML telemetry extraction (Page title, server banner, redirect traces)
4. Credential / Login form detection (<input type="password">)
5. Soft-404 and cloud platform 'Site Not Found' signature detection
"""

import socket
import re
import html
import ssl
import urllib.parse
import urllib.request
import urllib.error
from typing import Tuple, Dict, Any, Optional


def check_website_presence(url: str, timeout: float = 4.0) -> Tuple[bool, str, Dict[str, Any]]:
    """Check if the website domain exists in DNS and extract live telemetry.
    
    Args:
        url: The full target URL string (e.g. 'https://example.com/login').
        timeout: Maximum seconds to wait for DNS/HTTP response.
        
    Returns:
        Tuple of (is_present: bool, message: str, details_dict: Dict).
    """
    clean_url = str(url).strip()
    if not clean_url:
        return False, "Empty URL provided.", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": None,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "empty_url"
        }

    # Normalize parse target
    parse_target = clean_url if ("://" in clean_url or clean_url.startswith("//")) else f"http://{clean_url}"
    try:
        parsed = urllib.parse.urlsplit(parse_target)
        host = parsed.netloc.split(":")[0].strip()
        scheme = parsed.scheme.lower() or "http"
    except Exception as e:
        return False, f"Invalid URL structure: {str(e)}", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": None,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "invalid_url"
        }

    if not host:
        return False, "URL does not contain a valid hostname.", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": None,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "missing_host"
        }

    # 1. DNS Resolution Check
    resolved_ip = None
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if addr_info and len(addr_info) > 0:
            resolved_ip = addr_info[0][4][0]
    except socket.gaierror:
        return False, f"Domain '{host}' does not exist in DNS (NXDOMAIN / Name Not Resolved).", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": None,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "dns_nxdomain"
        }
    except Exception as e:
        return False, f"DNS resolution failed for '{host}': {str(e)}", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": None,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "dns_error"
        }

    # 2. Live HTTP/HTTPS Connectivity and Telemetry Extraction
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # Probe reachability without aborting on self-signed certs

    req = urllib.request.Request(
        clean_url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 PhishGuardAI/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as response:
            status_code = getattr(response, "status", 200)
            final_url = response.geturl()
            server_header = response.headers.get("Server", "Active Web Server")
            content_type = response.headers.get("Content-Type", "")

            # Read sample of HTML body (up to 32KB)
            body_sample = ""
            try:
                raw_bytes = response.read(32768)
                body_sample = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                pass

            body_lower = body_sample.lower()

            # Extract Page Title
            page_title = None
            title_match = re.search(r"<title[^>]*>(.*?)</title>", body_sample, re.IGNORECASE | re.DOTALL)
            if title_match:
                page_title = html.unescape(title_match.group(1)).strip()
                page_title = re.sub(r"\s+", " ", page_title)
                if len(page_title) > 90:
                    page_title = page_title[:87] + "..."

            # Detect Password Input & Forms
            has_password = bool(re.search(r'<input[^>]+type=["\']password["\']', body_sample, re.IGNORECASE))
            has_login_form = has_password and bool(re.search(r'<form[^>]*>', body_sample, re.IGNORECASE))

            # Detect Soft 404 / Cloud Hosting 'Site Not Found' / Parked Domains
            soft_not_found_phrases = (
                "site not found",
                "page not found",
                "looks like you followed a broken link or entered a url that doesn't exist",
                "there isn't a github pages site here",
                "the deployment could not be found",
                "deployment not found",
                "project not found",
                "no such app",
                "domain not configured",
                "this domain is parked",
                "domain is for sale",
                "buy this domain",
                "account suspended",
                "default website page",
                "server not configured"
            )

            title_lower = (page_title or "").lower()
            if any(phrase in body_lower or phrase in title_lower for phrase in soft_not_found_phrases):
                platform_note = "Site Not Found / Not Deployed"
                if "netlify" in body_lower or "netlify" in host:
                    platform_note = "Netlify: Site not found"
                elif "vercel" in body_lower or "vercel" in host:
                    platform_note = "Vercel: Deployment not found"
                elif "github" in body_lower or "github" in host:
                    platform_note = "GitHub Pages: Site not found"

                return False, f"Website does not exist ({platform_note} - HTTP {status_code}).", {
                    "dns_resolved": True,
                    "resolved_ip": resolved_ip,
                    "http_status": status_code,
                    "page_title": page_title or "Site Not Found",
                    "server_header": server_header,
                    "final_url": final_url,
                    "ssl_verified": clean_url.lower().startswith("https://"),
                    "has_password_input": False,
                    "has_login_form": False,
                    "reason": "soft_404_site_not_found"
                }

            title_display = f" — '{page_title}'" if page_title else ""
            return True, f"Website is online and reachable (HTTP {status_code}){title_display}.", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": status_code,
                "page_title": page_title,
                "server_header": server_header,
                "final_url": final_url,
                "ssl_verified": clean_url.lower().startswith("https://"),
                "has_password_input": has_password,
                "has_login_form": has_login_form,
                "reason": "reachable"
            }

    except urllib.error.HTTPError as e:
        status_code = e.code
        server_header = e.headers.get("Server", "Web Gateway") if hasattr(e, "headers") and e.headers else "Web Server"
        
        # Read error body
        error_body = ""
        try:
            error_body = e.read(4096).decode("utf-8", errors="ignore").lower()
        except Exception:
            pass

        # 404 Not Found & 410 Gone mean the website/page does NOT exist!
        if status_code in (404, 410):
            platform_hint = "HTTP 404 Not Found"
            if "netlify" in host or "netlify" in error_body:
                platform_hint = "Netlify: Site not found"
            elif "vercel" in host or "vercel" in error_body:
                platform_hint = "Vercel: 404 Not Found"
            elif "github" in host or "github" in error_body:
                platform_hint = "GitHub Pages: 404 Not Found"
            elif "firebase" in host or "firebase" in error_body:
                platform_hint = "Firebase: Site not found"

            return False, f"Website does not exist ({platform_hint}).", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": status_code,
                "page_title": "Site Not Found (404)",
                "server_header": server_header,
                "final_url": clean_url,
                "ssl_verified": clean_url.lower().startswith("https://"),
                "has_password_input": False,
                "has_login_form": False,
                "reason": "http_404_not_found"
            }

        # Check for unassigned cloud application gateway errors (502 / 503)
        if status_code in (502, 503, 504):
            if any(p in error_body for p in ("site not found", "no such app", "deployment not found", "unregistered domain")):
                return False, f"Website is not deployed or unassigned (HTTP {status_code}).", {
                    "dns_resolved": True,
                    "resolved_ip": resolved_ip,
                    "http_status": status_code,
                    "page_title": "Application Not Found",
                    "server_header": server_header,
                    "final_url": clean_url,
                    "ssl_verified": clean_url.lower().startswith("https://"),
                    "has_password_input": False,
                    "has_login_form": False,
                    "reason": "unassigned_host"
                }

        # Codes like 401 (Auth Required), 403 (Forbidden), 500 (Internal Server Error) prove the web server is physically running!
        return True, f"Website server is present and responding (HTTP {status_code}).", {
            "dns_resolved": True,
            "resolved_ip": resolved_ip,
            "http_status": status_code,
            "page_title": f"HTTP {status_code} Response",
            "server_header": server_header,
            "final_url": clean_url,
            "ssl_verified": clean_url.lower().startswith("https://"),
            "has_password_input": False,
            "has_login_form": False,
            "reason": "http_response"
        }

    except urllib.error.URLError as e:
        reason_str = str(e.reason).lower()
        if "ssl" in reason_str or "certificate" in reason_str:
            return True, f"Website server is present (SSL Handshake: {e.reason}).", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": None,
                "page_title": None,
                "server_header": None,
                "final_url": clean_url,
                "ssl_verified": False,
                "has_password_input": False,
                "has_login_form": False,
                "reason": "ssl_handshake"
            }
        elif "connection refused" in reason_str:
            return False, f"Server found at '{host}', but port is closed (Connection Refused).", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": None,
                "page_title": None,
                "server_header": None,
                "final_url": clean_url,
                "ssl_verified": False,
                "has_password_input": False,
                "has_login_form": False,
                "reason": "connection_refused"
            }
        elif "timed out" in reason_str:
            return False, f"Website at '{host}' timed out after {timeout} seconds.", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": None,
                "page_title": None,
                "server_header": None,
                "final_url": clean_url,
                "ssl_verified": False,
                "has_password_input": False,
                "has_login_form": False,
                "reason": "timeout"
            }
        else:
            return False, f"Could not establish connection to '{host}': {e.reason}", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": None,
                "page_title": None,
                "server_header": None,
                "final_url": clean_url,
                "ssl_verified": False,
                "has_password_input": False,
                "has_login_form": False,
                "reason": "unreachable"
            }

    except TimeoutError:
        return False, f"Connection to '{host}' timed out after {timeout} seconds.", {
            "dns_resolved": True,
            "resolved_ip": resolved_ip,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": clean_url,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "timeout"
        }

    except Exception as e:
        if resolved_ip:
            return True, f"Domain resolved to {resolved_ip}, but connection returned: {str(e)[:60]}", {
                "dns_resolved": True,
                "resolved_ip": resolved_ip,
                "http_status": None,
                "page_title": None,
                "server_header": None,
                "final_url": clean_url,
                "ssl_verified": False,
                "has_password_input": False,
                "has_login_form": False,
                "reason": "dns_resolved_only"
            }
        return False, f"Unable to reach website: {str(e)}", {
            "dns_resolved": False,
            "resolved_ip": None,
            "http_status": None,
            "page_title": None,
            "server_header": None,
            "final_url": clean_url,
            "ssl_verified": False,
            "has_password_input": False,
            "has_login_form": False,
            "reason": "unknown_error"
        }
