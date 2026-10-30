import urllib.parse
import re
import ipaddress
import idna

def validate_url(url):
    if url is None or not isinstance(url, str):
        return False, "Field 'url' must be a non-empty string.", None
    clean = url.strip()
    if len(clean) == 0:
        return False, "Field 'url' cannot be empty or whitespace.", None
    if any(c in clean for c in (' ', '\t', '\n', '\r')):
        return False, "URL contains invalid whitespace characters.", None
    if len(clean) > 4096:
        return False, "URL exceeds maximum allowed length of 4096 characters.", None

    # Scheme
    if '://' in clean:
        scheme_part, _ = clean.split('://', 1)
        scheme = scheme_part.lower()
    elif ':' in clean:
        scheme_part, _ = clean.split(':', 1)
        scheme = scheme_part.lower()
    else:
        scheme = ''

    if not scheme:
        return False, "Invalid URL: missing URL scheme (http:// or https:// required).", None
    if scheme not in ('http', 'https'):
        return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS schemes are supported.", None

    # Parse
    try:
        parsed = urllib.parse.urlsplit(clean)
    except ValueError as e:
        return False, f"Malformed URL format: {str(e)}", None
    except Exception:
        return False, "Malformed URL format.", None

    if not parsed.netloc:
        return False, "Invalid URL: missing domain or host specification.", None

    try:
        hostname = parsed.hostname
    except ValueError as e:
        return False, f"Malformed URL authority: {str(e)}", None

    if not hostname:
        return False, "Invalid URL: missing domain or host specification.", None

    # Check authority components
    if hostname.startswith('[') or ']' in hostname or ':' in hostname:
        clean_ipv6 = hostname.strip('[]')
        try:
            ipaddress.IPv6Address(clean_ipv6)
            is_ip = True
        except Exception as e:
            return False, f"Malformed IPv6 address: {str(e)}", None
    elif re.fullmatch(r'[\d\.]+', hostname):
        try:
            ipaddress.IPv4Address(hostname)
            is_ip = True
        except Exception as e:
            return False, f"Malformed IPv4 address: {str(e)}", None
    else:
        is_ip = False
        # Domain name checks
        if len(hostname) > 253:
            return False, "Hostname exceeds maximum length of 253 characters.", None
        labels = hostname.split('.')
        for label in labels:
            if not label:
                return False, "Hostname contains empty label or consecutive dots.", None
            if len(label) > 63:
                return False, f"Hostname label '{label[:15]}...' exceeds 63 characters.", None
            if label.startswith('-') or label.endswith('-'):
                return False, f"Hostname label '{label}' cannot start or end with a hyphen.", None

        # Check Punycode/IDN validity
        has_xn = any(l.lower().startswith('xn--') for l in labels)
        if has_xn:
            try:
                unicode_host = idna.decode(hostname)
            except Exception as e:
                return False, f"Malformed Punycode domain: {str(e)}", None
        elif any(ord(c) > 127 for c in hostname):
            try:
                norm = idna.encode(hostname).decode('ascii')
            except Exception as e:
                return False, f"Malformed internationalized domain: {str(e)}", None

    return True, None, {'clean': clean, 'scheme': scheme, 'host': hostname}

test_cases = [
    'http://',
    'https://///',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'data:text/plain,test',
    '',
    '   ',
    'https:///path/only',
    'http://256.256.256.256',
    'http://1.2.3.4.5',
    'http://[invalid_ipv6]',
    'http://[:::1]',
    'http://[::1]',
    'http://192.168.1.1',
    'http://example.com',
    'https://example.com/test',
    'https://xn--e1afmkfd.xn--p1ai/test',
    'https://xn--invalidpunycode-999.com',
    'https://пример.рф/test',
    'http://??::255.255/'
]

import unicodedata

def analyze_punycode(host):
    labels = host.split('.')
    is_puny = any(l.lower().startswith('xn--') for l in labels)
    if not is_puny and not any(ord(c) > 127 for c in host):
        return {'is_punycode': False}
    
    try:
        decoded_host = idna.decode(host)
    except Exception as e:
        return {'is_punycode': True, 'malformed': True, 'error': str(e)}

    decoded_labels = decoded_host.split('.')
    has_mixed_script = False
    for dl in decoded_labels:
        has_latin = any('LATIN' in unicodedata.name(c, '') for c in dl)
        has_non_latin = any('LATIN' not in unicodedata.name(c, '') and c.isalnum() for c in dl)
        if has_latin and has_non_latin:
            has_mixed_script = True
            break
            
    return {
        'is_punycode': True,
        'original_host': host,
        'unicode_host': ascii(decoded_host),
        'has_mixed_script': has_mixed_script
    }

test_hosts = [
    'example.com',
    'xn--e1afmkfd.xn--p1ai',
    'xn--pple-43d.com',
    'xn--mgbh0fb.xn--kgbechtv'
]

if __name__ == '__main__':
    for h in test_hosts:
        res = analyze_punycode(h)
        print(f"{h:28s} -> is_puny={res['is_punycode']}, mixed={res.get('has_mixed_script')}, host={res.get('unicode_host')}")

