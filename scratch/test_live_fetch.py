import urllib.request
import re

req = urllib.request.Request(
    'https://ishacotton.sanchikahub.in/',
    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'}
)

try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        html = resp.read().decode('utf-8', errors='ignore')
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else 'No title'
        print('Status:', resp.status)
        print('Title:', title)
        print('Final URL:', resp.geturl())
        print('Server:', resp.headers.get('Server', 'Unknown'))
        has_password = bool(re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))
        print('Has password input:', has_password)
except Exception as e:
    print('Error:', e)
