import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'banking', 'paypal', 'amazon', 'google', 'microsoft',
    'apple', 'netflix', 'bank', 'password', 'credential', 'wallet'
]

LEGITIMATE_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'paypal.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'youtube.com'
]

def analyze_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    results = {
        'url': url,
        'domain': domain,
        'features': {},
        'risk_score': 0,
        'warnings': []
    }

    # Check for IP address as domain
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        results['features']['ip_as_domain'] = True
        results['risk_score'] += 30
        results['warnings'].append('IP address used as domain — highly suspicious')
    else:
        results['features']['ip_as_domain'] = False

    # Check URL length
    url_length = len(url)
    results['features']['url_length'] = url_length
    if url_length > 75:
        results['risk_score'] += 10
        results['warnings'].append(f'Long URL ({url_length} chars) — often used to hide true destination')

    # Check for suspicious keywords
    keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    results['features']['suspicious_keywords'] = keywords_found
    if keywords_found:
        results['risk_score'] += len(keywords_found) * 5
        results['warnings'].append(f'Suspicious keywords found: {", ".join(keywords_found)}')

    # Check number of subdomains
    subdomain_count = len(domain.split('.')) - 2
    results['features']['subdomain_count'] = subdomain_count
    if subdomain_count > 2:
        results['risk_score'] += 15
        results['warnings'].append(f'Too many subdomains ({subdomain_count}) — phishing tactic')

    # Check for lookalike domains
    for legit in LEGITIMATE_DOMAINS:
        legit_name = legit.split('.')[0]
        if legit_name in domain and domain != legit and not domain.endswith('.' + legit):
            results['risk_score'] += 40
            results['warnings'].append(f'Lookalike domain detected — impersonating {legit}')
            break

    # Check for HTTPS
    results['features']['has_https'] = url.startswith('https://')
    if not url.startswith('https://'):
        results['risk_score'] += 10
        results['warnings'].append('No HTTPS — connection is not encrypted')

    # Check for special characters in domain
    if re.search(r'[^a-zA-Z0-9\-\.]', domain):
        results['risk_score'] += 20
        results['warnings'].append('Special characters in domain — suspicious')

    # Check for @ symbol in URL
    if '@' in url:
        results['risk_score'] += 25
        results['warnings'].append('@ symbol in URL — used to hide true destination')

    # Check for double slashes in path
    if '//' in path:
        results['risk_score'] += 10
        results['warnings'].append('Double slashes in path — suspicious redirect')

    results['risk_score'] = min(results['risk_score'], 100)
    return results