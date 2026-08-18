import sys
import os
import argparse
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(__file__))

from src.url_analyzer import analyze_url
from src.domain_checker import check_domain
from src.ssl_checker import check_ssl
from src.reporter import generate_report, print_report

def scan_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc

    print(f"\n[*] Scanning: {url}")
    print(f"[*] Domain: {domain}")
    print(f"{'='*60}")

    print("[*] Analyzing URL structure...")
    url_results = analyze_url(url)

    print("[*] Checking domain WHOIS...")
    domain_results = check_domain(domain)

    print("[*] Checking SSL certificate...")
    ssl_results = check_ssl(domain)

    report = generate_report(url, url_results, domain_results, ssl_results)
    print_report(report)
    return report

def main():
    parser = argparse.ArgumentParser(
        description='Phishing URL Detector — analyze URLs for phishing indicators',
        epilog='''
Examples:
  Scan a URL:
    python main.py --url http://paypa1.com/login/verify

  Scan multiple URLs from file:
    python main.py --file urls.txt
        '''
    )

    parser.add_argument('--url', type=str, help='URL to scan')
    parser.add_argument('--file', type=str, help='File with URLs to scan (one per line)')

    args = parser.parse_args()

    if args.url:
        scan_url(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            print(f"[*] Scanning {len(urls)} URLs...")
            for url in urls:
                scan_url(url)
        except FileNotFoundError:
            print(f"[-] File not found: {args.file}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()