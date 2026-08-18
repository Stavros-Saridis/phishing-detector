from datetime import datetime
import json
import os

LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'logs', 'scans.log')

def calculate_final_score(url_results, domain_results, ssl_results):
    url_score = url_results.get('risk_score', 0)
    domain_score = domain_results.get('risk_score', 0)
    ssl_score = ssl_results.get('risk_score', 0)
    
    total = url_score + domain_score + ssl_score
    return min(total, 100)

def get_verdict(score):
    if score >= 70:
        return 'PHISHING', 'CRITICAL'
    elif score >= 40:
        return 'SUSPICIOUS', 'HIGH'
    elif score >= 20:
        return 'MODERATE RISK', 'MEDIUM'
    else:
        return 'LIKELY SAFE', 'LOW'

def generate_report(url, url_results, domain_results, ssl_results):
    score = calculate_final_score(url_results, domain_results, ssl_results)
    verdict, severity = get_verdict(score)

    all_warnings = (
        url_results.get('warnings', []) +
        domain_results.get('warnings', []) +
        ssl_results.get('warnings', [])
    )

    report = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url': url,
        'risk_score': score,
        'verdict': verdict,
        'severity': severity,
        'warnings': all_warnings,
        'details': {
            'url_analysis': url_results.get('features', {}),
            'domain_info': domain_results.get('info', {}),
            'ssl_info': ssl_results.get('info', {})
        }
    }

    log_scan(report)
    return report

def log_scan(report):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(report) + '\n')

def print_report(report):
    print(f"\n{'='*60}")
    print(f"PHISHING DETECTION REPORT")
    print(f"{'='*60}")
    print(f"URL:        {report['url']}")
    print(f"Timestamp:  {report['timestamp']}")
    print(f"Risk Score: {report['risk_score']}/100")
    print(f"Verdict:    {report['verdict']} [{report['severity']}]")

    if report['warnings']:
        print(f"\nWarnings:")
        for w in report['warnings']:
            print(f"  [!] {w}")

    if report['details']['domain_info']:
        print(f"\nDomain Info:")
        for k, v in report['details']['domain_info'].items():
            print(f"  {k}: {v}")

    if report['details']['ssl_info']:
        print(f"\nSSL Info:")
        for k, v in report['details']['ssl_info'].items():
            print(f"  {k}: {v}")

    print(f"{'='*60}\n")