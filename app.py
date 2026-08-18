from flask import Flask, render_template, jsonify, request
from src.url_analyzer import analyze_url
from src.domain_checker import check_domain
from src.ssl_checker import check_ssl
from src.reporter import generate_report
import threading
import json
import os

app = Flask(__name__)
LOG_PATH = os.path.join('logs', 'scans.log')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    from urllib.parse import urlparse
    domain = urlparse(url).netloc

    url_results = analyze_url(url)
    domain_results = check_domain(domain)
    ssl_results = check_ssl(domain)
    report = generate_report(url, url_results, domain_results, ssl_results)

    return jsonify(report)

@app.route('/api/history')
def api_history():
    scans = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, 'r') as f:
            for line in f:
                try:
                    scans.append(json.loads(line.strip()))
                except Exception:
                    continue
    return jsonify(list(reversed(scans[-50:])))

if __name__ == '__main__':
    app.run(debug=True, port=5003)