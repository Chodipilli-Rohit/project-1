import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import logging
import time
from flask import Flask, request, render_template, jsonify
from threading import Thread
import uuid
from datetime import datetime

# Configure logging
logging.basicConfig(filename='vuln_scan.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Payloads for vulnerability testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'><script>alert(1)</script>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1; DROP TABLE users --",
]

# Store scan results
scan_results = []

class WebVulnScanner:
    def __init__(self, target_url, max_depth=2):
        self.target_url = target_url.rstrip('/')
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VulnScanner/1.0'})

    def crawl(self, url, depth=0):
        """Crawl the website to find URLs and input fields."""
        if depth > self.max_depth or url in self.visited_urls:
            return
        self.visited_urls.add(url)
        logging.info(f"Crawling: {url}")

        try:
            response = self.session.get(url, timeout=5)
            if response.status_code != 200:
                return
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            links = []
            for a in soup.find_all('a', href=True):
                href = urllib.parse.urljoin(url, a['href'])
                if self.target_url in href and href not in self.visited_urls:
                    links.append(href)

            # Find forms and input fields
            forms = soup.find_all('form')
            for form in forms:
                action = urllib.parse.urljoin(url, form.get('action', ''))
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                input_fields = [(inp.get('name'), inp.get('type')) for inp in inputs if inp.get('name')]
                if input_fields:
                    self.test_form_vulnerabilities(url, action, method, input_fields)

            # Recursively crawl links
            for link in links:
                self.crawl(link, depth + 1)

        except requests.RequestException as e:
            logging.error(f"Error crawling {url}: {e}")

    def test_form_vulnerabilities(self, url, action, method, input_fields):
        """Test forms for XSS, SQLi, and CSRF vulnerabilities."""
        # Test XSS
        for name, _ in input_fields:
            for payload in XSS_PAYLOADS:
                data = {name: payload}
                try:
                    if method == 'post':
                        response = self.session.post(action, data=data, timeout=5)
                    else:
                        response = self.session.get(action, params=data, timeout=5)
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'type': 'XSS',
                            'url': action,
                            'evidence': f"Payload '{payload}' reflected in response",
                            'severity': 'High',
                            'timestamp': datetime.now().isoformat()
                        })
                        logging.warning(f"XSS detected at {action} with payload: {payload}")
                except requests.RequestException as e:
                    logging.error(f"Error testing XSS on {action}: {e}")

        # Test SQLi
        for name, _ in input_fields:
            for payload in SQLI_PAYLOADS:
                data = {name: payload}
                try:
                    if method == 'post':
                        response = self.session.post(action, data=data, timeout=5)
                    else:
                        response = self.session.get(action, params=data, timeout=5)
                    if re.search(r'(sql|mysql|database|syntax) error', response.text, re.I):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': action,
                            'evidence': f"SQL error detected with payload: {payload}",
                            'severity': 'Critical',
                            'timestamp': datetime.now().isoformat()
                        })
                        logging.warning(f"SQLi detected at {action} with payload: {payload}")
                except requests.RequestException as e:
                    logging.error(f"Error testing SQLi on {action}: {e}")

        # Test CSRF
        if not any(inp.get('name') == '_csrf_token' for inp in input_fields):
            self.vulnerabilities.append({
                'type': 'CSRF',
                'url': action,
                'evidence': 'No CSRF token found in form',
                'severity': 'Medium',
                'timestamp': datetime.now().isoformat()
            })
            logging.warning(f"Potential CSRF vulnerability at {action}: No CSRF token")

    def scan(self):
        """Run the full scan."""
        logging.info(f"Starting scan on {self.target_url}")
        self.crawl(self.target_url)
        return self.vulnerabilities

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('url')
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    scan_id = str(uuid.uuid4())
    scanner = WebVulnScanner(target_url)
    
    def run_scan():
        results = scanner.scan()
        scan_results.append({
            'id': scan_id,
            'url': target_url,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    
    # Run scan in background thread
    Thread(target=run_scan).start()
    return jsonify({'scan_id': scan_id, 'message': 'Scan started'})

@app.route('/results/<scan_id>')
def get_results(scan_id):
    for scan in scan_results:
        if scan['id'] == scan_id:
            return jsonify(scan)
    return jsonify({'error': 'Scan not found'}), 404

# HTML Template
@app.route('/templates/index.html')
def serve_template():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Vulnerability Scanner</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f0f0f0; }
        h1 { color: #333; }
        .form-container { margin-bottom: 20px; }
        input[type="text"] { width: 300px; padding: 8px; }
        button { padding: 8px 16px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #45a049; }
        #results { margin-top: 20px; }
        .vuln { border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; }
        .severity-critical { background-color: #ffcccc; }
        .severity-high { background-color: #ffebcc; }
        .severity-medium { background-color: #fff3cd; }
    </style>
    <script>
        async function startScan() {
            const url = document.getElementById('url').value;
            const response = await fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: `url=${encodeURIComponent(url)}`
            });
            const data = await response.json();
            alert(data.message);
            pollResults(data.scan_id);
        }

        async function pollResults(scan_id) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = 'Scanning... Please wait.';
            const interval = setInterval(async () => {
                const response = await fetch(`/results/${scan_id}`);
                const data = await response.json();
                if (!data.error) {
                    clearInterval(interval);
                    displayResults(data);
                }
            }, 2000);
        }

        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML = `<h2>Scan Results for ${data.url}</h2>`;
            if (data.results.length === 0) {
                resultsDiv.innerHTML += '<p>No vulnerabilities found.</p>';
                return;
            }
            data.results.forEach(vuln => {
                resultsDiv.innerHTML += `
                    <div class="vuln severity-${vuln.severity.toLowerCase()}">
                        <strong>Type:</strong> ${vuln.type}<br>
                        <strong>URL:</strong> ${vuln.url}<br>
                        <strong>Evidence:</strong> ${vuln.evidence}<br>
                        <strong>Severity:</strong> ${vuln.severity}<br>
                        <strong>Timestamp:</strong> ${vuln.timestamp}
                    </div>`;
            });
        }
    </script>
</head>
<body>
    <h1>Web Application Vulnerability Scanner</h1>
    <div class="form-container">
        <input type="text" id="url" placeholder="Enter target URL (e.g., http://example.com)">
        <button onclick="startScan()">Start Scan</button>
    </div>
    <div id="results"></div>
</body>
</html>
    """

if __name__ == '__main__':
    app.run(debug=True)