import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from flask import Flask, request, render_template
import logging
import time

# Configure logging
logging.basicConfig(filename='scan_report.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Common payloads for testing vulnerabilities
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'><script>alert('XSS')</script>"
]
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users --",
    "' UNION SELECT NULL, username, password FROM users --"
]
CSRF_PAYLOAD = "<form action='/submit' method='POST'><input type='hidden' name='csrf_token' value=''></form>"

def crawl_url(url):
    """Crawl a URL to find forms and input fields."""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        urls = [a['href'] for a in soup.find_all('a', href=True)]
        return forms, urls
    except Exception as e:
        logging.error(f"Error crawling {url}: {str(e)}")
        return [], []

def test_xss(url, form, inputs):
    """Test for XSS vulnerabilities."""
    vulnerabilities = []
    for payload in XSS_PAYLOADS:
        data = {inp['name']: payload for inp in inputs if 'name' in inp.attrs}
        try:
            if form.get('method', '').lower() == 'post':
                response = requests.post(urljoin(url, form.get('action', '')), data=data, timeout=5)
            else:
                response = requests.get(urljoin(url, form.get('action', '')), params=data, timeout=5)
            if payload in response.text:
                vulnerabilities.append({
                    'type': 'XSS',
                    'payload': payload,
                    'url': url,
                    'severity': 'High',
                    'evidence': f"Payload {payload} reflected in response"
                })
                logging.warning(f"XSS detected at {url} with payload: {payload}")
        except Exception as e:
            logging.error(f"XSS test failed for {url}: {str(e)}")
    return vulnerabilities

def test_sqli(url, form, inputs):
    """Test for SQL Injection vulnerabilities."""
    vulnerabilities = []
    for payload in SQLI_PAYLOADS:
        data = {inp['name']: payload for inp in inputs if 'name' in inp.attrs}
        try:
            if form.get('method', '').lower() == 'post':
                response = requests.post(urljoin(url, form.get('action', '')), data=data, timeout=5)
            else:
                response = requests.get(urljoin(url, form.get('action', '')), params=data, timeout=5)
            if re.search(r'sql|mysql|syntax|error', response.text, re.I):
                vulnerabilities.append({
                    'type': 'SQLi',
                    'payload': payload,
                    'url': url,
                    'severity': 'Critical',
                    'evidence': f"Possible SQL error in response"
                })
                logging.warning(f"SQLi detected at {url} with payload: {payload}")
        except Exception as e:
            logging.error(f"SQLi test failed for {url}: {str(e)}")
    return vulnerabilities

def test_csrf(form):
    """Check for CSRF token presence."""
    vulnerabilities = []
    if 'csrf' not in str(form).lower():
        vulnerabilities.append({
            'type': 'CSRF',
            'payload': 'None',
            'url': form.get('action', ''),
            'severity': 'Medium',
            'evidence': 'No CSRF token found in form'
        })
        logging.warning(f"CSRF vulnerability detected in form: {form.get('action', '')}")
    return vulnerabilities

def scan_website(target_url):
    """Main function to scan a website for vulnerabilities."""
    vulnerabilities = []
    forms, urls = crawl_url(target_url)
    for form in forms:
        inputs = form.find_all('input')
        vulnerabilities.extend(test_xss(target_url, form, inputs))
        vulnerabilities.extend(test_sqli(target_url, form, inputs))
        vulnerabilities.extend(test_csrf(form))
    
    # Crawl linked URLs
    for url in urls[:5]:  # Limit to 5 URLs to avoid excessive crawling
        abs_url = urljoin(target_url, url)
        forms, _ = crawl_url(abs_url)
        for form in forms:
            inputs = form.find_all('input')
            vulnerabilities.extend(test_xss(abs_url, form, inputs))
            vulnerabilities.extend(test_sqli(abs_url, form, inputs))
            vulnerabilities.extend(test_csrf(form))
    
    return vulnerabilities

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url']
    start_time = time.time()
    vulnerabilities = scan_website(target_url)
    end_time = time.time()
    return render_template('results.html', vulnerabilities=vulnerabilities, url=target_url, scan_time=end_time-start_time)

if __name__ == '__main__':
    app.run(debug=True)