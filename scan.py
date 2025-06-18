import requests
from bs4 import BeautifulSoup
import re

payloads = {
    'xss': ["<script>alert(1)</script>", "'\"><script>alert(1)</script>"],
    'sqli': ["' OR 1=1--", "\" OR \"1\"=\"1", "' UNION SELECT NULL--"]
}

def get_forms(url):
    try:
        soup = BeautifulSoup(requests.get(url).text, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        return []

def form_details(form):
    details = {}
    try:
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            name = input_tag.attrs.get("name")
            type_ = input_tag.attrs.get("type", "text")
            inputs.append({"name": name, "type": type_})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
    except Exception:
        pass
    return details

def submit_form(form_details, url, payload):
    target_url = url + form_details["action"]
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except:
        return None

def scan_xss_sqli(url):
    results = []
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for attack_type in ['xss', 'sqli']:
            for payload in payloads[attack_type]:
                response = submit_form(details, url, payload)
                if response and payload in response.text:
                    results.append({
                        "type": attack_type.upper(),
                        "payload": payload,
                        "url": url + details["action"],
                        "evidence": response.text[:300],
                        "severity": "High" if attack_type == "sqli" else "Medium"
                    })
    return results
