# scanner/integrity_failures.py

import requests
import re

def check_external_scripts_without_sri(target_url):
    print("[*] Checking for external scripts without Subresource Integrity (SRI)...")
    try:
        res = requests.get(target_url, timeout=5)
        matches = re.findall(r'<script\s+.*?src=["\'](http.*?)["\'].*?>', res.text, re.IGNORECASE)
        missing_sri = []

        for script_tag in matches:
            if "integrity=" not in script_tag and "crossorigin=" in script_tag:
                missing_sri.append(script_tag)

        return missing_sri
    except:
        return []

def check_dynamic_script_injection(target_url):
    print("[*] Checking for potential dynamic JS injection sources...")
    try:
        res = requests.get(target_url, timeout=5)
        dynamic_scripts = []

        if "eval(" in res.text or "new Function" in res.text or "document.write(" in res.text:
            dynamic_scripts.append("Detected use of eval(), document.write(), or Function constructor.")

        return dynamic_scripts
    except:
        return []

def scan(target_url):
    print("[*] Running A08: Software & Data Integrity Failures Scan...")

    result = {
        'vulnerability': 'Software & Data Integrity Failures (A08)',
        'found': False,
        'details': {}
    }

    no_sri = check_external_scripts_without_sri(target_url)
    if no_sri:
        result['found'] = True
        result['details']['External Scripts Without SRI'] = no_sri

    dynamic_js = check_dynamic_script_injection(target_url)
    if dynamic_js:
        result['found'] = True
        result['details']['Dynamic Script Injection Detected'] = dynamic_js

    if not result['details']:
        result['details'] = "No integrity issues found in scripts or data sources."

    return result
