6# scanner/outdated_components.py

import requests
import re

def detect_server_version(target_url):
    print("[*] Checking for outdated server headers...")
    try:
        res = requests.get(target_url, timeout=5)
        server_header = res.headers.get("Server")
        powered_by = res.headers.get("X-Powered-By")

        leaked_versions = {}

        if server_header:
            leaked_versions["Server"] = server_header
        if powered_by:
            leaked_versions["X-Powered-By"] = powered_by

        return leaked_versions if leaked_versions else None
    except:
        return None

def detect_exposed_js_versions(target_url):
    print("[*] Scanning for exposed JS/CSS library versions...")
    try:
        res = requests.get(target_url, timeout=5)
        scripts = re.findall(r'src=["\']([^"\']+)["\']', res.text)
        version_hits = []

        version_regex = re.compile(r"(jquery|bootstrap|vue|react)(\.min)?\.js(?:\?ver=)?[^\d]*([\d\.]+)", re.IGNORECASE)

        for src in scripts:
            match = version_regex.search(src)
            if match:
                version_hits.append({
                    "library": match.group(1),
                    "version": match.group(3),
                    "url": src
                })

        return version_hits
    except:
        return []

def scan(target_url):
    print("[*] Running A06: Vulnerable & Outdated Components Scan...")

    result = {
        'vulnerability': 'Vulnerable & Outdated Components (A06)',
        'found': False,
        'details': {}
    }

    # Header leakage
    leaked = detect_server_version(target_url)
    if leaked:
        result['found'] = True
        result['details']['Leaked Server Info'] = leaked

    # Script version exposure
    exposed_libs = detect_exposed_js_versions(target_url)
    if exposed_libs:
        result['found'] = True
        result['details']['Exposed Library Versions'] = exposed_libs

    if not result['details']:
        result['details'] = "No outdated or exposed components found."

    return result
