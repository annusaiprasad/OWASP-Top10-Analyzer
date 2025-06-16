# scanner/config_misconfig.py

import requests


def check_directory_listing(target_url):
    print("[*] Checking for directory listing...")

    common_paths = ["/uploads", "/files", "/backup", "/logs", "/images", "/admin"]
    vulnerable_paths = []

    for path in common_paths:
        url = target_url.rstrip("/") + path + "/"
        try:
            res = requests.get(url, timeout=5)
            if "Index of" in res.text and res.status_code == 200:
                vulnerable_paths.append(url)
        except:
            continue

    return vulnerable_paths

def check_debug_info(target_url):
    print("[*] Checking for debug information...")
    try:
        res = requests.get(target_url, timeout=5)
        if any(keyword in res.text.lower() for keyword in ["debug", "stack trace", "traceback", "exception", "line ", "warning:"]):
            return True
    except:
        pass
    return False

def check_missing_security_headers(target_url):
    print("[*] Checking for missing security headers...")
    required_headers = [
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]
    missing = []
    try:
        res = requests.get(target_url, timeout=5)
        for header in required_headers:
            if header not in res.headers:
                missing.append(header)
    except:
        pass
    return missing


def scan(target_url):
    print("[*] Running A05: Security Misconfiguration Scan...")

    result = {
        'vulnerability': 'Security Misconfiguration (A05)',
        'found': False,
        'details': {}
    }

    dir_listing = check_directory_listing(target_url)
    if dir_listing:
        result['found'] = True
        result['details']['Open Directories'] = dir_listing

    debug_exposed = check_debug_info(target_url)
    if debug_exposed:
        result['found'] = True
        result['details']['Debug Info Leaked'] = True

    missing_headers = check_missing_security_headers(target_url)
    if missing_headers:
        result['found'] = True
        result['details']['Missing Security Headers'] = missing_headers

    if not result['details']:
        result['details'] = "No misconfiguration issues found."

    return result
