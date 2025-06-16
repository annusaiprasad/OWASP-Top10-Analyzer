# scanner/logging_monitoring.py

import requests

def check_generic_error_messages(target_url):
    print("[*] Checking for generic responses to invalid logins...")

    try:
        login_url = target_url.rstrip("/") + "/login"
        res = requests.post(login_url, data={"username": "admin", "password": "wrong"}, timeout=5)
        if res.status_code == 200 and not any(x in res.text.lower() for x in ["invalid", "error", "unauthorized"]):
            return True
    except:
        pass
    return False

def check_for_missing_status_codes(target_url):
    print("[*] Checking for lack of 403/401 on unauthorized access...")

    protected_paths = ["/admin", "/dashboard", "/config", "/internal", "/users"]

    failed_paths = []
    for path in protected_paths:
        try:
            url = target_url.rstrip("/") + path
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                failed_paths.append(url)
        except:
            continue
    return failed_paths

def check_missing_log_indicators(target_url):
    print("[*] Checking for missing audit headers or log info...")

    try:
        res = requests.get(target_url, timeout=5)
        suspicious = []
        if "x-request-id" not in res.headers and "x-audit-id" not in res.headers:
            suspicious.append("Missing correlation IDs for logging.")
        if "x-content-type-options" not in res.headers:
            suspicious.append("Missing header protection (X-Content-Type-Options).")
        return suspicious
    except:
        return []

def scan(target_url):
    print("[*] Running A09: Logging & Monitoring Failures Scan...")

    result = {
        'vulnerability': 'Logging & Monitoring Failures (A09)',
        'found': False,
        'details': {}
    }

    generic_login = check_generic_error_messages(target_url)
    if generic_login:
        result['found'] = True
        result['details']['Generic Login Error Message'] = True

    missing_status_codes = check_for_missing_status_codes(target_url)
    if missing_status_codes:
        result['found'] = True
        result['details']['No 403/401 for Protected Paths'] = missing_status_codes

    missing_headers = check_missing_log_indicators(target_url)
    if missing_headers:
        result['found'] = True
        result['details']['Missing Log/Audit Headers'] = missing_headers

    if not result['details']:
        result['details'] = "No logging or monitoring failures detected."

    return result
