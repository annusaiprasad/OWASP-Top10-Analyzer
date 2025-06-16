# scanner/insecure_design.py

import requests
import time

def check_predictable_endpoints(target_url):
    print("[*] Checking for insecure/predictable endpoints...")

    test_endpoints = [
        "/reset-password?user=admin",
        "/forgot-password?email=admin@site.com",
        "/approve?user=admin",
        "/delete?id=1",
        "/debug",
        "/internal"
    ]

    exposed = []

    for ep in test_endpoints:
        try:
            url = target_url.rstrip("/") + ep
            res = requests.get(url, timeout=5, allow_redirects=False)
            if res.status_code in [200, 302] and "error" not in res.text.lower():
                exposed.append(url)
        except:
            continue

    return exposed

def check_rate_limiting(target_url):
    print("[*] Checking for missing rate limiting (basic test)...")

    test_url = target_url.rstrip("/") + "/login"
    rate_limit_detected = False
    try:
        for i in range(5):
            res = requests.post(test_url, data={"username": "admin", "password": "wrong"}, timeout=5)
            if "too many requests" in res.text.lower() or res.status_code == 429:
                rate_limit_detected = True
                break
            time.sleep(1)
    except:
        pass

    return not rate_limit_detected  # if no limit triggered, it's vulnerable

def scan(target_url):
    print("[*] Running A04: Insecure Design Scan...")

    result = {
        'vulnerability': 'Insecure Design (A04)',
        'found': False,
        'details': {}
    }

    weak_endpoints = check_predictable_endpoints(target_url)
    if weak_endpoints:
        result['found'] = True
        result['details']['Predictable Endpoints Found'] = weak_endpoints

    no_rate_limit = check_rate_limiting(target_url)
    if no_rate_limit:
        result['found'] = True
        result['details']['No Rate Limiting Detected on /login'] = True

    if not result['details']:
        result['details'] = "No insecure design flaws detected."

    return result


