# scanner/ssrf.py

import requests

def check_ssrf_vectors(target_url):
    print("[*] Checking for SSRF via vulnerable URL parameters...")

    vulnerable = []

    payloads = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata IP
        "http://0.0.0.0"
    ]

    test_params = ["url", "next", "data", "image", "load", "redirect"]

    for param in test_params:
        for payload in payloads:
            try:
                test_url = f"{target_url}?{param}={payload}"
                res = requests.get(test_url, timeout=5)
                # Heuristic: did we get a non-standard response or long delay?
                if res.status_code in [200, 202] and "localhost" in res.text.lower():
                    vulnerable.append(f"{param} -> {payload}")
            except:
                continue

    return vulnerable

def scan(target_url):
    print("[*] Running A10: SSRF (Server-Side Request Forgery) Scan...")

    result = {
        'vulnerability': 'Server-Side Request Forgery (A10)',
        'found': False,
        'details': {}
    }

    ssrf_hits = check_ssrf_vectors(target_url)
    if ssrf_hits:
        result['found'] = True
        result['details']['SSRF-Likely Parameters'] = ssrf_hits
    else:
        result['details'] = "No SSRF indicators found."

    return result
