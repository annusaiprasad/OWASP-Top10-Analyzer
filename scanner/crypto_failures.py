# scanner/crypto_failures.py

import requests
from urllib.parse import urlparse

def check_https_enforcement(target_url):
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return False, "Website does not enforce HTTPS"
    try:
        response = requests.get(target_url, timeout=5)
        if response.url.startswith("http://"):
            return False, "Redirects to HTTP (no HTTPS enforcement)"
    except:
        return False, "Could not verify HTTPS enforcement"
    return True, "HTTPS enforced"

def check_env_file_exposure(target_url):
    test_url = target_url.rstrip("/") + "/.env"
    try:
        response = requests.get(test_url, timeout=5)
        if "DB_PASSWORD" in response.text or "SECRET_KEY" in response.text:
            return True, test_url
    except:
        pass
    return False, None

def check_cookie_flags(target_url):
    try:
        response = requests.get(target_url, timeout=5)
        cookies = response.cookies
        insecure_cookies = []
        for cookie in cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr("HttpOnly"):
                insecure_cookies.append(cookie.name)
        if insecure_cookies:
            return True, insecure_cookies
    except:
        pass
    return False, None

def scan(target_url):
    print("[*] Running A02: Cryptographic Failures Scan...")

    report = {
        'vulnerability': 'Cryptographic Failures (A02)',
        'found': False,
        'details': {}
    }

    https_ok, https_result = check_https_enforcement(target_url)
    if not https_ok:
        report['found'] = True
        report['details']['HTTPS Enforcement'] = https_result

    env_exposed, env_url = check_env_file_exposure(target_url)
    if env_exposed:
        report['found'] = True
        report['details']['.env File Exposed'] = env_url

    weak_cookies, cookie_names = check_cookie_flags(target_url)
    if weak_cookies:
        report['found'] = True
        report['details']['Weak Cookies Detected'] = cookie_names

    if not report['details']:
        report['details'] = "No cryptographic failures found."

    return report
