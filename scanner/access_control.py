6# scanner/access_control.py

import requests

def check_sensitive_paths(target_url):
    print("[*] Checking for unprotected sensitive endpoints...")

    sensitive_endpoints = [
        "/admin", "/dashboard", "/config", "/dev", "/logs", "/users", "/.env", "/hidden", "/internal"
    ]
    exposed = []

    for path in sensitive_endpoints:
        try:
            url = target_url.rstrip("/") + path
            res = requests.get(url, timeout=5, allow_redirects=False)
            if res.status_code == 200 and "login" not in res.text.lower():
                exposed.append(url)
        except:
            continue
    return exposed

def check_idor(target_url):
    print("[*] Checking for Insecure Direct Object Reference (IDOR)...")

    idor_test_urls = [
        "/user?id=1", "/user?id=2", "/account/1", "/account/2", "/profile/1", "/profile/2"
    ]
    vulnerable = []

    for path in idor_test_urls:
        try:
            url = target_url.rstrip("/") + path
            res = requests.get(url, timeout=5)
            if res.status_code == 200 and "unauthorized" not in res.text.lower():
                vulnerable.append(url)
        except:
            continue
    return vulnerable

def check_privilege_escalation(target_url):
    print("[*] Checking for role tampering in cookies...")

    # Simulate logged-in low-privilege user with a 'role=user' cookie
    try:
        res = requests.get(
            target_url,
            cookies={"role": "admin"},
            timeout=5
        )
        if "admin" in res.text.lower():
            return True
    except:
        return False

    return False

def scan(target_url):
    print("[*] Running A01: Broken Access Control Scan...")

    exposed_endpoints = check_sensitive_paths(target_url)
    idor_vulns = check_idor(target_url)
    privilege_escalation = check_privilege_escalation(target_url)

    any_vuln = exposed_endpoints or idor_vulns or privilege_escalation

    return {
        'vulnerability': 'Broken Access Control (A01)',
        'found': any_vuln,
        'details': {
            'Exposed Admin URLs': exposed_endpoints,
            'Possible IDORs': idor_vulns,
            'Role Tampering Success': privilege_escalation
        }
    }
