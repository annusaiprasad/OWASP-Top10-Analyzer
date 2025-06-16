# scanner/auth_failures.py

import requests

def test_default_login(target_url):
    print("[*] Testing for weak/default credentials...")

    login_url = target_url.rstrip("/") + "/login"
    common_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("user", "user"),
        ("test", "test123")
    ]
    vulnerable = []

    for username, password in common_creds:
        try:
            res = requests.post(login_url, data={"username": username, "password": password}, timeout=5)
            if res.status_code == 200 and "logout" in res.text.lower():
                vulnerable.append((username, password))
        except:
            continue
    return vulnerable

def test_username_enumeration(target_url):
    print("[*] Testing for username enumeration...")

    login_url = target_url.rstrip("/") + "/login"
    try:
        valid_user = requests.post(login_url, data={"username": "admin", "password": "wrong"}, timeout=5)
        invalid_user = requests.post(login_url, data={"username": "nosuchuser", "password": "wrong"}, timeout=5)

        if valid_user.status_code == 200 and invalid_user.status_code == 200:
            if valid_user.text != invalid_user.text:
                return True
    except:
        pass
    return False

def test_logout_missing(target_url):
    print("[*] Checking for missing logout endpoint...")
    logout_url = target_url.rstrip("/") + "/logout"
    try:
        res = requests.get(logout_url, timeout=5)
        if res.status_code == 404 or "not found" in res.text.lower():
            return True
    except:
        pass
    return False

def scan(target_url):
    print("[*] Running A07: Identification and Authentication Failures Scan...")

    report = {
        'vulnerability': 'Auth Failures (A07)',
        'found': False,
        'details': {}
    }

    # Weak/default credentials
    weak_creds = test_default_login(target_url)
    if weak_creds:
        report['found'] = True
        report['details']['Default Credentials Accepted'] = weak_creds

    # Username Enumeration
    user_enum = test_username_enumeration(target_url)
    if user_enum:
        report['found'] = True
        report['details']['Username Enumeration Detected'] = True

    # Logout Endpoint Missing
    missing_logout = test_logout_missing(target_url)
    if missing_logout:
        report['found'] = True
        report['details']['Logout Not Implemented'] = True

    if not report['details']:
        report['details'] = "No authentication-related vulnerabilities found."

    return report
