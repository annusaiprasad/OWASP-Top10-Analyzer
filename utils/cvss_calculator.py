# utils/cvss_calculator.py

def assign_cvss_score(vuln_name: str, details):
    """
    Returns a dictionary with CVSS score and severity level.
    """

    base_scores = {
        "Injection": 9.8,
        "Broken Access Control": 9.0,
        "Cryptographic Failures": 7.4,
        "Insecure Design": 6.5,
        "Security Misconfiguration": 6.0,
        "Outdated Components": 5.5,
        "Auth Failures": 8.2,
        "Integrity Failures": 7.1,
        "Logging & Monitoring Failures": 4.5,
        "SSRF": 9.0
    }

    key = vuln_name.split()[-1] if ':' in vuln_name else vuln_name
    base = base_scores.get(key.strip(), 5.0)

    if isinstance(details, dict):
        impact_factor = 1 + min(len(details) * 0.1, 1.0)
    elif isinstance(details, list):
        impact_factor = 1 + min(len(details) * 0.05, 1.0)
    else:
        impact_factor = 1.0

    score = round(min(base * impact_factor, 10.0), 1)
    severity = classify_severity(score)

    return {
        "score": score,
        "risk": severity
    }

def classify_severity(score):
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"
